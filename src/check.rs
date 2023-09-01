// SPDX-License-Identifier: AGPL-3.0-or-later

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::net::{IpAddr, Shutdown, TcpStream};
use std::sync::mpsc::Receiver;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime};

extern crate chrono;
use anyhow::{anyhow, Result};
use rustls::client::ServerCertVerified;
use rustls::client::ServerCertVerifier;
use rustls::server::DnsName;
use rustls::{Certificate, ClientConfig, ClientConnection, ServerName};
use trust_dns_resolver::Resolver;
use x509_parser::prelude::{
    BasicExtension, FromDer, GeneralName, SubjectAlternativeName, Validity, X509Certificate,
    X509Name,
};
use x509_parser::time::ASN1Time;

use crate::gai_result::GetAddrInfoResult;
use crate::remote_connection::RemoteConnection;

struct NoopServerCertVerifier;

impl ServerCertVerifier for NoopServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &Certificate,
        intermediates: &[Certificate],
        server_name: &ServerName,
        scts: &mut dyn Iterator<Item = &[u8]>,
        ocsp_response: &[u8],
        now: SystemTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
}

struct RemoteTlsIdentity {
    remote_connection: RemoteConnection,
    dns_name: String,
    certificates: Vec<Certificate>,
}

struct CertificateDetails {
    subject_names: Vec<String>,
    validity: Validity,
}

struct CertCheckResults {
    pub dns_match: bool,
    pub days_until_expiration: i64,
}

impl CertCheckResults {
    pub fn is_expired(&self) -> bool {
        self.days_until_expiration <= 0
    }

    pub fn will_expire_soon(&self, threshold_days: i64) -> bool {
        self.days_until_expiration <= threshold_days
    }
}

fn handshake_with_remote(
    rconn: &RemoteConnection,
    dns_name: &String,
) -> Result<Vec<CertificateDetails>, Box<dyn Error>> {
    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(Arc::new(NoopServerCertVerifier {}))
        .with_no_client_auth();
    let mut tls_conn = ClientConnection::new(
        Arc::new(config),
        ServerName::DnsName(DnsName::try_from_ascii(dns_name.as_ref())?),
    )?;
    let mut sock = TcpStream::connect((rconn.ip_addr(), rconn.port()))?;

    while tls_conn.is_handshaking() {
        let (_bytes_in, _bytes_out) = tls_conn.complete_io(&mut sock)?;
    }

    tls_conn.send_close_notify();
    sock.shutdown(Shutdown::Both);

    let raw_certs = tls_conn
        .peer_certificates()
        .map(|certs| Vec::from(certs))
        .ok_or_else(|| anyhow!("Could not obtain certificates from {}", rconn.clone()))?;

    let mut certs: Vec<CertificateDetails> = Vec::new();
    for bytes in raw_certs.iter() {
        let x509 = X509Certificate::from_der(&bytes.0).map(|(_remaining, x509)| x509)?;
        let names = collect_cert_subject_names(&x509);
        certs.push(CertificateDetails {
            subject_names: names,
            validity: x509.validity().clone(),
        });
    }

    if certs.len() == 0 {
        return Err(anyhow!("No certificates available from {}", rconn.clone()).into());
    }

    Ok(certs)
}

fn rfc3339_not_after(cert: &X509Certificate) -> String {
    let dt: chrono::naive::NaiveDateTime =
        chrono::naive::NaiveDateTime::from_timestamp_opt(cert.validity().not_after.timestamp(), 0)
            .expect("If this fails some clock is extremely wrong.");
    format!("{}", dt.format("%Y-%m-%d"))
}

fn collect_ptr_names(ip_addr: &IpAddr) -> Result<Vec<String>, Box<dyn Error>> {
    let resolver = Resolver::from_system_conf().unwrap();
    let records = resolver.reverse_lookup(ip_addr.clone())?;
    Ok(records
        .iter()
        .map(|n| String::from(n.to_ascii().trim_end_matches('.')))
        .collect())
}

fn collect_cert_subject_names(cert: &X509Certificate) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    names.push(format!("{}", cert.subject()));

    if let Ok(san_ext) = cert.subject_alternative_name() {
        if let Some(san_ext) = san_ext {
            for name in san_ext.value.general_names.iter() {
                if let GeneralName::DNSName(name_ref) = name {
                    names.push(name_ref.to_string());
                }
            }
        }
    }

    names
}

fn check_cert(cert: &CertificateDetails, dns_name: Option<&String>) -> CertCheckResults {
    let mut result = CertCheckResults {
        dns_match: false,
        days_until_expiration: 0,
    };

    // If the dns_name parameter is None then the connection is assumed to have been made by
    // directly specifying the IP address and thus the DNS <=> subject mapping should be bypassed.
    result.dns_match = match dns_name {
        Some(dns_name) => cert.subject_names.iter().any(|n| n == dns_name),
        None => true,
    };

    if let Some(since_expiration) = ASN1Time::now() - cert.validity.not_after {
        result.days_until_expiration = 0 - since_expiration.whole_days();
    } else if let Some(until_expiration) = cert.validity.not_after - ASN1Time::now() {
        result.days_until_expiration = until_expiration.whole_days();
    }

    result
}

fn check_remote_connection(
    expiration_threshold: Duration,
    rconn: &RemoteConnection,
    hostnames: Option<&BTreeSet<String>>,
) -> Result<(), Box<dyn Error>> {
    let dns_names: Vec<String> = match hostnames {
        Some(hset) => hset.iter().map(|h| h.clone()).collect(),
        None => {
            println!("info:using-ptr-records:{}", &rconn);
            collect_ptr_names(&rconn.ip_addr())?
        }
    };

    for dns_name in dns_names {
        let certs = handshake_with_remote(&rconn, &dns_name)?;
        let primary_cert = &certs[0];

        let check = check_cert(primary_cert, Some(&dns_name.to_string()));

        // Since we don't know which DNS name was used to find the address used in a given
        // connection we accept the first match. We could consider requiring a match for all
        // hostnames. Needs further consideration on the cost of false positives vs false
        // negatives after the proof-of-concept stage is completed.
        if check.dns_match {
            println!(
                "info:cert-match:{}:{}",
                rconn, primary_cert.subject_names[0]
            );
            return Ok(());
        } else {
            println!(
                "info:cert-mismatch:{}:{}",
                rconn, primary_cert.subject_names[0]
            );
        }
    }

    // We've done our best to determine a hostname to use via the Server Name Indicator extension
    // in loop above. However if we get here none of the hostnames yielded a passing certificate.
    // It is possible that the getaddrinfo() calls that returned this address and/or the PTR
    // records looked up just so happen be for the same address something connects to by IP
    // address.
    // TODO: Okay, maybe not our *best* because we could implement TLS handshake decoding in BPF
    // to capture the actual SNI extension record. No one would do *that* ... would they?
    let default_certs = handshake_with_remote(&rconn, &"".to_string())?;
    let default_check = check_cert(&default_certs[0], None);

    println!("err:no-cert-match:{}", rconn.ip_addr());
    Ok(())
}

pub enum CheckDatum {
    RemoteConnectionMessage(RemoteConnection),
    GetAddrInfoMessage(GetAddrInfoResult),
}

pub fn spawn_check_thread(
    expiration_threshold: Duration,
    rx: Receiver<CheckDatum>,
) -> thread::JoinHandle<()> {
    let mut gai_history: RefCell<BTreeMap<IpAddr, BTreeSet<String>>> =
        RefCell::new(BTreeMap::new());
    thread::spawn(move || loop {
        match rx.recv() {
            Err(_) => return,
            Ok(msg) => match msg {
                CheckDatum::RemoteConnectionMessage(rconn) => {
                    let borrowed_hist = gai_history.borrow();
                    let hostnames = borrowed_hist.get(&rconn.ip_addr());
                    println!(
                        "debug:checking-with-hostnames:{}:{:?}",
                        &rconn.ip_addr(),
                        &hostnames
                    );
                    if let Err(e) = check_remote_connection(expiration_threshold, &rconn, hostnames)
                    {
                        eprintln!("error:{}", e);
                    }
                }
                CheckDatum::GetAddrInfoMessage(gai) => {
                    println!(
                        "info:captured-getaddrinfo-result:{}:{}",
                        &gai.hostname, &gai.addr
                    );
                    let mut borrowed_hist = gai_history.borrow_mut();
                    let hostnames = borrowed_hist.entry(gai.addr).or_default();
                    if hostnames.insert(gai.hostname.clone()) {
                        println!("debug:remembered-hostname:{}", &gai.hostname);
                    } else {
                        println!("debug:forgot-hostname:{}", &gai.hostname);
                    }
                }
            },
        };
    })
}
