// SPDX-License-Identifier: AGPL-3.0-or-later

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::net::{IpAddr, Shutdown, TcpStream};
use std::sync::mpsc::Receiver;
use std::sync::Arc;
use std::thread;
use std::time::SystemTime;

extern crate chrono;
use anyhow::{anyhow, Result};
use rustls::client::ServerCertVerified;
use rustls::client::ServerCertVerifier;
use rustls::server::DnsName;
use rustls::{Certificate, ClientConfig, ClientConnection, ServerName};
use slog::{debug, error, info, Logger};
use trust_dns_resolver::Resolver;
use x509_parser::prelude::{FromDer, GeneralName, Validity, X509Certificate};
use x509_parser::time::ASN1Time;

use crate::gai_result::GetAddrInfoResult;
use crate::remote_connection::RemoteConnection;

struct NoopServerCertVerifier;

impl ServerCertVerifier for NoopServerCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: SystemTime,
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
    pub subject_name: String,
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
    let _ = sock.shutdown(Shutdown::Both);

    let raw_certs = tls_conn
        .peer_certificates()
        .map(Vec::from)
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

    if certs.is_empty() {
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
    let records = resolver.reverse_lookup(*ip_addr)?;
    Ok(records
        .iter()
        .map(|n| String::from(n.to_ascii().trim_end_matches('.')))
        .collect())
}

fn collect_cert_subject_names(cert: &X509Certificate) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    names.push(format!("{}", cert.subject()));

    if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
        for name in san_ext.value.general_names.iter() {
            if let GeneralName::DNSName(name_ref) = name {
                names.push(name_ref.to_string());
            }
        }
    }

    names
}

fn check_cert(cert: &CertificateDetails, dns_name: Option<&String>) -> CertCheckResults {
    let mut result = CertCheckResults {
        dns_match: false,
        days_until_expiration: 0,
        subject_name: cert.subject_names[0].clone(),
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

fn log_cert_result(
    log: &Logger,
    expiration_threshold: &time::Duration,
    rconn: &RemoteConnection,
    check: &CertCheckResults,
) {
    if check.is_expired() {
        error!(log, "cert-is-expired";
            "remote-connection" => rconn.to_string(),
            "cert-subject-name" => check.subject_name.clone(),
            "days-until-expiration" => check.days_until_expiration,
        );
    } else if check.will_expire_soon(expiration_threshold.whole_days()) {
        error!(log, "cert-expires-soon";
            "remote-connection" => rconn.to_string(),
            "cert-subject-name" => check.subject_name.clone(),
            "days-until-expiration" => check.days_until_expiration,
        );
    } else {
        info!(log,
            "cert-match";
            "remote-connection" => rconn.to_string(),
            "cert-subject-name" => check.subject_name.clone(),
        );
    }
}

fn check_remote_connection(
    log: &Logger,
    expiration_threshold: &time::Duration,
    rconn: &RemoteConnection,
    hostnames: Option<&BTreeSet<String>>,
) -> Result<(), Box<dyn Error>> {
    let dns_names: Vec<String> = match hostnames {
        Some(hset) => hset.iter().cloned().collect(),
        None => collect_ptr_names(&rconn.ip_addr())?,
    };

    for dns_name in dns_names {
        let certs = handshake_with_remote(rconn, &dns_name)?;
        let primary_cert = &certs[0];

        let check = check_cert(primary_cert, Some(&dns_name.to_string()));

        // Since we don't know which DNS name was used to find the address used in a given
        // connection we accept the first match. We could consider requiring a match for all
        // hostnames. Needs further consideration on the cost of false positives vs false
        // negatives after the proof-of-concept stage is completed.
        if check.dns_match {
            log_cert_result(log, expiration_threshold, rconn, &check);
            return Ok(());
        } else {
            info!(log,
                "cert-mismatch";
                "remote-connection" => rconn.to_string(),
                "cert" => primary_cert.subject_names[0].clone()
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
    let default_certs = handshake_with_remote(rconn, &"".to_string())?;
    let default_check = check_cert(&default_certs[0], None);

    log_cert_result(log, expiration_threshold, rconn, &default_check);
    Ok(())
}

pub enum CheckDatum {
    RemoteConnectionMessage(RemoteConnection),
    GetAddrInfoMessage(GetAddrInfoResult),
}

pub fn spawn_check_thread(
    log: Logger,
    expiration_threshold: time::Duration,
    rx: Receiver<CheckDatum>,
) -> thread::JoinHandle<()> {
    let gai_history: RefCell<BTreeMap<IpAddr, BTreeSet<String>>> = RefCell::new(BTreeMap::new());
    thread::spawn(move || loop {
        match rx.recv() {
            Err(_) => return,
            Ok(msg) => match msg {
                CheckDatum::RemoteConnectionMessage(rconn) => {
                    debug!(log, "will-check"; "remote-connection" => rconn.to_string());
                    let borrowed_hist = gai_history.borrow();
                    let hostnames = borrowed_hist.get(&rconn.ip_addr());
                    if let Some(hostnames) = hostnames {
                        debug!(
                            log,
                            "checking-with-hostnames";
                            "addr" => &rconn.ip_addr().to_string(),
                            "hostnames" => format!("{:?}", &hostnames),
                        );
                    } else {
                        debug!(log,
                            "checking-via-ptr-records";
                            "addr" => &rconn.ip_addr().to_string());
                    }

                    if let Err(e) =
                        check_remote_connection(&log, &expiration_threshold, &rconn, hostnames)
                    {
                        error!(log, "{}", e);
                    }
                }
                CheckDatum::GetAddrInfoMessage(gai) => {
                    info!(
                        log,
                        "captured-getaddrinfo-result";
                        "hostname" => &gai.hostname, "addr" => &gai.addr.to_string()
                    );
                    let mut borrowed_hist = gai_history.borrow_mut();
                    let hostnames = borrowed_hist.entry(gai.addr).or_default();
                    if hostnames.insert(gai.hostname.clone()) {
                        debug!(log, "remembered-hostname"; "hostname" => &gai.hostname);
                    } else {
                        debug!(log, "forgot-hostname"; "hostname" => &gai.hostname);
                    }
                }
            },
        };
    })
}
