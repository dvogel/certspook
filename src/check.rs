// SPDX-License-Identifier: AGPL-3.0-or-later

use std::error::Error;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::rc::Rc;
use std::sync::mpsc::Receiver;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime};

extern crate chrono;
use anyhow::{anyhow, Result};
use rustls::client::ServerCertVerified;
use rustls::client::ServerCertVerifier;
use rustls::{Certificate, ClientConfig, ClientConnection, ServerName};
use time::OffsetDateTime;
use x509_parser::prelude::{FromDer, X509Certificate};
use x509_parser::time::ASN1Time;

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

fn handshake_with_remote(rconn: &RemoteConnection) -> Result<Vec<Certificate>, Box<dyn Error>> {
    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(Arc::new(NoopServerCertVerifier {}))
        .with_no_client_auth();
    let mut tls_conn =
        ClientConnection::new(Arc::new(config), ServerName::IpAddress(rconn.ip_addr()))?;
    let mut sock = TcpStream::connect((rconn.ip_addr(), rconn.port()))?;

    while tls_conn.is_handshaking() {
        let (_bytes_in, _bytes_out) = tls_conn.complete_io(&mut sock)?;
    }

    tls_conn.send_close_notify();
    sock.shutdown(Shutdown::Both);

    tls_conn
        .peer_certificates()
        .map(|certs| Vec::from(certs))
        .ok_or_else(|| anyhow!("Could not obtain certificates from {}", rconn).into())
}

fn rfc3339_not_after(cert: &X509Certificate) -> String {
    let dt: chrono::naive::NaiveDateTime =
        chrono::naive::NaiveDateTime::from_timestamp_opt(cert.validity().not_after.timestamp(), 0)
            .expect("If this fails some clock is extremely wrong.");
    format!("{}", dt.format("%Y-%m-%d"))
}

fn check_remote_connection(
    expiration_threshold: Duration,
    rconn: &RemoteConnection,
) -> Result<(), Box<dyn Error>> {
    let raw_certs = handshake_with_remote(&rconn)?;
    let maybe_certs: Vec<Result<X509Certificate, Box<dyn Error>>> = raw_certs
        .iter()
        .map(|bytes| {
            X509Certificate::from_der(&bytes.0)
                .map(|(_remaining, x509)| x509)
                .map_err(|e| e.into())
        })
        .collect();

    for (idx, maybe_cert) in maybe_certs.iter().enumerate() {
        match maybe_cert {
            Ok(x509) => {
                println!("info:cert:{}:{}:{}", rconn, idx, x509.subject());

                let threshold_time = ASN1Time::from_timestamp(
                    // TODO: This is truncating the expiration_threshold. Does it matter?
                    ASN1Time::now().timestamp() + expiration_threshold.as_secs() as i64,
                )
                .expect("If this overflows the system clock must be way too far in the future.");
                let is_expired = !x509.validity().is_valid();
                let will_expire_soon = x509.validity().is_valid_at(threshold_time);
                if is_expired {
                    println!(
                        "err:expired-cert:{}:{}:{}",
                        rconn,
                        idx,
                        rfc3339_not_after(&x509)
                    );
                } else if will_expire_soon {
                    println!(
                        "warn:expiration-near:{}:{}:{}",
                        rconn,
                        idx,
                        rfc3339_not_after(&x509)
                    );
                } else {
                    // TODO: This should be behind a verbose option.
                    println!(
                        "ok:{}:{}:{}:{}",
                        rconn,
                        idx,
                        x509.subject(),
                        rfc3339_not_after(&x509)
                    );
                }
            }
            Err(_) => eprintln!("Could not parse certificate from {} ({})", rconn, idx),
        }
    }
    Ok(())
}

pub fn spawn_check_thread(
    expiration_threshold: Duration,
    rx: Receiver<RemoteConnection>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || loop {
        let rconn = match rx.recv() {
            Err(_) => return,
            Ok(val) => val,
        };
        if let Err(e) = check_remote_connection(expiration_threshold, &rconn) {
            eprintln!("error:{}", e);
        }
    })
}
