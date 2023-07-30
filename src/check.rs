// SPDX-License-Identifier: AGPL-3.0-or-later

use std::error::Error;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::rc::Rc;
use std::sync::mpsc::Receiver;
use std::sync::Arc;
use std::thread;
use std::time::SystemTime;

use anyhow::{anyhow, Result};
use rustls::client::ServerCertVerified;
use rustls::client::ServerCertVerifier;
use rustls::{Certificate, ClientConfig, ClientConnection, ServerName};
use x509_parser::prelude::{FromDer, X509Certificate};

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

fn check_remote_connection(rconn: &RemoteConnection) -> Result<(), Box<dyn Error>> {
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

    match tls_conn.peer_certificates() {
        None => Err(anyhow!("Could not obtain certificates from {}", rconn).into()),
        Some(certs) => {
            for (idx, x509bytes) in certs.iter().enumerate() {
                if let Ok((_remaining_bytes, x509)) = X509Certificate::from_der(&x509bytes.0) {
                    println!(
                        "Got certificate {} from {} ({})",
                        x509.subject(),
                        rconn,
                        idx
                    )
                } else {
                    eprintln!("Could not parse certificate from {} ({})", rconn, idx);
                }
            }
            tls_conn.send_close_notify();
            sock.shutdown(Shutdown::Both);
            Ok(())
        }
    }
}

pub fn spawn_check_thread(rx: Receiver<RemoteConnection>) -> thread::JoinHandle<()> {
    thread::spawn(move || loop {
        let rconn = match rx.recv() {
            Err(_) => return,
            Ok(val) => val,
        };
        if let Err(e) = check_remote_connection(&rconn) {
            eprintln!("error:{}", e);
        }
    })
}
