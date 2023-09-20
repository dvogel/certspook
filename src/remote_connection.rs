// SPDX-License-Identifier: AGPL-3.0-or-later

// This module provides a RemoteConnection struct that serves as the primary identity of the work
// to be done by the certificate checker.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use cidr_utils::cidr::{IpCidr, Ipv4Cidr, Ipv6Cidr};

use crate::wrapped_sockaddr::WrappedSockaddr;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RemoteConnection {
    addr: IpAddr,
    port: u16,
}

impl RemoteConnection {
    fn new(addr: IpAddr, port: u16) -> Self {
        Self { addr, port }
    }

    fn from_sockaddr(addr: &WrappedSockaddr) -> Option<Self> {
        match addr {
            WrappedSockaddr::V4(addr4) => Some(RemoteConnection {
                addr: IpAddr::V4(Ipv4Addr::from(addr4.0.sin_addr.s_addr)),
                port: addr4.0.sin_port,
            }),
            WrappedSockaddr::V6(addr6) => Some(RemoteConnection {
                addr: IpAddr::V6(Ipv6Addr::from(addr6.0.sin6_addr.s6_addr)),
                port: addr6.0.sin6_port,
            }),
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        WrappedSockaddr::from_bytes(bytes).and_then(|w| Self::from_sockaddr(&w))
    }

    pub fn ip_addr(&self) -> IpAddr {
        self.addr
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

impl fmt::Display for RemoteConnection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.addr {
            IpAddr::V4(addr4) => write!(f, "v4:{}:{}", addr4, self.port,),
            IpAddr::V6(addr6) => write!(f, "v6:[{}]:{}", addr6, self.port,),
        }
    }
}

#[derive(Clone)]
pub struct RemoteConnectionFilter {
    cidr_list: Vec<IpCidr>,
    port_list: Vec<u16>,
}

impl RemoteConnectionFilter {
    pub fn new(cidr_list: Vec<IpCidr>, port_list: Vec<u16>) -> Self {
        Self {
            cidr_list,
            port_list,
        }
    }

    pub fn allows(&self, rconn: &RemoteConnection) -> bool {
        let port_match = match self.port_list.contains(&rconn.port()) {
            true => true,
            false => self.port_list.is_empty(),
        };

        let cidr_match = match self.cidr_list.iter().find(|c| c.contains(rconn.ip_addr())) {
            Some(_) => true,
            None => self.cidr_list.is_empty(),
        };

        return port_match && cidr_match;
    }

    pub fn allows_addr(&self, addr: &IpAddr) -> bool {
        match self.cidr_list.iter().find(|c| c.contains(*addr)) {
            Some(_) => true,
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    use cidr_utils::cidr::{IpCidr, Ipv4Cidr, Ipv6Cidr};

    use super::{RemoteConnection, RemoteConnectionFilter};

    #[test]
    fn empty_always_matches() {
        // TODO: Generate random addresses.
        let subj = RemoteConnectionFilter::new(Vec::new(), Vec::new());
        assert!(subj.allows(&RemoteConnection::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443)));
    }

    #[test]
    fn just_cidr_matches() {
        let subj = RemoteConnectionFilter::new(
            vec![IpCidr::V4(Ipv4Cidr::from_str("10.0.0.0/8").unwrap())],
            Vec::new(),
        );
        assert!(subj.allows(&RemoteConnection::new(
            IpAddr::V4(Ipv4Addr::from_str("10.1.2.3").unwrap()),
            443
        )));
    }

    #[test]
    fn just_cidr_and_port_compound() {
        let subj = RemoteConnectionFilter::new(
            vec![IpCidr::V4(Ipv4Cidr::from_str("10.0.0.0/8").unwrap())],
            vec![443u16],
        );
        assert!(subj.allows(&RemoteConnection::new(
            IpAddr::V4(Ipv4Addr::from_str("10.1.2.3").unwrap()),
            443
        )));
        assert!(!subj.allows(&RemoteConnection::new(
            IpAddr::V4(Ipv4Addr::from_str("10.1.2.3").unwrap()),
            80
        )));
        assert!(!subj.allows(&RemoteConnection::new(
            IpAddr::V4(Ipv4Addr::from_str("192.168.1.1").unwrap()),
            80
        )));
    }

    #[test]
    fn multiples_entries_match_at_least_one() {
        let subj = RemoteConnectionFilter::new(
            vec![
                IpCidr::V4(Ipv4Cidr::from_str("10.0.0.0/8").unwrap()),
                IpCidr::V4(Ipv4Cidr::from_str("1.1.1.1/32").unwrap()),
            ],
            vec![443u16, 80u16],
        );
        assert!(subj.allows(&RemoteConnection::new(
            IpAddr::V4(Ipv4Addr::from_str("10.1.2.3").unwrap()),
            80
        )));
        assert!(subj.allows(&RemoteConnection::new(
            IpAddr::V4(Ipv4Addr::from_str("1.1.1.1").unwrap()),
            443
        )));
    }
}
