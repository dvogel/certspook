// SPDX-License-Identifier: AGPL-3.0-or-later

// This module provides a RemoteConnection struct that serves as the primary identity of the work
// to be done by the certificate checker.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

mod wrapped_sockaddr;
use wrapped_sockaddr::WrappedSockaddr;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RemoteConnection {
    addr: IpAddr,
    port: u16,
}

impl RemoteConnection {
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
}

impl fmt::Display for RemoteConnection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.addr {
            IpAddr::V4(addr4) => write!(f, "v4:{}:{}", addr4, self.port,),
            IpAddr::V6(addr6) => write!(f, "v6:[{}]:{}", addr6, self.port,),
        }
    }
}
