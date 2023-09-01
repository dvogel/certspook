// SPDX-License-Identifier: AGPL-3.0-or-later

// This module provides a GetAddrInfoResult struct that is used to decode perf events coming from
// the uprobe of getaddrinfo().

extern crate libc;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{anyhow, Context, Result};
use plain::Plain;
use std::error::Error;
use std::ffi::CStr;
use std::mem;

use crate::wrapped_sockaddr::WrappedSockaddr;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct GetAddrInfoResult {
    pub addr: IpAddr,
    pub hostname: String,
}

#[repr(C)]
#[derive(Copy, Clone)]
union Sockaddr {
    saddr4: libc::sockaddr_in,
    saddr6: libc::sockaddr_in6,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct ExportedGaiResult {
    sa_family: u16,
    saddr: Sockaddr,
    hostname_buf: [libc::c_uchar; 257],
}
unsafe impl Plain for ExportedGaiResult {}

impl GetAddrInfoResult {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn Error>> {
        if bytes.len() == mem::size_of::<ExportedGaiResult>() {
            let res: ExportedGaiResult = *plain::from_bytes(bytes)
                .map_err(|_| "Buffer could not be decoded into ExportedGaiResult")?;
            let hostname_bytes = &res.hostname_buf.to_vec();
            let c_hostname = CStr::from_bytes_until_nul(hostname_bytes)?;
            let hostname = c_hostname
                .to_str()
                .with_context(|| "Could not decode hostname as UTF-8")?;
            let ip_addr = match res.sa_family {
                AF_INET => IpAddr::V4(unsafe {
                    Ipv4Addr::from(u32::from_be(res.saddr.saddr4.sin_addr.s_addr))
                }),
                AF_INET6 => {
                    IpAddr::V6(unsafe { Ipv6Addr::from(res.saddr.saddr6.sin6_addr.s6_addr) })
                }
                _ => return Err(anyhow!("Unexpected sa_family value").into()),
            };

            eprintln!(
                "debug:decoded-exported-gai-result:{}:{}",
                &hostname, &ip_addr
            );
            Ok(GetAddrInfoResult {
                hostname: hostname.to_string(),
                addr: ip_addr,
            })
        } else {
            eprintln!("warn:unrecoggnized-exported-gai-result");
            Err(anyhow!(
                "Unrecognized record length from ring buffer: {} bytes",
                bytes.len()
            )
            .into())
        }
    }
}
