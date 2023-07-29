// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This module wraps the libc sockaddr structs so that we can implement the Plain trait on them.

extern crate libc;

use plain::Plain;
use std::mem;

#[derive(Copy, Clone, PartialEq, Eq)]
pub(super) struct WrappedSockaddrIn(pub(super) libc::sockaddr_in);
unsafe impl Plain for WrappedSockaddrIn {}

#[derive(Copy, Clone, PartialEq, Eq)]
pub(super) struct WrappedSockaddrIn6(pub(super) libc::sockaddr_in6);
unsafe impl Plain for WrappedSockaddrIn6 {}

pub(super) enum WrappedSockaddr {
    V4(WrappedSockaddrIn),
    V6(WrappedSockaddrIn6),
}

impl WrappedSockaddr {
    pub(super) fn from_bytes(buf: &[u8]) -> Option<WrappedSockaddr> {
        // libc normally converts these from network byte order to host byte order. Since we copied
        // them directly from the kernel we need to do so.
        if buf.len() == mem::size_of::<libc::sockaddr_in>() {
            let mut addr4: WrappedSockaddrIn;
            addr4 = *plain::from_bytes(buf).expect("Buffer cannot be decoded into sockaddr_in.");
            addr4.0.sin_addr.s_addr = u32::from_be(addr4.0.sin_addr.s_addr);
            addr4.0.sin_port = u16::from_be(addr4.0.sin_port);
            Some(WrappedSockaddr::V4(addr4))
        } else if buf.len() == mem::size_of::<libc::sockaddr_in6>() {
            let mut addr6: WrappedSockaddrIn6;
            addr6 = *plain::from_bytes(buf).expect("Buffer cannot be decoded into sockaddr_in6.");
            addr6.0.sin6_port = u16::from_be(addr6.0.sin6_port);
            Some(WrappedSockaddr::V6(addr6))
        } else {
            None
        }
    }
}
