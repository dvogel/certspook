// SPDX-License-Identifier: AGPL-3.0-or-later

use std::fmt;
use std::time::Duration;

use anyhow::bail;
use anyhow::Result;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::RingBufferBuilder;
use plain::Plain;
use std::mem;

mod certspook {
    include!(concat!(env!("OUT_DIR"), "/certspook.skel.rs"));
}

use certspook::*;

#[derive(Copy, Clone)]
struct WrappedSockaddrIn(libc::sockaddr_in);

unsafe impl Plain for WrappedSockaddrIn {}

impl WrappedSockaddrIn {
    fn from_bytes(buf: &[u8]) -> WrappedSockaddrIn {
        let mut addr: WrappedSockaddrIn =
            *plain::from_bytes(buf).expect("Buffer cannot be decoded into sockaddr_in.");
        // libc normally converts these from network byte order to host byte order. Since we copied
        // them directly from the kernel we need to do so.
        addr.0.sin_addr.s_addr = u32::from_be(addr.0.sin_addr.s_addr);
        addr.0.sin_port = u16::from_be(addr.0.sin_port);
        addr
    }

    fn bytelen() -> usize {
        mem::size_of::<libc::sockaddr_in>()
    }
}

impl fmt::Display for WrappedSockaddrIn {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}:{}",
            std::net::Ipv4Addr::from(self.0.sin_addr.s_addr),
            self.0.sin_port
        )
    }
}

#[derive(Copy, Clone)]
struct WrappedSockaddrIn6(libc::sockaddr_in6);

unsafe impl Plain for WrappedSockaddrIn6 {}

impl WrappedSockaddrIn6 {
    fn from_bytes(buf: &[u8]) -> WrappedSockaddrIn6 {
        let mut addr6: WrappedSockaddrIn6 =
            *plain::from_bytes(buf).expect("Buffer cannot be decoded into sockaddr_in.");
        // libc normally converts the port from network byte order to host byte order. Since we
        // copied them directly from the kernel we need to do so.
        addr6.0.sin6_port = u16::from_be(addr6.0.sin6_port);
        addr6
    }

    fn bytelen() -> usize {
        mem::size_of::<libc::sockaddr_in6>()
    }
}

impl fmt::Display for WrappedSockaddrIn6 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "[{}]:{}",
            std::net::Ipv6Addr::from(self.0.sin6_addr.s6_addr),
            self.0.sin6_port,
        )
    }
}

fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!("Failed to increase rlimit");
    }

    Ok(())
}

fn handle_record(bytes: &[u8]) -> i32 {
    if bytes.len() == WrappedSockaddrIn::bytelen() {
        let addr_in = WrappedSockaddrIn::from_bytes(bytes);
        println!("ipv4:{}", &addr_in);
    } else if bytes.len() == WrappedSockaddrIn6::bytelen() {
        let addr_in6 = WrappedSockaddrIn6::from_bytes(bytes);
        println!("ipv6:{}", &addr_in6);
    } else {
        eprintln!(
            "Unrecognized record with byte length of {}, sockaddr_in should have {}",
            bytes.len(),
            WrappedSockaddrIn::bytelen()
        );
    }
    0
}

fn handle_lost_events(cpu: i32, count: u64) {
    eprintln!("Lost {count} connection events on CPU {cpu}");
}

fn main() -> Result<()> {
    println!("sockaddr_in: {} bytes", WrappedSockaddrIn::bytelen());
    println!("sockaddr_in6: {} bytes", WrappedSockaddrIn6::bytelen());

    bump_memlock_rlimit()?;

    let mut skel_builder = CertspookSkelBuilder::default();
    skel_builder.obj_builder.debug(true);
    let open_skel = skel_builder.open()?;
    let mut skel = open_skel.load()?;
    skel.attach()?;

    let mut map_handles = skel.maps_mut();
    let mut ringbuf_builder = RingBufferBuilder::new();
    ringbuf_builder.add(map_handles.connaddrs(), &handle_record)?;
    let connaddrs = ringbuf_builder.build()?;

    loop {
        connaddrs.poll(Duration::from_millis(100))?;
    }
}
