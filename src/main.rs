// SPDX-License-Identifier: AGPL-3.0-or-later

use std::fmt;
use std::time::Duration;

use anyhow::bail;
use anyhow::Result;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::RingBufferBuilder;
use libc; // TODO: replace custom sockaddr implementations with libc
use plain::Plain;
use std::mem;

mod certspook {
    include!(concat!(env!("OUT_DIR"), "/certspook.skel.rs"));
}

use certspook::*;

#[repr(C)]
#[derive(Default, Copy, Clone)]
struct in_addr {
    pub s_addr: u32,
}

#[repr(C)]
#[derive(Default, Copy, Clone)]
struct sockaddr_in {
    pub sin_family: u16,
    pub sin_port: u16,
    pub sin_addr: in_addr,
    pub sin_zero: [u8; 8],
}

unsafe impl Plain for sockaddr_in {}

impl sockaddr_in {
    fn from_bytes(buf: &[u8]) -> &sockaddr_in {
        plain::from_bytes(buf).expect("Buffer cannot be decoded into sockaddr_in.")
    }

    fn bytelen() -> usize {
        // return 16;
        // TODO: Why does mem::size_of return 8?
        return mem::size_of::<sockaddr_in>();
    }
}

impl fmt::Display for sockaddr_in {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // TODO: The bytes will be in host order in sockaddr_in so this is not portable.
        write!(
            f,
            "{}.{}.{}.{}:{}",
            (self.sin_addr.s_addr & 0xFF),
            (self.sin_addr.s_addr >> 8) & 0xFF,
            (self.sin_addr.s_addr >> 16) & 0xFF,
            (self.sin_addr.s_addr >> 24) & 0xFF,
            ((self.sin_port >> 8) & 0xFF) | ((self.sin_port << 8) & 0xFF00)
        )
    }
}

#[repr(C)]
#[derive(Default, Copy, Clone)]
struct sockaddr_in6 {
    pub sin6_family: u16,
    pub sin6_port: u16,
    pub sin6_flowinfo: u32,
    pub sin6_addr: [u8; 16],
    pub sin6_scope_id: u32,
}

unsafe impl Plain for sockaddr_in6 {}

impl sockaddr_in6 {
    fn from_bytes(buf: &[u8]) -> &sockaddr_in6 {
        plain::from_bytes(buf).expect("Buffer cannot be decoded into sockaddr_in.")
    }

    fn bytelen() -> usize {
        // return 28;
        // TODO: Can this be made to work?
        return mem::size_of::<sockaddr_in6>();
    }
}

impl fmt::Display for sockaddr_in6 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "[{}]:{}",
            std::net::Ipv6Addr::from(self.sin6_addr),
            self.sin6_port,
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

// These bytes should already be in big endian format.
fn handle_record(bytes: &[u8]) -> i32 {
    if bytes.len() == sockaddr_in::bytelen() {
        let addr_in = sockaddr_in::from_bytes(bytes);
        println!("ipv4:{}", &addr_in);
    } else if bytes.len() == sockaddr_in6::bytelen() {
        let addr_in6 = sockaddr_in6::from_bytes(bytes);
        println!("ipv6:{}", &addr_in6);
    } else {
        eprintln!(
            "Unrecognized record with byte length of {}, sockaddr_in should have {}",
            bytes.len(),
            sockaddr_in::bytelen()
        );
    }
    0
}

fn handle_lost_events(cpu: i32, count: u64) {
    eprintln!("Lost {count} connection events on CPU {cpu}");
}

fn main() -> Result<()> {
    println!("sockaddr_in: {} bytes", sockaddr_in::bytelen());
    println!("sockaddr_in6: {} bytes", sockaddr_in6::bytelen());

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
