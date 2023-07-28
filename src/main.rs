// SPDX-License-Identifier: AGPL-3.0-or-later

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fmt;
use std::rc::Rc;
use std::time::{Duration, Instant};

use anyhow::bail;
use anyhow::Result;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::RingBufferBuilder;
use plain::Plain;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

mod certspook {
    include!(concat!(env!("OUT_DIR"), "/certspook.skel.rs"));
}

use certspook::*;

#[derive(Copy, Clone, PartialEq, Eq)]
struct WrappedSockaddrIn(libc::sockaddr_in);
unsafe impl Plain for WrappedSockaddrIn {}

#[derive(Copy, Clone, PartialEq, Eq)]
struct WrappedSockaddrIn6(libc::sockaddr_in6);
unsafe impl Plain for WrappedSockaddrIn6 {}

enum WrappedSockaddr {
    V4(WrappedSockaddrIn),
    V6(WrappedSockaddrIn6),
}

impl WrappedSockaddr {
    fn from_bytes(buf: &[u8]) -> Option<WrappedSockaddr> {
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

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct RemoteConnection {
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
}

impl fmt::Display for RemoteConnection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.addr {
            IpAddr::V4(addr4) => write!(f, "v4:{}:{}", addr4, self.port,),
            IpAddr::V6(addr6) => write!(f, "v6:[{}]:{}", addr6, self.port,),
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct AddrSeenStats {
    first_seen: Instant,
    last_seen: Instant,
    count: usize,
}

impl Default for AddrSeenStats {
    fn default() -> Self {
        AddrSeenStats {
            first_seen: Instant::now(),
            last_seen: Instant::now(),
            count: 0,
        }
    }
}

#[derive(Copy, Clone)]
struct CertProbeResult {
    pub address: std::net::IpAddr,
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

fn handle_record(
    bytes: &[u8],
    addr_histo: Rc<RefCell<BTreeMap<RemoteConnection, AddrSeenStats>>>,
) -> i32 {
    if let Some(addr) = WrappedSockaddr::from_bytes(bytes) {
        if let Some(rconn) = RemoteConnection::from_sockaddr(&addr) {
            let mut borrowed_histo = addr_histo.borrow_mut();
            let mut addr_stats = borrowed_histo
                .entry(rconn)
                .or_insert_with(|| AddrSeenStats::default());
            addr_stats.count += 1 as usize;
            addr_stats.last_seen = Instant::now();
            println!("{}", &rconn);
        } else {
            eprintln!("warn:Unrecognized protocol family.");
        }
    } else {
        eprintln!("warn:Unrecognized message byte length.");
    }

    0
}

fn handle_lost_events(cpu: i32, count: u64) {
    eprintln!("Lost {count} connection events on CPU {cpu}");
}

fn main() -> Result<()> {
    let addr_histo: Rc<RefCell<BTreeMap<RemoteConnection, AddrSeenStats>>> =
        Rc::new(RefCell::new(BTreeMap::new()));

    bump_memlock_rlimit()?;

    let mut skel_builder = CertspookSkelBuilder::default();
    skel_builder.obj_builder.debug(true);
    let open_skel = skel_builder.open()?;
    let mut skel = open_skel.load()?;
    skel.attach()?;

    let mut map_handles = skel.maps_mut();
    let mut ringbuf_builder = RingBufferBuilder::new();
    ringbuf_builder.add(map_handles.connaddrs(), |bytes| {
        handle_record(bytes, addr_histo.clone())
    })?;
    let connaddrs = ringbuf_builder.build()?;

    loop {
        connaddrs.poll(Duration::from_millis(100))?;
    }
}
