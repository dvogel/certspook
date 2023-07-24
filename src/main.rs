// SPDX-License-Identifier: GPL-3.0

use core::time::Duration;

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

#[repr(C)]
#[derive(Default, Copy, Clone)]
struct sockaddr_in {
    pub sin_family: u16,
    pub sin_port: u16,
    pub sin_addr: u32,
}

unsafe impl Plain for sockaddr_in {}

impl sockaddr_in {
    fn from_bytes(buf: &[u8]) -> &sockaddr_in {
        plain::from_bytes(buf).expect("Buffer cannot be decoded into sockaddr_in.")
    }

    fn bytelen() -> usize {
        return 16;
        // TODO: Why does mem::size_of return 8?
        // return mem::size_of::<sockaddr_in>();
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
        // TODO: The bytes will be in host order in sockaddr_in so this is not portable.
        println!(
            "{}.{}.{}.{}:{}",
            addr_in.sin_addr & 0xFF,
            (addr_in.sin_addr >> 8) & 0xFF,
            (addr_in.sin_addr >> 16) & 0xFF,
            (addr_in.sin_addr >> 24) & 0xFF,
            ((addr_in.sin_port >> 8) & 0xFF) | ((addr_in.sin_port << 8) & 0xFF00)
        );
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
