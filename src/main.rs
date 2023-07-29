// SPDX-License-Identifier: AGPL-3.0-or-later

use std::sync::mpsc::{channel, Sender};
use std::time::Duration;

use anyhow::bail;
use anyhow::Result;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::RingBufferBuilder;

mod certspook {
    include!(concat!(env!("OUT_DIR"), "/certspook.skel.rs"));
}
mod remote_connection;
mod squelch;

use certspook::*;
use remote_connection::RemoteConnection;
use squelch::spawn_squelch_thread;

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

fn handle_record(bytes: &[u8], tx_rconn: &Sender<RemoteConnection>) -> i32 {
    if let Some(rconn) = RemoteConnection::from_bytes(bytes) {
        if let Err(e) = tx_rconn.send(rconn) {
            eprintln!("{}", e);
            return 1;
        }
    } else {
        eprintln!("warn:Unrecognized sockaddr record.");
    }

    0
}

fn handle_lost_events(cpu: i32, count: u64) {
    eprintln!("Lost {count} connection events on CPU {cpu}");
}

fn main() -> Result<()> {
    let (tx_rconn, rx_rconn) = channel::<RemoteConnection>();
    let _squelch_thread = spawn_squelch_thread(rx_rconn);

    bump_memlock_rlimit()?;

    let mut skel_builder = CertspookSkelBuilder::default();
    skel_builder.obj_builder.debug(true);
    let open_skel = skel_builder.open()?;
    let mut skel = open_skel.load()?;
    skel.attach()?;

    let mut map_handles = skel.maps_mut();
    let mut ringbuf_builder = RingBufferBuilder::new();
    ringbuf_builder.add(map_handles.connaddrs(), move |bytes| {
        handle_record(bytes, &tx_rconn)
    })?;
    let connaddrs = ringbuf_builder.build()?;

    loop {
        connaddrs.poll(Duration::from_millis(100))?;
    }
}
