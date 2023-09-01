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
mod check;
mod gai_result;
mod remote_connection;
mod squelch;
mod wrapped_sockaddr;

use certspook::*;
use check::{spawn_check_thread, CheckDatum};
use gai_result::GetAddrInfoResult;
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

fn handle_gai_result(bytes: &[u8], tx_chkque: &Sender<CheckDatum>) -> i32 {
    // TODO: Some of these results are due to an IP address being looked up as a hostname. In that
    // case we see sensical but unhelpful events like this:
    // debug:decoded-exported-gai-result:162.243.1.193:162.243.1.193
    if let Ok(gai_result) = GetAddrInfoResult::from_bytes(bytes) {
        let gai_result1 = gai_result.clone();
        if let Err(e) = tx_chkque.send(CheckDatum::GetAddrInfoMessage(gai_result)) {
            eprintln!("{}", e);
            return 1;
        }
    } else {
        eprintln!(
            "warn:Unrecognized getaddrinfo() result perf event: {} bytes",
            bytes.len()
        );
    }
    0
}

fn handle_lost_events(cpu: i32, count: u64) {
    eprintln!("Lost {count} connection events on CPU {cpu}");
}

fn main() -> Result<()> {
    let expiration_threshold = Duration::from_secs(60u64 * 60u64 * 24u64 * 365u64);

    let (tx_chkque, rx_chkque) = channel::<CheckDatum>();
    let tx_chkque1 = tx_chkque.clone();
    let _check_thread = spawn_check_thread(expiration_threshold, rx_chkque);

    let (tx_rconn, rx_rconn) = channel::<RemoteConnection>();
    let _squelch_thread = spawn_squelch_thread(Duration::from_secs(10u64), rx_rconn, tx_chkque);

    bump_memlock_rlimit()?;

    let mut skel_builder = CertspookSkelBuilder::default();
    skel_builder.obj_builder.debug(true);
    let open_skel = skel_builder.open()?;
    let mut skel = open_skel.load()?;
    skel.attach()?;

    let mut map_handles = skel.maps_mut();

    let mut connaddr_ringbuf_builder = RingBufferBuilder::new();
    connaddr_ringbuf_builder.add(map_handles.connaddrs(), move |bytes| {
        handle_record(bytes, &tx_rconn)
    })?;
    let connaddrs = connaddr_ringbuf_builder.build()?;

    let mut ex_gai_ringbuf_builder = RingBufferBuilder::new();
    ex_gai_ringbuf_builder.add(map_handles.exported_gai_results(), move |bytes| {
        handle_gai_result(bytes, &tx_chkque1)
    })?;
    let exported_gai_results = ex_gai_ringbuf_builder.build()?;

    loop {
        connaddrs.poll(Duration::from_millis(100))?;
        exported_gai_results.poll(Duration::from_millis(100))?;
    }
}
