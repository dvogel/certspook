// SPDX-License-Identifier: AGPL-3.0-or-later

use std::sync::{
    mpsc::{channel, Sender},
    Mutex,
};
use std::time::Duration;

use anyhow::bail;
use anyhow::Result;
use clap::Parser;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::RingBufferBuilder;
use slog::{error, info, o, warn, Drain, Logger};

mod certspook {
    include!("certspook.skel.rs");
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

#[derive(Parser, Debug)]
#[command(about, long_about = None)]
struct CmdArgs {
    #[arg(long, default_value_t = 30)]
    expiration_threshold: u32,

    #[arg(long, default_value_t = 10)]
    squelch_seconds: u32,
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

fn handle_record(log: Logger, bytes: &[u8], tx_rconn: &Sender<RemoteConnection>) -> i32 {
    if let Some(rconn) = RemoteConnection::from_bytes(bytes) {
        if let Err(e) = tx_rconn.send(rconn) {
            error!(log, "{}", e);
            return 1;
        }
    } else {
        warn!(log, "Unrecognized sockaddr record.");
    }

    0
}

fn handle_gai_result(log: Logger, bytes: &[u8], tx_chkque: &Sender<CheckDatum>) -> i32 {
    // TODO: Some of these results are due to an IP address being looked up as a hostname. In that
    // case we see sensical but unhelpful events like this:
    // debug:decoded-exported-gai-result:162.243.1.193:162.243.1.193
    match GetAddrInfoResult::from_bytes(bytes) {
        Ok(gai_result) => {
            if let Err(e) = tx_chkque.send(CheckDatum::GetAddrInfoMessage(gai_result)) {
                error!(log, "{}", e);
                return 1;
            }
        }
        Err(e) => {
            warn!(log, "{}", e);
        }
    }
    0
}

fn handle_lost_events(cpu: i32, count: u64) {
    eprintln!("Lost {count} connection events on CPU {cpu}");
}

fn pretty_duration(duration: &time::Duration) -> String {
    const SECS_PER_HOUR: i64 = 60 * 60;
    const SECS_PER_DAY: i64 = SECS_PER_HOUR * 24;
    let mut remainder = duration.as_seconds_f64() as i64;
    let days = remainder / SECS_PER_DAY;
    remainder %= SECS_PER_DAY;
    let hours = remainder / SECS_PER_HOUR;
    format!("{}d{}h", days, hours)
}

fn main() -> Result<()> {
    let log_root = slog::Logger::root(
        Mutex::new(slog_json::Json::default(std::io::stderr())).map(slog::Fuse),
        o!(),
    );

    let cmd_args = CmdArgs::parse();
    let expiration_threshold = time::Duration::days(cmd_args.expiration_threshold as i64);

    info!(
        log_root,
        "configuration";
        "expiration_threshold" => pretty_duration(&expiration_threshold)
    );

    let (tx_chkque, rx_chkque) = channel::<CheckDatum>();
    let tx_chkque1 = tx_chkque.clone();
    let _check_thread = spawn_check_thread(log_root.clone(), expiration_threshold, rx_chkque);

    let (tx_rconn, rx_rconn) = channel::<RemoteConnection>();
    let _squelch_thread = spawn_squelch_thread(
        log_root.clone(),
        Duration::from_secs(cmd_args.squelch_seconds as u64),
        rx_rconn,
        tx_chkque,
    );

    bump_memlock_rlimit()?;

    let current_pid: u32 = std::process::id();
    info!(
        log_root,
        "startup";
        "pid" => current_pid.to_string()
    );

    let mut skel_builder = CertspookSkelBuilder::default();
    skel_builder.obj_builder.debug(true);
    let mut open_skel = skel_builder.open()?;
    open_skel.bss().g_certspook_tgid = current_pid;

    let mut skel = open_skel.load()?;
    skel.attach()?;

    let mut map_handles = skel.maps_mut();

    let mut connaddr_ringbuf_builder = RingBufferBuilder::new();
    connaddr_ringbuf_builder.add(map_handles.connaddrs(), {
        let log = log_root.clone();
        move |bytes| {
            let log = log.clone();
            handle_record(log, bytes, &tx_rconn)
        }
    })?;
    let connaddrs = connaddr_ringbuf_builder.build()?;

    let mut ex_gai_ringbuf_builder = RingBufferBuilder::new();
    ex_gai_ringbuf_builder.add(map_handles.exported_gai_results(), move |bytes| {
        handle_gai_result(log_root.clone(), bytes, &tx_chkque1)
    })?;
    let exported_gai_results = ex_gai_ringbuf_builder.build()?;

    loop {
        connaddrs.poll(Duration::from_millis(10))?;
        exported_gai_results.poll(Duration::from_millis(10))?;
    }
}
