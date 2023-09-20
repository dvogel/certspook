// SPDX-License-Identifier: AGPL-3.0-or-later

use std::num::ParseIntError;
use std::sync::{
    mpsc::{channel, Sender},
    Mutex,
};
use std::time::Duration;

use anyhow::bail;
use anyhow::Result;
use cidr_utils::cidr::{IpCidr, IpCidrError, Ipv4Cidr, Ipv6Cidr};
use clap::Parser;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::RingBufferBuilder;
use slog::{debug, error, info, o, warn, Drain, Logger};

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
use remote_connection::{RemoteConnection, RemoteConnectionFilter};
use squelch::spawn_squelch_thread;

#[derive(Parser, Debug)]
#[command(about, long_about = None)]
struct CmdArgs {
    #[arg(long, default_value_t = 30)]
    expiration_threshold: u32,

    #[arg(long, default_value_t = 10)]
    squelch_seconds: u32,

    #[arg(long, default_value_t = false)]
    debug: bool,

    // This currently only includes 443 for HTTPS because that is the only certificate checker
    // implemented. It would be nice to support each of these eventually.
    // 443: HTTPS
    // 465: SMTP over TLS
    // 587: SMTP with STARTLS
    // 993: IMAP over TLS
    // 995: POP over TLS
    #[arg(long, default_value_t = String::from("443"))]
    included_ports: String,

    #[arg(long, default_value_t = String::from(""))]
    included_networks: String,
}

impl CmdArgs {
    pub fn included_networks(&self) -> Result<Vec<IpCidr>, IpCidrError> {
        Result::from_iter(
            self.included_networks
                .split_terminator(',')
                .map(IpCidr::from_str)
                .collect::<Vec<Result<IpCidr, IpCidrError>>>(),
        )
    }

    pub fn included_ports(&self) -> Result<Vec<u16>, ParseIntError> {
        Result::from_iter(
            self.included_ports
                .split_terminator(',')
                .map(|cidrstr| cidrstr.parse::<u16>())
                .collect::<Vec<Result<u16, ParseIntError>>>(),
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

fn handle_record(
    log: &Logger,
    bytes: &[u8],
    filter: &RemoteConnectionFilter,
    tx_rconn: &Sender<RemoteConnection>,
) -> i32 {
    if let Some(rconn) = RemoteConnection::from_bytes(bytes) {
        if filter.allows(&rconn) {
            if let Err(e) = tx_rconn.send(rconn) {
                error!(log, "{}", e);
                return 1;
            }
        } else {
            debug!(log, "Ignoring remote connection."; "rconn" => format!("{}", rconn));
        }
    } else {
        warn!(log, "Unrecognized sockaddr record.");
    }

    0
}

fn handle_gai_result(
    log: &Logger,
    bytes: &[u8],
    filter: &RemoteConnectionFilter,
    tx_chkque: &Sender<CheckDatum>,
) -> i32 {
    // TODO: Some of these results are due to an IP address being looked up as a hostname. In that
    // case we see sensical but unhelpful events like this:
    // debug:decoded-exported-gai-result:162.243.1.193:162.243.1.193
    match GetAddrInfoResult::from_bytes(bytes) {
        Ok(gai_result) => {
            if filter.allows_addr(&gai_result.addr) {
                if let Err(e) = tx_chkque.send(CheckDatum::GetAddrInfoMessage(gai_result)) {
                    error!(log, "{}", e);
                    return 1;
                }
            } else {
                debug!(log, "Ignoring getaddrinfo() result."; "addr" => format!("{}", &gai_result.addr));
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
    let cmd_args = CmdArgs::parse();
    let expiration_threshold = time::Duration::days(cmd_args.expiration_threshold as i64);

    let log_root = slog::Logger::root(
        Mutex::new(slog::LevelFilter::new(
            slog_json::Json::default(std::io::stdout()),
            match cmd_args.debug {
                true => slog::Level::Debug,
                false => slog::Level::Info,
            },
        ))
        .map(slog::Fuse),
        o!(),
    );

    info!(
        log_root,
        "configuration";
        "expiration_threshold" => pretty_duration(&expiration_threshold),
        "included_ports" => format!("{:?}", cmd_args.included_ports()?),
        "included_networks" => format!("{:?}", cmd_args.included_networks()?),
    );

    let (tx_chkque, rx_chkque) = channel::<CheckDatum>();
    let _check_thread = spawn_check_thread(log_root.clone(), expiration_threshold, rx_chkque);

    let (tx_rconn, rx_rconn) = channel::<RemoteConnection>();
    let _squelch_thread = {
        let tx_chkque = tx_chkque.clone();

        spawn_squelch_thread(
            log_root.clone(),
            Duration::from_secs(cmd_args.squelch_seconds as u64),
            rx_rconn,
            tx_chkque,
        )
    };

    bump_memlock_rlimit()?;

    let current_pid: u32 = std::process::id();
    info!(
        log_root,
        "startup";
        "pid" => current_pid.to_string()
    );

    let mut skel_builder = CertspookSkelBuilder::default();
    if cmd_args.debug {
        skel_builder.obj_builder.debug(true);
    }
    let mut open_skel = skel_builder.open()?;
    open_skel.bss().g_certspook_tgid = current_pid;

    let mut skel = open_skel.load()?;
    skel.attach()?;

    let mut map_handles = skel.maps_mut();

    let rconn_filter = RemoteConnectionFilter::new(
        cmd_args.included_networks()?.clone(),
        cmd_args.included_ports()?.clone(),
    );

    let mut connaddr_ringbuf_builder = RingBufferBuilder::new();
    connaddr_ringbuf_builder.add(map_handles.connaddrs(), {
        |bytes| handle_record(&log_root, bytes, &rconn_filter, &tx_rconn)
    })?;
    let connaddrs = connaddr_ringbuf_builder.build()?;

    let gai_filter = RemoteConnectionFilter::new(cmd_args.included_networks()?.clone(), Vec::new());
    let mut ex_gai_ringbuf_builder = RingBufferBuilder::new();
    ex_gai_ringbuf_builder.add(map_handles.exported_gai_results(), |bytes| {
        handle_gai_result(&log_root, bytes, &gai_filter, &tx_chkque)
    })?;
    let exported_gai_results = ex_gai_ringbuf_builder.build()?;

    loop {
        connaddrs.poll(Duration::from_millis(10))?;
        exported_gai_results.poll(Duration::from_millis(10))?;
    }
}
