// SPDX-License-Identifier: AGPL-3.0-or-later

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;
use std::sync::mpsc::{Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

use crate::check::CheckDatum;
use crate::remote_connection::RemoteConnection;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct AddrSeenStats {
    first_seen: Instant,
    last_seen: Instant,
    last_checked: Option<Instant>,
    count: usize,
}

impl Default for AddrSeenStats {
    fn default() -> Self {
        AddrSeenStats {
            first_seen: Instant::now(),
            last_seen: Instant::now(),
            last_checked: None,
            count: 0,
        }
    }
}

pub fn spawn_squelch_thread(
    threshold: Duration,
    rx: Receiver<RemoteConnection>,
    tx: Sender<CheckDatum>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let addr_histo: Rc<RefCell<BTreeMap<RemoteConnection, AddrSeenStats>>> =
            Rc::new(RefCell::new(BTreeMap::new()));

        loop {
            let rconn = match rx.recv() {
                Err(_) => return,
                Ok(val) => val,
            };
            let mut borrowed_histo = addr_histo.borrow_mut();
            let addr_stats = borrowed_histo
                .entry(rconn)
                .or_insert(AddrSeenStats::default());
            addr_stats.count += 1_usize;
            addr_stats.last_seen = Instant::now();
            let will_check_now = match addr_stats.last_checked {
                Some(last_checked) => (Instant::now() - last_checked) > threshold,
                None => true,
            };
            if will_check_now {
                println!("debug:queued-connection:{}", &rconn);
                std::thread::sleep(Duration::from_secs(1));
                tx.send(CheckDatum::RemoteConnectionMessage(rconn));
                addr_stats.last_checked = Some(Instant::now());
            } else {
                println!("debug:squelched-observation:{}", &rconn);
            }
        }
    })
}
