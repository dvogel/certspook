// SPDX-License-Identifier: AGPL-3.0-or-later

use libbpf_cargo::SkeletonBuilder;
use std::env;
use std::path::PathBuf;

const SRC: &str = "src/bpf/certspook.bpf.c";

fn main() {
    let out = PathBuf::from("src/certspook.skel.rs");
    SkeletonBuilder::new()
        .source(SRC)
        .build_and_generate(&out)
        .unwrap();
    println!("cargo:rerun-if-changed={SRC}");
}
