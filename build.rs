extern crate gcc;

use std::env;

fn main() {
    let static_libpcap_path = env::var_os("STATIC_LIBPCAP_PATH");

    gcc::compile_library("libasm.a", &["src/sha1_ssse3_asm.S", "src/sha1.c", "src/csum-partial_64.c"]);
    if let Some(path) = static_libpcap_path {
        println!("cargo:rustc-link-lib=static=pcap");
        println!("cargo:rustc-link-search=native={}", path.into_string().unwrap());
    }
}
