extern crate gcc;

fn main() {
    gcc::compile_library("libasm.a", &["src/sha1_ssse3_asm.S", "src/sha1.c", "src/csum-partial_64.c"]);
}
