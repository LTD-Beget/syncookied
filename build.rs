extern crate gcc;

fn main() {
    //gcc::compile_library("libsha1.a", &["src/sha1_ssse3_asm.S"]);
    gcc::compile_library("libsha1.a", &["src/sha1_ssse3_asm.S", "src/sha1.c"]);
}
