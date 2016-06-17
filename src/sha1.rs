/// Just a wrapper around C/assembly functions
#[allow(dead_code)]
#[link(name = "asm")]
extern "C" {
    #[allow(dead_code)]
    pub fn sha1_transform_ssse3(digest: *mut u32, data: *const u8, rounds: u32);
    #[allow(dead_code)]
    pub fn sha1_transform_avx(digest: *mut u32, data: *const u8, rounds: u32);
    #[allow(dead_code)]
    pub fn sha_transform(digest: *mut u32, data: *const u8, W: *mut u32);
}
