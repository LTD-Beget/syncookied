/// Just a wrapper around C/assembly functions
#[allow(dead_code)]
#[link(name = "asm")]
extern "C" {
    #[allow(dead_code)]
    fn sha1_transform_ssse3(digest: *mut u32, data: *const u8, rounds: u32);
    #[allow(dead_code)]
    fn sha1_transform_avx(digest: *mut u32, data: *const u8, rounds: u32);
    #[allow(dead_code)]
    fn sha_transform(digest: *mut u32, data: *const u8, W: *mut u32);
}

#[cfg(feature = "avx")]
pub unsafe fn sha1_transform_platform(digest: *mut u32, data: *const u8, rounds: u32) {
    sha1_transform_avx(digest, data, rounds)
}

#[cfg(feature = "sse3")]
pub unsafe fn sha1_transform_platform(digest: *mut u32, data: *const u8, rounds: u32) {
    sha1_transform_ssse3(digest, data, rounds)
}

#[cfg(not(any(feature = "avx", feature = "sse3")))]
pub unsafe fn sha1_transform_platform(digest: *mut u32, data: *const u8, rounds: u32) {
    let mut buf: [u32; SHA_WORKSPACE_WORDS] = unsafe { mem::uninitialized() };
    sha_transform(digest, data, &mut buf);
}
