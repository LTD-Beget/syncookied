#[link(name = "sha1")]
extern "C" {
    pub fn sha1_transform_ssse3(digest: *mut u32, data: *const u8, rounds: u32);
    pub fn sha_transform(digest: *mut u32, data: *const u8, W: *mut u32);
}
