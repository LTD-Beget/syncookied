#[link(name = "sha1")]
extern {
    pub fn sha1_transform_ssse3(digest: *mut u32, data: *const u8, rounds: u32);
}
