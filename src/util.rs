use std::fs::OpenOptions;
use std::io::Write;
use std::num::ParseIntError;
use ::libc;
use ::pnet::util::MacAddr;

pub fn set_thread_name(name: &str) {
    let tid = unsafe { libc::syscall(186 /* gettid on x86_64 */) }; /* FIXME */
    let mut file = OpenOptions::new()
                    .write(true)
                    .create(false)
                    .open(format!("/proc/self/task/{}/comm", tid)).unwrap();
    file.write_all(name.as_bytes());
}

pub fn get_cpu_count() -> usize {
    unsafe {
        libc::sysconf(libc::_SC_NPROCESSORS_ONLN) as usize
    }
}

pub fn parse_mac(text: &str) -> Result<MacAddr, ParseIntError> {
    let mut result = [0, 0, 0, 0, 0, 0];
    for (idx, word) in text.split(':').enumerate() {
        result[idx] = try!(u8::from_str_radix(word, 16));
    }
    Ok(MacAddr::new(result[0], result[1], result[2], result[3], result[4], result[5]))
}
