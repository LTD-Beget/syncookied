use std::fs::OpenOptions;
use std::io::Write;
use ::libc;

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
