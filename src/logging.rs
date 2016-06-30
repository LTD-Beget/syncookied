use ::log;
use ::chrono;

struct SimpleLogger;

impl log::Log for SimpleLogger {
    fn enabled(&self, metadata: &log::LogMetadata) -> bool {
        metadata.level() <= log::LogLevel::Debug
    }

    fn log(&self, record: &log::LogRecord) {
        if self.enabled(record.metadata()) {
            let now = chrono::Local::now();
            println!("[{}] {} - {}", now, record.level(), record.args());
        }
    }
}

pub fn initialize(debug: bool) {
    log::set_logger(|max_log_level| {
        max_log_level.set(if debug { log::LogLevelFilter::Debug } else { log::LogLevelFilter::Info });
        Box::new(SimpleLogger)
    }).unwrap();
}
