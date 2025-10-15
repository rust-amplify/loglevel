use std::error::Error;

use loglevel::{LogLevel, Logger};
fn main() -> Result<(), Box<dyn Error>> {
    let (log_level, json, bindings) = LogLevel::from_args()?;
    let logger = Logger::new(log_level, json, None);
    logger.apply()?;
    log::error!("Parent: error message");
    log::warn!("Parent: warning message");
    log::info!("Parent: info message");
    log::debug!("Parent: debug message");
    log::trace!("Parent: trace message");

    let child = logger.child(bindings.clone());
    child.apply()?;
    log::error!("Child: error message");
    log::warn!("Child: warning message");
    log::info!("Child: info message");
    log::debug!("Child: debug message");
    log::trace!("Child: trace message");

    Ok(())
}
