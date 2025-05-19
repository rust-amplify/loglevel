use std::error::Error;

use loglevel::LogLevel;

fn main() -> Result<(), Box<dyn Error>> {
    let log_level = LogLevel::from_args()?;

    log_level.apply()?;

    log::error!("This is an error");
    log::warn!("This is a warning");
    log::info!("This is an info");
    log::debug!("This is a debug");
    log::trace!("This is a trace");

    Ok(())
}
