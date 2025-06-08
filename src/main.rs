use std::env;
use std::error::Error;

use clap::{Arg, Command};
use loglevel::LogLevel;

fn main() -> Result<(), Box<dyn Error>> {
    // let log_level = LogLevel::from_args()?;

    // log_level.apply()?;

    // log::error!("This is an error");
    // log::warn!("This is a warning");
    // log::info!("This is an info");
    // log::debug!("This is a debug");
    // log::trace!("This is a trace");

    let matches = Command::new(env!("CARGO_PKG_NAME"))
        .arg(
            Arg::new("verbose")
                .short('v')
                .action(clap::ArgAction::Count)
                .help("Increase verbosity level (e.g., -vvv for Info)"),
        )
        .arg(
            Arg::new("json")
                .long("json")
                .action(clap::ArgAction::SetTrue)
                .help("Enable JSON formatting"),
        )
        .get_matches();

    let log_level = LogLevel::from_verbosity_flag_count(matches.get_count("verbose"));
    let json = matches.get_flag("json");

    log_level.apply_custom(None, false, json)?;

    log::error!("This is an error");
    log::warn!("This is a warning");
    log::info!("This is an info");
    log::debug!("This is a debug");
    log::trace!("This is a trace");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verbosity_flag_count() {
        assert_eq!(LogLevel::None.verbosity_flag_count(), 0);
        assert_eq!(LogLevel::Error.verbosity_flag_count(), 1);
        assert_eq!(LogLevel::Warn.verbosity_flag_count(), 2);
        assert_eq!(LogLevel::Info.verbosity_flag_count(), 3);
        assert_eq!(LogLevel::Debug.verbosity_flag_count(), 4);
        assert_eq!(LogLevel::Trace.verbosity_flag_count(), 5);
    }

    #[test]
    #[cfg(feature = "json")]
    fn test_json_logging() {
        LogLevel::Info
            .apply_custom(None, false, true)
            .expect("Failed to initialize logger");
        log::info!("This is a JSON log");
        // Should output: {"level":"info","message":"This is a JSON log","timestamp":"..."}
    }

    #[test]
    fn test_plain_logging() {
        LogLevel::Info
            .apply_custom(None, false, false)
            .expect("Failed to initialize logger");
        log::info!("This is a plain log");
        // Should output: [timestamp] INFO This is a plain log
    }
}
