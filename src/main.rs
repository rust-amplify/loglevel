use std::env;
use std::error::Error;

use clap::{Arg, Command};
use loglevel::LogLevel;

fn main() -> Result<(), Box<dyn Error>> {
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
        .arg(
            Arg::new("custom-level")
                .long("custom-level")
                .action(clap::ArgAction::Append)
                .help("Define a custom log level (e.g., --custom-level http=10)"),
        )
        .get_matches();

   
    let json = matches.get_flag("json");
    //let log_level = LogLevel::from_verbosity_flag_count(matches.get_count("verbose"));
    let log_level = if let Some(custom_level) = matches.get_many::<String>("custom-level") {
        let custom = custom_level.last().ok_or("No custom level provided")?; 
        let parts: Vec<&str> = custom.split('=').collect();
        if parts.len() != 2 {
            return Err("Invalid custom level format".into());
        }

        #[cfg(feature = "custom_level")]
        {
            let name = parts[0].to_string();
            let value = parts[1].parse::<u8>().unwrap();
            LogLevel::custom(name, value)
        }
        #[cfg(not(feature = "custom_level"))]
        {
            return Err("Invalid custom level format".into());
        }
    }
    else {
        LogLevel::from_verbosity_flag_count(matches.get_count("verbose"))
    };

   log_level.apply_custom(None, false, json)?;
    let log_level = LogLevel::from_args();

    log_level.apply();

    log::error!("This is an error");
    log::warn!("This is a warning");
    log::info!("This is an info");
    log::debug!("This is a debug");
    log::trace!("This is a trace");

    Ok(())
}