// SPDX-License-Identifier: Apache-2.0

//! Simple way to set your log level

use std::error::Error;
use std::io::Write;
use std::{env, fmt};

#[cfg(feature = "json")]
use chrono::Utc;
use clap::{Arg, Command};
use log::{LevelFilter, Record};
#[cfg(feature = "json")]
use serde::Serialize;

#[cfg(feature = "json")]
#[derive(Serialize)]
struct JsonLog {
    level: String,
    message: String,
    timestamp: String,
}

#[cfg(feature = "custom_level")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomLogLevel {
    name: String,
    value: u8,
}

#[cfg(feature = "custom_level")]
impl CustomLogLevel {
    pub fn new(name: String, value: u8) -> Self { Self { name, value } }

    pub fn name(&self) -> &str { self.name.as_str() }
    pub fn value(&self) -> u8 { self.value }
}

/// Represents desired logging verbosity level
#[repr(u8)]
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum LogLevel {
    /// Do not log anything. Corresponds to zero verbosity flags.
    None = 0,
    /// Report only errors to `stderr` and normal program output to `stdout` (if not redirected).
    /// Corresponds to a single `-v` verbosity flag.
    Error,
    /// Report warning messages, errors, and standard output. Corresponds to `-vv` flags.
    Warn,
    /// Report general information messages, warnings, and errors. Corresponds to `-vvv` flags.
    Info,
    /// Report debugging information and all non-trace messages. Corresponds to `-vvvv` flags.
    Debug,
    /// Print all possible messages, including tracing information. Corresponds to `-vvvvv` flags.
    Trace,

    #[cfg(feature = "custom_level")]
    Custom(CustomLogLevel),
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            LogLevel::None => "none",
            LogLevel::Error => "error",
            LogLevel::Warn => "warn",
            LogLevel::Info => "info",
            LogLevel::Debug => "debug",
            LogLevel::Trace => "trace",
            #[cfg(feature = "custom_level")]
            LogLevel::Custom(custom) => custom.name(),
        };

        // Just write the string representation of the enum variant to the formatter.
        // In the case of LogLevel, all variants are a single word, so this is sufficient.
        write!(f, "{}", s)
    }
}

impl From<u8> for LogLevel {
    fn from(val: u8) -> Self { Self::from_verbosity_flag_count(val) }
}

impl From<LogLevel> for u8 {
    fn from(log_level: LogLevel) -> Self { log_level.verbosity_flag_count() }
}

impl From<LogLevel> for LevelFilter {
    fn from(log_level: LogLevel) -> Self {
        match log_level {
            LogLevel::None => LevelFilter::Off,
            LogLevel::Error => LevelFilter::Error,
            LogLevel::Warn => LevelFilter::Warn,
            LogLevel::Info => LevelFilter::Info,
            LogLevel::Debug => LevelFilter::Debug,
            LogLevel::Trace => LevelFilter::Trace,
            #[cfg(feature = "custom_level")]
            LogLevel::Custom(custom) => match custom.value {
                v if v <= 1 => LevelFilter::Error,
                v if v <= 2 => LevelFilter::Warn,
                v if v <= 3 => LevelFilter::Info,
                v if v <= 4 => LevelFilter::Debug,
                _ => LevelFilter::Trace,
            },
        }
    }
}

impl LogLevel {
    /// Indicates number of required verbosity flags
    pub fn verbosity_flag_count(&self) -> u8 {
        match self {
            LogLevel::None => 0,
            LogLevel::Error => 1,
            LogLevel::Warn => 2,
            LogLevel::Info => 3,
            LogLevel::Debug => 4,
            LogLevel::Trace => 5,
            #[cfg(feature = "custom_level")]
            LogLevel::Custom(custom) => custom.value,
        }
    }

    /// Logs a warning if the verbosity level exceeds 5, as it will be treated as `Trace`.
    pub fn from_verbosity_flag_count(level: u8) -> Self {
        if level > 5 {
            log::warn!("Verbosity level {} exceeds maximum; using Trace", level);
        }
        match level {
            0 => LogLevel::None,
            1 => LogLevel::Error,
            2 => LogLevel::Warn,
            3 => LogLevel::Info,
            4 => LogLevel::Debug,
            _ => LogLevel::Trace,
        }
    }

    #[cfg(feature = "custom_level")]
    pub fn custom(name: String, value: u8) -> Self {
        LogLevel::Custom(CustomLogLevel::new(name, value))
    }

    /// Parses verbosity level from command-line arguments using `-v` flags.
    ///
    /// # Errors
    /// Returns an error if command-line parsing fails.
    ///
    /// # Examples
    /// ```
    /// use loglevel::LogLevel;
    /// let log_level = LogLevel::from_args().expect("Failed to parse arguments");
    /// log_level.apply().expect("Failed to initialize logger");
    /// ```
    pub fn from_args() -> Result<Self, Box<dyn Error>> {
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
                    .help("Custom log level value (e.g., --custom-level http=10)"),
            )
            .get_matches();

        let verbosity = matches.get_count("verbose");
        #[cfg(feature = "custom_level")]
        if let Some(custom_levels) = matches.get_many::<String>("custom-level") {
            if let Some(custom) = custom_levels.clone().last() {
                let parts = custom.split('=').collect::<Vec<&str>>();
                if parts.len() == 2 {
                    let name = parts[0].to_string();
                    let value = parts[1].parse::<u8>()?;
                    return Ok(LogLevel::custom(name.to_string(), value));
                } else {
                    return Err("Invalid custom log level format".into());
                }
            }
        }
        Ok(Self::from_verbosity_flag_count(verbosity))
    }

    /// Applies the log level to the system with optional custom `RUST_LOG` configuration.
    ///
    /// If `custom_log` is provided, it is used as the `RUST_LOG` value. If `override_existing` is
    /// `true`, the `RUST_LOG` environment variable is set even if already defined. Otherwise, the
    /// existing `RUST_LOG` is respected.
    ///
    /// # Errors
    /// Returns an error if the logger fails to initialize.
    ///
    /// # Examples
    /// ```
    /// use loglevel::LogLevel;
    /// LogLevel::Info
    ///     .apply_custom(None, false, false)
    ///     .expect("Failed to initialize logger");
    /// log::info!("This message will be logged");
    ///
    /// // Custom RUST_LOG configuration
    /// LogLevel::Debug
    ///     .apply_custom(Some("my_module=trace,info".to_string()), true, false)
    ///     .expect("Failed to initialize logger");
    /// ```
    pub fn apply_custom(
        &self,
        custom_log: Option<String>,
        override_existing: bool,
        json: bool,
    ) -> Result<(), Box<dyn Error + 'static>> {
        static INIT: std::sync::Once = std::sync::Once::new();
        let filter = LevelFilter::from(self.clone());
        INIT.call_once(|| {
            if override_existing || env::var("RUST_LOG").is_err() {
                let log_value = custom_log.unwrap_or_else(|| self.to_string());
                env::set_var("RUST_LOG", log_value);
            }

            let mut builder = env_logger::Builder::from_env(
                env_logger::Env::default().default_filter_or(self.to_string()),
            );

            if json {
                #[cfg(feature = "json")]
                {
                    let this = self.clone();
                    builder.format(move |buf, record: &Record| {
                        let level_str = match &this {
                            #[cfg(feature = "custom_level")]
                            LogLevel::Custom(custom) => custom.name().to_string(),
                            _ => record.level().as_str().to_string(),
                        };
                        let json_log = JsonLog {
                            level: level_str,
                            message: record.args().to_string(),
                            timestamp: Utc::now().to_rfc3339(),
                        };

                        let json_str = serde_json::to_string(&json_log)?;
                        buf.write_all(json_str.as_bytes())?;
                        buf.write_all(b"\n")
                    });
                }

                #[cfg(not(feature = "json"))]
                {
                    panic!("JSON output requires the `json` feature")
                }
            }

            builder.filter_level(filter).try_init().expect("Logger");
        });

        Ok(())
    }

    /// Applies the log level to the system, respecting existing `RUST_LOG` settings.
    ///
    /// # Errors
    /// Returns an error if the logger fails to initialize.
    ///
    /// # Examples
    /// ```
    /// use loglevel::LogLevel;
    /// LogLevel::Info.apply().expect("Failed to initialize logger");
    /// log::info!("This message will be logged");
    /// ```
    pub fn apply(self) -> Result<(), Box<dyn Error>> { self.apply_custom(None, false, false) }
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
    fn test_from_verbosity_flag_count() {
        assert_eq!(LogLevel::from_verbosity_flag_count(0), LogLevel::None);
        assert_eq!(LogLevel::from_verbosity_flag_count(1), LogLevel::Error);
        assert_eq!(LogLevel::from_verbosity_flag_count(2), LogLevel::Warn);
        assert_eq!(LogLevel::from_verbosity_flag_count(3), LogLevel::Info);
        assert_eq!(LogLevel::from_verbosity_flag_count(4), LogLevel::Debug);
        assert_eq!(LogLevel::from_verbosity_flag_count(5), LogLevel::Trace);
        assert_eq!(LogLevel::from_verbosity_flag_count(6), LogLevel::Trace);
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
    #[cfg(feature = "custom_level")]
    fn test_custom_level() {
        LogLevel::Custom(CustomLogLevel::new("http", 10))
            .apply_custom(None, false, false)
            .expect("Failed to initialize logger");
        log::info!("This is a custom log");
    }

    #[test]
    #[cfg(all(feature = "custom_level", feature = "json"))]
    fn test_custom_level_json() {
        LogLevel::Custom(CustomLogLevel::new("http", 10))
            .apply_custom(None, false, true)
            .expect("Failed to initialize logger");
        log::info!("This is a custom log");
    }
}
