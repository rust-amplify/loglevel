// SPDX-License-Identifier: Apache-2.0

//! Simple way to set your log level

use std::error::Error;
use std::{env, fmt};

use clap::{Arg, Command};
use log::LevelFilter;

/// Represents the desired logging verbosity level
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
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
        };

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
        }
    }
}

impl LogLevel {
    /// Indicates number of required verbosity flags
    pub fn verbosity_flag_count(&self) -> u8 { *self as u8 }

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
            .get_matches();

        let verbosity = matches.get_count("verbose");
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
    ///     .apply_custom(None, false)
    ///     .expect("Failed to initialize logger");
    /// log::info!("This message will be logged");
    ///
    /// // Custom RUST_LOG configuration
    /// LogLevel::Debug
    ///     .apply_custom(Some("my_module=trace,info".to_string()), true)
    ///     .expect("Failed to initialize logger");
    /// ```
    pub fn apply_custom(
        &self,
        custom_log: Option<String>,
        override_existing: bool,
    ) -> Result<(), Box<dyn Error>> {
        static INIT: std::sync::Once = std::sync::Once::new();
        let filter = LevelFilter::from(*self);
        INIT.call_once(|| {
            if override_existing || env::var("RUST_LOG").is_err() {
                let log_value = custom_log.unwrap_or_else(|| self.to_string());
                env::set_var("RUST_LOG", log_value);
            }

            env_logger::Builder::from_env(
                env_logger::Env::default().default_filter_or(self.to_string()),
            )
            .filter_level(filter)
            .try_init()
            .expect("Logger instantiation failed");
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
    pub fn apply(self) -> Result<(), Box<dyn Error>> { self.apply_custom(None, false) }
}
