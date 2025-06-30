// SPDX-License-Identifier: Apache-2.0

//! Simple way to set your log level

pub(crate) mod transport;

use std::cell::RefCell;
use std::collections::HashMap;
use std::error::Error;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use std::{env, fmt};

#[cfg(feature = "json")]
use chrono::Utc;
use clap::{Arg, Command};
use log::{LevelFilter, Record};
#[cfg(feature = "json")]
use serde::Serialize;
#[cfg(feature = "remote")]
use transport::RemoteTransport;
use transport::{
    ConsoleTransport, FileTransport, Transport, TransportConfig, TransportDestination,
};

#[cfg(feature = "json")]
#[derive(Serialize)]
struct JsonLog {
    level: String,
    message: String,
    timestamp: String,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    bindings: HashMap<String, String>,
}

#[cfg(feature = "custom_level")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomLogLevel {
    name: String,
    value: u8,
}

#[derive(Clone)]
pub struct Logger {
    level: LogLevel,
    json: bool,
    bindings: HashMap<String, String>,
    transport: Option<Vec<TransportConfig>>,
}

type TransportBox = Box<dyn Transport>;
type TransportRef = Arc<Mutex<TransportBox>>;
type TransportList = Vec<TransportRef>;

thread_local! {
    // Keep the original type for CURRENT_LOGGER
    static CURRENT_LOGGER: RefCell<Option<Logger>> = const {RefCell::new(None) };

    // Update TRANSPORTS to use tyoe alias
    static TRANSPORTS: RefCell<Option<TransportList>> = const { RefCell::new(None) };
}

pub type LogConfig = (LogLevel, bool, HashMap<String, String>);

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
    /// Report custom level, debug, info, warnings and errors to `stderr` and normal program output
    /// to `stdout` (if not redirected). Corresponds to a custom verbosity flag.
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
        write!(f, "{s}")
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

impl Logger {
    pub fn new(level: LogLevel, json: bool, transport: Option<Vec<TransportConfig>>) -> Self {
        Self { level, json, bindings: HashMap::new(), transport }
    }

    pub fn child(&self, bindings: HashMap<String, String>) -> Self {
        let mut new_bindings = self.bindings.clone();
        new_bindings.extend(bindings);
        Self {
            level: self.level.clone(),
            json: self.json,
            bindings: new_bindings,
            transport: self.transport.clone(),
        }
    }

    pub fn apply(&self) -> Result<(), Box<dyn Error>> { self.apply_custom(None, false) }

    pub fn apply_custom(
        &self,
        custom_log: Option<String>,
        override_existing: bool,
    ) -> Result<(), Box<dyn Error>> {
        static INIT: std::sync::Once = std::sync::Once::new();
        let filter = LevelFilter::from(self.level.clone());
        CURRENT_LOGGER.with(|current| {
            *current.borrow_mut() = Some(self.clone());
        });

        let transports: Vec<Arc<Mutex<Box<dyn Transport>>>> = self
            .transport
            .as_ref()
            .map(|configs| {
                configs
                    .iter()
                    .map(|config| match &config.destination {
                        TransportDestination::Console => Ok(Arc::new(Mutex::new(Box::new(
                            ConsoleTransport::new(config.level.clone()),
                        )
                            as Box<dyn Transport>))),
                        TransportDestination::File { path, append } => {
                            FileTransport::new(path, *append, config.level.clone())
                                .map(|t| Arc::new(Mutex::new(Box::new(t) as Box<dyn Transport>)))
                        }
                        #[cfg(feature = "remote")]
                        TransportDestination::Remote { url } => {
                            RemoteTransport::new(url.clone(), config.level.clone())
                                .map(|t| Arc::new(Mutex::new(Box::new(t) as Box<dyn Transport>)))
                        } /* #[cfg(not(feature = "remote"))]
                           * TransportDestination::Remote { .. } => Err(io::Error::new(
                           *     io::ErrorKind::Other,
                           *     "Remote transport is not enabled",
                           * )), */
                    })
                    .collect::<io::Result<Vec<_>>>()
            })
            .transpose()?
            .unwrap_or_default();

        TRANSPORTS.with(|transport| {
            *transport.borrow_mut() = Some(transports.clone());
        });

        TRANSPORTS.with(|t| {
            *t.borrow_mut() = Some(transports.clone());
        });

        INIT.call_once(|| {
            if override_existing || env::var("RUST_LOG").is_err() {
                let log_value = custom_log.unwrap_or_else(|| self.level.to_string());
                env::set_var("RUST_LOG", log_value);
            }
            let mut builder = env_logger::Builder::from_env(
                env_logger::Env::default().default_filter_or(self.level.to_string()),
            );

            builder.format(move |buf, record: &Record| {
                CURRENT_LOGGER.with(|current| {
                    let logger = current.borrow();
                    let logger = logger
                        .as_ref()
                        .ok_or_else(|| io::Error::other("No logger set"))?;

                    TRANSPORTS.with(|transports| {
                        let transports = transports.borrow();
                        let transports = match transports.as_ref() {
                            Some(t) => t,
                            None => {
                                return Err(io::Error::other("No transports set"));
                            }
                        };

                        for transport in transports.iter() {
                            if let Ok(mut transport) = transport.lock() {
                                if let Err(e) = transport.send(record, logger) {
                                    eprintln!("Transport error: {e}");
                                }
                            }
                        }

                        Ok(())
                    })?;

                    if transports.is_empty() {
                        let level_str = match &logger.level {
                            #[cfg(feature = "custom_level")]
                            LogLevel::Custom(custom) => custom.name().to_string(),
                            _ => record.level().as_str().to_string(),
                        };
                        if logger.json {
                            #[cfg(feature = "json")]
                            {
                                let json_log = JsonLog {
                                    level: level_str,
                                    message: record.args().to_string(),
                                    timestamp: Utc::now().to_rfc3339(),
                                    bindings: logger.bindings.clone(),
                                };
                                let json_str =
                                    serde_json::to_string(&json_log).map_err(io::Error::other)?;
                                buf.write_all(json_str.as_bytes())?;
                                buf.write_all(b"\n")?;
                                Ok(())
                            }
                            #[cfg(not(feature = "json"))]
                            {
                                panic!("JSON output requires the `json` feature")
                            }
                        } else {
                            let timestamp = SystemTime::now()
                                .duration_since(SystemTime::UNIX_EPOCH)
                                .map(|d| d.as_secs())
                                .unwrap_or(0)
                                .to_string();
                            write!(buf, "[{timestamp}: {level_str}")?;
                            if !logger.bindings.is_empty() {
                                write!(buf, " {{")?;
                                let mut first = true;
                                for (key, value) in &logger.bindings {
                                    if !first {
                                        write!(buf, ", ")?;
                                    }
                                    write!(buf, "{key}={value}")?;
                                    first = false;
                                }
                                write!(buf, "}}")?;
                            }
                            write!(buf, " {}", record.args())?;
                            writeln!(buf)?;
                            Ok(())
                        }
                    } else {
                        Ok(())
                    }
                })
            });

            builder
                .filter_level(filter)
                .try_init()
                .map_err(|e| Box::new(e) as Box<dyn Error>)
                .expect("Failed to initialize logger")
        });

        Ok(())
    }
}

impl LogLevel {
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

    pub fn from_verbosity_flag_count(level: u8) -> Self {
        if level > 5 {
            log::warn!("Verbosity level {level} exceeds maximum; using Trace");
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
    /// use loglevel::{LogLevel, Logger};
    /// let (log_level, json, bindings) = LogLevel::from_args().expect("Failed to parse args");
    /// let logger = Logger::new(log_level, json, None);
    /// logger.apply().expect("Failed to initialize logger");
    /// ```
    pub fn from_args() -> Result<LogConfig, Box<dyn Error>> {
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
                    .value_name("NAME=VALUE")
                    .action(clap::ArgAction::Append)
                    .help("Custom log level (e.g., --custom-level http=10)"),
            )
            .arg(
                Arg::new("bindings")
                    .long("bindings")
                    .value_name("KEY=VALUE[,KEY=VALUE]")
                    .action(clap::ArgAction::Append)
                    .help("Logger bindings (e.g., --bindings module=http,service=api)"),
            )
            .get_matches();

        let verbosity = matches.get_count("verbose");
        let json = matches.get_flag("json");
        let mut bindings = HashMap::new();

        if let Some(bindings_values) = matches.get_many::<String>("bindings") {
            for value in bindings_values {
                for pair in value.split(',') {
                    let parts: Vec<&str> = pair.split('=').collect();
                    if parts.len() == 2 {
                        bindings.insert(parts[0].to_string(), parts[1].to_string());
                    } else {
                        return Err(
                            "Invalid bindings format, expected KEY=VALUE[,KEY=VALUE]".into()
                        );
                    }
                }
            }
        }

        #[cfg(feature = "custom_level")]
        if let Some(custom_levels) = matches.get_many::<String>("custom-level") {
            if let Some(custom) = custom_levels.clone().next_back() {
                let parts: Vec<&str> = custom.split('=').collect();
                if parts.len() == 2 {
                    let name = parts[0].to_string();
                    let value = parts[1].parse::<u8>()?;
                    return Ok((LogLevel::custom(name, value), json, bindings));
                } else {
                    return Err("Invalid custom log level format, expected NAME=VALUE".into());
                }
            }
        }

        Ok((Self::from_verbosity_flag_count(verbosity), json, bindings))
    }

    pub fn apply_custom(
        &self,
        custom_log: Option<String>,
        override_existing: bool,
        json: bool,
    ) -> Result<(), Box<dyn Error>> {
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
                            bindings: HashMap::new(),
                        };
                        let json_str = serde_json::to_string(&json_log)?;
                        buf.write_all(json_str.as_bytes())?;
                        buf.write_all(b"\n")?;
                        Ok(())
                    });
                }
                #[cfg(not(feature = "json"))]
                {
                    panic!("JSON output requires the `json` feature")
                }
            }

            builder
                .filter_level(filter)
                .try_init()
                .expect("Failed to initialize logger");
        });

        Ok(())
    }

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
    }

    #[test]
    #[cfg(feature = "custom_level")]
    fn test_custom_level() {
        LogLevel::Custom(CustomLogLevel::new("http".to_string(), 10))
            .apply_custom(None, false, false)
            .expect("Failed to initialize logger");
        log::info!("This is a custom log");
    }

    #[test]
    #[cfg(all(feature = "custom_level", feature = "json"))]
    fn test_custom_level_json() {
        LogLevel::Custom(CustomLogLevel::new("http".to_string(), 10))
            .apply_custom(None, false, true)
            .expect("Failed to initialize logger");
        log::info!("This is a custom JSON log");
    }

    #[test]
    fn test_logger() {
        let logger = Logger::new(LogLevel::Info, false, None);
        logger.apply().expect("Failed to initialize logger");
        log::info!("Parent log");
        let child = logger.child(HashMap::from([("module".to_string(), "child".to_string())]));
        child.apply().expect("Failed to initialize child logger");
        log::info!("Child log");
    }

    #[test]
    #[cfg(feature = "json")]
    fn test_logger_json() {
        let logger = Logger::new(LogLevel::Info, true, None);
        logger.apply().expect("Failed to initialize logger");
        log::info!("Parent JSON log");
        let child = logger.child(HashMap::from([("module".to_string(), "child".to_string())]));
        child.apply().expect("Failed to initialize child logger");
        log::info!("Child JSON log");
    }
}
