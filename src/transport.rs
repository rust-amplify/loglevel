// SPDX-License-Identifier: Apache-2.0

use std::fmt::Write as FmtWrite;
use std::io::{self, Write as IoWrite};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::SystemTime;

#[cfg(feature = "json")]
use chrono::Utc;
use crossbeam_channel::{Receiver, Sender, bounded};
use log::{Level, Record};
#[cfg(feature = "json")]
use serde::Serialize;

use crate::{LogLevel, Logger};

#[cfg(feature = "json")]
#[derive(Serialize)]
pub struct JsonLog {
    level: String,
    message: String,
    timestamp: String,
    #[serde(skip_serializing_if = "std::collections::HashMap::is_empty")]
    bindings: std::collections::HashMap<String, String>,
}

#[derive(Clone)]
pub enum TransportDestination {
    Console,
    File {
        path: String,
        append: bool,
    },
    #[cfg(feature = "remote")]
    Remote {
        url: String,
    },
}

#[derive(Clone)]
pub struct TransportConfig {
    pub destination: TransportDestination,
    pub level: LogLevel,
}

pub trait Transport: Send + 'static {
    fn send(&mut self, record: &Record, logger: &Logger) -> io::Result<()>;
}

pub struct ConsoleTransport {
    sender: Sender<String>,
    level: LogLevel,
}

pub struct FileTransport {
    file: Arc<Mutex<std::fs::File>>,
    sender: Sender<String>,
    level: LogLevel,
}

#[cfg(feature = "remote")]
pub struct RemoteTransport {
    client: reqwest::blocking::Client,
    url: String,
    sender: Sender<String>,
    level: LogLevel,
}

fn is_level_enabled(record_level: Level, transport_level: LogLevel) -> bool {
    let record_level = match record_level {
        Level::Error => 1,
        Level::Warn => 2,
        Level::Info => 3,
        Level::Debug => 4,
        Level::Trace => 5,
    };

    let transport_value = match transport_level {
        LogLevel::None => 0,
        LogLevel::Error => 1,
        LogLevel::Warn => 2,
        LogLevel::Info => 3,
        LogLevel::Debug => 4,
        LogLevel::Trace => 5,
        #[cfg(feature = "custom_level")]
        LogLevel::Custom(custom) => custom.value,
    };

    record_level <= transport_value
}

impl ConsoleTransport {
    pub fn new(level: LogLevel) -> Self {
        let (sender, receiver): (Sender<String>, Receiver<String>) = bounded(100);
        thread::spawn(move || {
            while let Ok(message) = receiver.recv() {
                println!("{message}");
            }
        });
        Self { sender, level }
    }
}

impl FileTransport {
    pub fn new(path: &str, append: bool, level: LogLevel) -> io::Result<Self> {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .append(append)
            .open(path)?;
        let (sender, receiver): (Sender<String>, Receiver<String>) = bounded(100);
        let file = Arc::new(Mutex::new(file));
        let file_writer = file.clone();
        thread::spawn(move || {
            while let Ok(message) = receiver.recv() {
                if let Ok(mut file_guard) = file_writer.lock() {
                    if let Err(e) = file_guard.write_all(message.as_bytes()) {
                        eprintln!("FileTransport error: {e}");
                    }
                    if let Err(e) = file_guard.write_all(b"\n") {
                        eprintln!("FileTransport error: {e}");
                    }
                    if let Err(e) = file_guard.flush() {
                        eprintln!("FileTransport flush error: {e}");
                    }
                }
            }
        });
        Ok(Self { file, sender, level })
    }
}

#[cfg(feature = "remote")]
impl RemoteTransport {
    pub fn new(url: String, level: LogLevel) -> io::Result<Self> {
        let (sender, receiver): (Sender<String>, Receiver<String>) = bounded(100);
        let url_clone = url.clone();
        thread::spawn(move || {
            let client = reqwest::blocking::Client::new();
            while let Ok(message) = receiver.recv() {
                if let Err(e) = client.post(&url_clone).body(message).send() {
                    eprintln!("RemoteTransport error: {}", e);
                }
            }
        });

        let client = reqwest::blocking::Client::new();

        Ok(Self { url, sender, level, client })
    }
}

impl Transport for ConsoleTransport {
    fn send(&mut self, record: &Record, logger: &Logger) -> io::Result<()> {
        if is_level_enabled(record.level(), self.level.clone()) {
            let message = format_log(record, logger)?;
            self.sender.send(message).map_err(|e| io::Error::other(e))?;
        }
        Ok(())
    }
}

impl Transport for FileTransport {
    fn send(&mut self, record: &Record, logger: &Logger) -> io::Result<()> {
        if is_level_enabled(record.level(), self.level.clone()) {
            let message = format_log(record, logger)?;
            self.sender.send(message).map_err(|e| io::Error::other(e))?;
        }
        Ok(())
    }
}

#[cfg(feature = "remote")]
impl Transport for RemoteTransport {
    fn send(&mut self, record: &Record, logger: &Logger) -> io::Result<()> {
        if is_level_enabled(record.level(), self.level.clone()) {
            let message = format_log(record, logger)?;
            self.sender
                .send(message)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        }
        Ok(())
    }
}

pub fn format_log(record: &Record, logger: &Logger) -> io::Result<String> {
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
            let json_str = serde_json::to_string(&json_log)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            Ok(json_str)
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
        let mut output = String::new();
        write!(output, "[{timestamp}: {level_str}").map_err(|e| io::Error::other(e))?;
        if !logger.bindings.is_empty() {
            write!(output, " {{").map_err(|e| io::Error::other(e))?;
            let mut first = true;
            for (key, value) in &logger.bindings {
                if !first {
                    write!(output, ", ").map_err(|e| io::Error::other(e))?;
                }
                write!(output, "{key}={value}").map_err(|e| io::Error::other(e))?;
                first = false;
            }
            write!(output, "}}").map_err(|e| io::Error::other(e))?;
        }
        write!(output, "{}", record.args()).map_err(|e| io::Error::other(e))?;
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use super::*;

    #[test]
    fn test_console_transport() {
        let transports = vec![TransportConfig {
            destination: TransportDestination::Console,
            level: LogLevel::Info,
        }];
        let logger = Logger::new(LogLevel::Info, false, Some(transports));
        logger.apply().expect("Failed to initialize logger");
        log::info!("Console log");
        std::thread::sleep(std::time::Duration::from_millis(100)); // Allow console write
    }

    #[test]
    fn test_file_transport() {
        let transports = vec![TransportConfig {
            destination: TransportDestination::File { path: "test.log".to_string(), append: false },
            level: LogLevel::Info,
        }];
        let logger = Logger::new(LogLevel::Info, false, Some(transports));
        logger.apply().expect("Failed to initialize logger");
        log::info!("File log");
        std::thread::sleep(std::time::Duration::from_millis(100)); // Allow file write

        assert!(Path::new("test.log").exists());
        let contents = fs::read_to_string("test.log").expect("Failed to read log file");
        assert!(contents.contains("File log"));
        fs::remove_file("test.log").expect("Failed to clean up test log file");
    }

    #[test]
    #[cfg(feature = "json")]
    fn test_file_transport_json() {
        let transports = vec![TransportConfig {
            destination: TransportDestination::File {
                path: "test_json.log".to_string(),
                append: false,
            },
            level: LogLevel::Info,
        }];
        let logger = Logger::new(LogLevel::Info, true, Some(transports));
        logger.apply().expect("Failed to initialize logger");
        log::info!("File JSON log");
        std::thread::sleep(std::time::Duration::from_millis(100)); // Allow file write

        assert!(Path::new("test_json.log").exists());
        let contents = fs::read_to_string("test_json.log").expect("Failed to read log file");
        assert!(contents.contains("File JSON log"));
        fs::remove_file("test_json.log").expect("Failed to clean up test JSON log file");
    }

    #[test]
    #[cfg(feature = "remote")]
    fn test_remote_transport() {
        let transports = vec![TransportConfig {
            destination: TransportDestination::Remote { url: "http://localhost:8080".to_string() },
            level: LogLevel::Info,
        }];
        let logger = Logger::new(LogLevel::Info, true, Some(transports));
        logger.apply().expect("Failed to initialize logger");
        log::info!("Remote log");
        std::thread::sleep(std::time::Duration::from_millis(100)); // Allow remote send
    }
}
