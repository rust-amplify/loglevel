// SPDX-License-Identifier: Apache-2.0

//! Simple way to set your log level

#[macro_use]
extern crate amplify;

use std::env;

use log::LevelFilter;

/// Represents desired logging verbosity level
#[derive(Copy, Clone, PartialEq, Eq, Debug, Display)]
pub enum LogLevel {
    /// Do not log anything. Corresponds to zero verbosity flags.
    #[display("none")]
    None = 0,

    /// Report only errors to `stderr` and normal program output to stdin (if it is not directed to
    /// a file). Corresponds to a single `-v` verbosity flag.
    #[display("error")]
    Error,

    /// Report warning messages and errors, plus standard program output. Corresponds to a double
    /// `-vv` verbosity flag.
    #[display("warn")]
    Warn,

    /// Report genetic information messages, warnings and errors. Corresponds to a triple `-vvv`
    /// verbosity flag.
    #[display("info")]
    Info,

    /// Report debugging information and all non-trace messages, including general information,
    /// warnings and errors. Corresponds to quadruple `-vvvv` verbosity flag.
    #[display("debug")]
    Debug,

    /// Print all possible messages including tracing information. Corresponds to five `-vvvvv`
    /// verbosity flags.
    #[display("trace")]
    Trace,
}

impl From<u8> for LogLevel {
    fn from(val: u8) -> Self { Self::from_verbosity_flag_count(val) }
}

impl From<LogLevel> for u8 {
    fn from(log_level: LogLevel) -> Self { log_level.verbosity_flag_count() }
}

impl LogLevel {
    /// Indicates number of required verbosity flags
    pub fn verbosity_flag_count(&self) -> u8 { *self as u8 }

    /// Constructs enum value from a given number of verbosity flags
    pub fn from_verbosity_flag_count(level: u8) -> Self {
        match level {
            0 => LogLevel::None,
            1 => LogLevel::Error,
            2 => LogLevel::Warn,
            3 => LogLevel::Info,
            4 => LogLevel::Debug,
            _ => LogLevel::Trace,
        }
    }

    /// Applies log level to the system
    pub fn apply(&self) {
        log::set_max_level(LevelFilter::Trace);
        if env::var("RUST_LOG").is_err() {
            env::set_var("RUST_LOG", self.to_string());
        }
        env_logger::init();
    }
}
