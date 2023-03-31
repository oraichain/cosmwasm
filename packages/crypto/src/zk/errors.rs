#[cfg(feature = "backtraces")]
use std::backtrace::Backtrace;
use std::fmt::Debug;
use thiserror::Error;

pub type ZKResult<T> = core::result::Result<T, ZKError>;

#[derive(Error, Debug)]
pub enum ZKError {
    #[error("ZK verification error")]
    VerifierError {
        #[cfg(feature = "backtraces")]
        backtrace: Backtrace,
    },

    #[error("Curve is unimplemented")]
    Unimplemented {},

    #[error("ZK error: {msg}")]
    GenericErr {
        msg: String,
        #[cfg(feature = "backtraces")]
        backtrace: Backtrace,
    },
}

impl ZKError {
    pub fn generic_err(msg: impl Into<String>) -> Self {
        ZKError::GenericErr {
            msg: msg.into(),
            #[cfg(feature = "backtraces")]
            backtrace: Backtrace::capture(),
        }
    }

    /// Numeric error code that can easily be passed over the
    /// contract VM boundary.
    pub fn code(&self) -> u32 {
        match self {
            ZKError::VerifierError { .. } => 3,
            ZKError::Unimplemented { .. } => 4,
            ZKError::GenericErr { .. } => 10,
        }
    }
}
