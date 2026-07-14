use std::fmt;

use napi::{Error, Status};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ScannerError {
    pub kind: &'static str,
    pub code: &'static str,
    pub operation: &'static str,
    pub errno: Option<i32>,
    pub message: String,
}

impl ScannerError {
    pub(crate) fn invalid(operation: &'static str, message: impl Into<String>) -> Self {
        Self {
            kind: "invalidPlan",
            code: "ERR_INVALID_SCAN_PLAN",
            operation,
            errno: None,
            message: message.into(),
        }
    }

    pub(crate) fn resource(operation: &'static str, message: impl Into<String>) -> Self {
        Self {
            kind: "resourceLimit",
            code: "ERR_RESOURCE_LIMIT",
            operation,
            errno: None,
            message: message.into(),
        }
    }

    pub(crate) fn lifecycle(operation: &'static str, message: impl Into<String>) -> Self {
        Self {
            kind: "lifecycle",
            code: "ERR_INVALID_STATE",
            operation,
            errno: None,
            message: message.into(),
        }
    }

    pub(crate) fn environment_closed(operation: &'static str) -> Self {
        Self {
            kind: "environmentClosed",
            code: "ERR_ENVIRONMENT_CLOSED",
            operation,
            errno: None,
            message: "the Node environment is closing".into(),
        }
    }

    pub(crate) fn system(operation: &'static str, error: impl Into<nix::errno::Errno>) -> Self {
        let errno = error.into();
        let number = errno as i32;
        let permission = matches!(errno, nix::errno::Errno::EPERM | nix::errno::Errno::EACCES);
        Self {
            kind: if permission { "permission" } else { "io" },
            code: if permission {
                "ERR_PERMISSION"
            } else {
                "ERR_SYSTEM"
            },
            operation,
            errno: Some(number),
            message: format!("{operation} failed: {errno}"),
        }
    }

    pub(crate) fn system_rustix(operation: &'static str, errno: rustix::io::Errno) -> Self {
        let number = errno.raw_os_error();
        let permission = matches!(number, libc_permission::EPERM | libc_permission::EACCES);
        Self {
            kind: if permission { "permission" } else { "io" },
            code: if permission {
                "ERR_PERMISSION"
            } else {
                "ERR_SYSTEM"
            },
            operation,
            errno: Some(number),
            message: format!("{operation} failed: errno {number}"),
        }
    }

    pub(crate) fn context(operation: &'static str, message: impl Into<String>) -> Self {
        Self {
            kind: "context",
            code: "ERR_NETWORK_CONTEXT",
            operation,
            errno: None,
            message: message.into(),
        }
    }

    pub(crate) fn unsupported(operation: &'static str, message: impl Into<String>) -> Self {
        Self {
            kind: "unsupported",
            code: "ERR_UNSUPPORTED_ROUTE",
            operation,
            errno: None,
            message: message.into(),
        }
    }

    pub(crate) fn internal(operation: &'static str, message: impl Into<String>) -> Self {
        Self {
            kind: "internal",
            code: "ERR_SCANNER_INTERNAL",
            operation,
            errno: None,
            message: message.into(),
        }
    }

    pub(crate) fn into_napi(self) -> Error {
        let errno = self
            .errno
            .map_or_else(String::new, |value| value.to_string());
        let message = self.message.replace(['|', '\n', '\r'], " ");
        Error::new(
            Status::GenericFailure,
            format!(
                "NODENET_SCANNER|{}|{}|{}|{errno}|{message}",
                self.kind, self.code, self.operation
            ),
        )
    }
}

mod libc_permission {
    pub const EPERM: i32 = 1;
    pub const EACCES: i32 = 13;
}

impl fmt::Display for ScannerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ScannerError {}

impl From<nodenetscanner_engine::EngineError> for ScannerError {
    fn from(value: nodenetscanner_engine::EngineError) -> Self {
        Self::invalid("validate scan plan", value.to_string())
    }
}

impl From<nodenet_protocols::BuildError> for ScannerError {
    fn from(value: nodenet_protocols::BuildError) -> Self {
        Self::invalid("build probe packet", value.to_string())
    }
}
