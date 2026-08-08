use std::{
    env, fmt,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

use iroh_relay::server::{Access, AccessControl, ClientRequest};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

pub const TOKEN_ENV: &str = "UC_RELAY_TOKEN";
pub const MIN_TOKEN_LENGTH: usize = 32;
pub const MAX_TOKEN_LENGTH: usize = 512;

#[derive(Clone)]
pub struct TokenAccess {
    token_digest: [u8; 32],
}

impl TokenAccess {
    /// Creates access control for one relay token.
    ///
    /// # Errors
    ///
    /// Returns [`TokenError`] when the token cannot be transported safely or does not meet the
    /// minimum strength requirement.
    pub fn new(token: String) -> Result<Self, TokenError> {
        let token = Zeroizing::new(token);
        validate_token(&token)?;
        Ok(Self {
            token_digest: *blake3::hash(token.as_bytes()).as_bytes(),
        })
    }

    /// Checks a candidate token without exposing the configured token.
    #[must_use]
    pub fn allows(&self, token: &str) -> bool {
        if validate_token(token).is_err() {
            return false;
        }
        let candidate = blake3::hash(token.as_bytes());
        constant_time_eq::constant_time_eq(&self.token_digest, candidate.as_bytes())
    }
}

impl fmt::Debug for TokenAccess {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TokenAccess")
            .field("token", &"[REDACTED]")
            .finish()
    }
}

impl AccessControl for TokenAccess {
    async fn on_connect(&self, request: &ClientRequest) -> Access {
        let Some(mut token) = request.auth_token() else {
            return Access::Deny { reason: None };
        };
        let allowed = self.allows(&token);
        token.zeroize();
        if allowed {
            Access::Allow
        } else {
            Access::Deny { reason: None }
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TokenError {
    #[error("access token must contain at least {MIN_TOKEN_LENGTH} characters")]
    TooShort,
    #[error("access token must contain at most {MAX_TOKEN_LENGTH} characters")]
    TooLong,
    #[error("access token must contain only visible ASCII characters")]
    InvalidCharacter,
}

#[derive(Debug, Error)]
pub enum AccessLoadError {
    #[error("no access token configured; set --token-file or {TOKEN_ENV}")]
    Missing,
    #[error("unauthenticated relay mode requires a loopback bind address")]
    UnauthenticatedRequiresLoopback,
    #[error("failed to open access token file {path}")]
    Open {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("access token path is not a regular file: {0}")]
    NotFile(PathBuf),
    #[cfg(unix)]
    #[error("access token file permissions are too broad: {path}; run chmod 600 {path}")]
    InsecurePermissions { path: PathBuf },
    #[error("failed to read access token file {path}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("{TOKEN_ENV} is not valid Unicode")]
    InvalidEnvironment,
    #[error(transparent)]
    InvalidToken(#[from] TokenError),
}

/// Loads access control from an owner-only token file or [`TOKEN_ENV`].
///
/// The file takes precedence when one is supplied.
///
/// # Errors
///
/// Returns [`AccessLoadError`] when no token is configured, the credential file cannot be read
/// securely, or the token is invalid.
pub fn load_access(token_file: Option<&Path>) -> Result<TokenAccess, AccessLoadError> {
    let token = match token_file {
        Some(path) => read_token_file(path)?,
        None => match env::var(TOKEN_ENV) {
            Ok(token) => token,
            Err(env::VarError::NotPresent) => return Err(AccessLoadError::Missing),
            Err(env::VarError::NotUnicode(_)) => return Err(AccessLoadError::InvalidEnvironment),
        },
    };
    TokenAccess::new(token).map_err(Into::into)
}

fn read_token_file(path: &Path) -> Result<String, AccessLoadError> {
    let mut file = File::open(path).map_err(|source| AccessLoadError::Open {
        path: path.to_path_buf(),
        source,
    })?;
    let metadata = file.metadata().map_err(|source| AccessLoadError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(AccessLoadError::NotFile(path.to_path_buf()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(AccessLoadError::InsecurePermissions {
                path: path.to_path_buf(),
            });
        }
    }

    let mut token = String::new();
    file.read_to_string(&mut token)
        .map_err(|source| AccessLoadError::Read {
            path: path.to_path_buf(),
            source,
        })?;
    let trimmed_length = token.trim_end_matches(['\r', '\n']).len();
    token.truncate(trimmed_length);
    Ok(token)
}

fn validate_token(token: &str) -> Result<(), TokenError> {
    if token.len() < MIN_TOKEN_LENGTH {
        return Err(TokenError::TooShort);
    }
    if token.len() > MAX_TOKEN_LENGTH {
        return Err(TokenError::TooLong);
    }
    if !token.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
        return Err(TokenError::InvalidCharacter);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::NamedTempFile;

    use super::*;

    const TOKEN: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn keeps_only_a_digest_and_redacts_debug_output() {
        let access = TokenAccess::new(TOKEN.to_owned()).expect("valid token");
        assert!(access.allows(TOKEN));
        assert!(!access.allows("fedcba9876543210fedcba9876543210"));
        let debug = format!("{access:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(TOKEN));
    }

    #[test]
    fn rejects_tokens_that_cannot_be_sent_safely() {
        assert_eq!(
            TokenAccess::new("short".to_owned()).unwrap_err(),
            TokenError::TooShort
        );
        assert_eq!(
            TokenAccess::new(format!("{}\n", "x".repeat(32))).unwrap_err(),
            TokenError::InvalidCharacter
        );
        assert_eq!(
            TokenAccess::new("x".repeat(MAX_TOKEN_LENGTH + 1)).unwrap_err(),
            TokenError::TooLong
        );
    }

    #[test]
    fn reads_an_owner_only_token_file_and_ignores_its_final_newline() {
        let mut file = NamedTempFile::new().expect("temporary file");
        writeln!(file, "{TOKEN}").expect("write token");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.as_file()
                .set_permissions(std::fs::Permissions::from_mode(0o600))
                .expect("secure permissions");
        }
        let access = load_access(Some(file.path())).expect("load token");
        assert!(access.allows(TOKEN));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_a_token_file_readable_by_other_users() {
        use std::os::unix::fs::PermissionsExt;

        let mut file = NamedTempFile::new().expect("temporary file");
        write!(file, "{TOKEN}").expect("write token");
        file.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o644))
            .expect("set permissions");
        assert!(matches!(
            load_access(Some(file.path())),
            Err(AccessLoadError::InsecurePermissions { .. })
        ));
    }
}
