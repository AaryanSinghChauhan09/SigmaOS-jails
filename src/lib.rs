#![forbid(unsafe_code)]
//! SigmaOS Jails — lightweight process, filesystem, and capability isolation.

use std::collections::{BTreeSet, HashMap};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors returned by jail registry and lifecycle operations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum JailError {
    #[error("invalid jail id: {0}")]
    InvalidId(String),
    #[error("invalid rootfs path: {0}")]
    InvalidRootfs(String),
    #[error("duplicate jail id: {0}")]
    Duplicate(String),
    #[error("jail not found: {0}")]
    NotFound(String),
    #[error("jail {0} is already running")]
    AlreadyRunning(String),
    #[error("jail {0} is not running")]
    NotRunning(String),
    #[error("cannot remove running jail: {0}")]
    RemoveWhileRunning(String),
    #[error("invalid resource limit: {0}")]
    InvalidLimit(&'static str),
}

/// Network isolation mode for a jail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkMode {
    None,
    LoopbackOnly,
    Bridged { interface: String },
}

/// Resource ceilings enforced on a jail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub memory_mb: u64,
    pub max_pids: u32,
    pub cpu_shares: u32,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            memory_mb: 512,
            max_pids: 128,
            cpu_shares: 1024,
        }
    }
}

/// Runtime state of a jail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum JailState {
    Stopped,
    Running { pid_root: u32 },
}

/// Declarative specification + state of a SigmaOS jail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jail {
    pub id: String,
    pub rootfs: String,
    pub read_only_root: bool,
    pub network: NetworkMode,
    pub capabilities: BTreeSet<String>,
    pub limits: ResourceLimits,
    pub state: JailState,
}

impl Jail {
    /// Construct a new least-privilege jail specification (network=None, read_only_root=true).
    pub fn new(id: impl Into<String>, rootfs: impl Into<String>) -> Result<Self, JailError> {
        let id = id.into();
        let rootfs = rootfs.into();
        if id.trim().is_empty() || id.contains('/') || id.contains("..") {
            return Err(JailError::InvalidId(id));
        }
        if !rootfs.starts_with('/') || rootfs.contains("..") {
            return Err(JailError::InvalidRootfs(rootfs));
        }
        Ok(Self {
            id,
            rootfs,
            read_only_root: true,
            network: NetworkMode::None,
            capabilities: BTreeSet::new(),
            limits: ResourceLimits::default(),
            state: JailState::Stopped,
        })
    }

    /// Grant a capability (e.g. `NET_BIND_SERVICE`) to this jail.
    pub fn allow_capability(&mut self, cap: impl Into<String>) {
        self.capabilities.insert(cap.into());
    }

    /// Set resource limits after validating non-zero bounds.
    pub fn set_limits(&mut self, limits: ResourceLimits) -> Result<(), JailError> {
        if limits.memory_mb == 0 {
            return Err(JailError::InvalidLimit("memory_mb must be > 0"));
        }
        if limits.max_pids == 0 {
            return Err(JailError::InvalidLimit("max_pids must be > 0"));
        }
        if limits.cpu_shares == 0 {
            return Err(JailError::InvalidLimit("cpu_shares must be > 0"));
        }
        self.limits = limits;
        Ok(())
    }
}

/// In-memory registry managing SigmaOS jails.
#[derive(Debug, Default)]
pub struct JailRegistry {
    jails: HashMap<String, Jail>,
}

impl JailRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, jail: Jail) -> Result<(), JailError> {
        if self.jails.contains_key(&jail.id) {
            return Err(JailError::Duplicate(jail.id));
        }
        self.jails.insert(jail.id.clone(), jail);
        Ok(())
    }

    pub fn get(&self, id: &str) -> Option<&Jail> {
        self.jails.get(id)
    }

    pub fn start(&mut self, id: &str, pid_root: u32) -> Result<(), JailError> {
        let jail = self
            .jails
            .get_mut(id)
            .ok_or_else(|| JailError::NotFound(id.to_string()))?;
        if matches!(jail.state, JailState::Running { .. }) {
            return Err(JailError::AlreadyRunning(id.to_string()));
        }
        jail.state = JailState::Running { pid_root };
        Ok(())
    }

    pub fn stop(&mut self, id: &str) -> Result<(), JailError> {
        let jail = self
            .jails
            .get_mut(id)
            .ok_or_else(|| JailError::NotFound(id.to_string()))?;
        if !matches!(jail.state, JailState::Running { .. }) {
            return Err(JailError::NotRunning(id.to_string()));
        }
        jail.state = JailState::Stopped;
        Ok(())
    }

    pub fn remove(&mut self, id: &str) -> Result<Jail, JailError> {
        let is_running = self
            .jails
            .get(id)
            .map(|j| matches!(j.state, JailState::Running { .. }))
            .ok_or_else(|| JailError::NotFound(id.to_string()))?;
        if is_running {
            return Err(JailError::RemoveWhileRunning(id.to_string()));
        }
        Ok(self.jails.remove(id).expect("checked existence above"))
    }

    pub fn list(&self) -> Vec<&Jail> {
        let mut out: Vec<&Jail> = self.jails.values().collect();
        out.sort_by(|a, b| a.id.cmp(&b.id));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jail_defaults_least_privilege_aaa() {
        // Arrange & Act
        let jail = Jail::new("web-sandbox", "/var/lib/sigma/jails/web").unwrap();
        // Assert
        assert!(jail.read_only_root);
        assert_eq!(jail.network, NetworkMode::None);
        assert!(jail.capabilities.is_empty());
        assert_eq!(jail.state, JailState::Stopped);
    }

    #[test]
    fn test_jail_rejects_traversal_and_relative_rootfs_aaa() {
        // Arrange & Act
        let bad_id = Jail::new("../escape", "/var/lib/sigma/jails/a");
        let bad_root = Jail::new("ok", "relative/path");
        // Assert
        assert!(matches!(bad_id, Err(JailError::InvalidId(_))));
        assert!(matches!(bad_root, Err(JailError::InvalidRootfs(_))));
    }

    #[test]
    fn test_jail_lifecycle_start_stop_remove_aaa() {
        // Arrange
        let mut reg = JailRegistry::new();
        reg.register(Jail::new("db-jail", "/var/lib/sigma/jails/db").unwrap())
            .unwrap();
        // Act
        reg.start("db-jail", 4200).unwrap();
        let running_remove = reg.remove("db-jail");
        reg.stop("db-jail").unwrap();
        let removed = reg.remove("db-jail").unwrap();
        // Assert
        assert!(matches!(running_remove, Err(JailError::RemoveWhileRunning(_))));
        assert_eq!(removed.id, "db-jail");
        assert!(reg.get("db-jail").is_none());
    }

    #[test]
    fn test_jail_zero_resource_limits_rejected_aaa() {
        // Arrange
        let mut jail = Jail::new("worker", "/var/lib/sigma/jails/worker").unwrap();
        let bad_limits = ResourceLimits {
            memory_mb: 0,
            max_pids: 16,
            cpu_shares: 512,
        };
        // Act
        let res = jail.set_limits(bad_limits);
        // Assert
        assert!(matches!(res, Err(JailError::InvalidLimit(_))));
    }

    #[test]
    fn test_jail_duplicate_registration_rejected_aaa() {
        // Arrange
        let mut reg = JailRegistry::new();
        reg.register(Jail::new("app", "/var/lib/sigma/jails/app").unwrap())
            .unwrap();
        // Act
        let res = reg.register(Jail::new("app", "/var/lib/sigma/jails/app2").unwrap());
        // Assert
        assert!(matches!(res, Err(JailError::Duplicate(_))));
    }
}
