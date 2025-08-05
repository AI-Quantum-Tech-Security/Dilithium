#![allow(dead_code)]

use chrono::Utc;
use std::sync::Mutex;
use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct AuditEvent {
    pub event_type: AuditEventType,
    pub key_id: String,
    pub user: String,
    pub timestamp: i64,
    pub success: bool,
    pub details: Option<String>,
}

#[derive(Clone, Debug)]
pub enum AuditEventType {
    KeyCreation,
    KeyAccess,
    KeyRotation,
    KeyDeletion,
}

pub struct AuditLog {
    events: Mutex<Vec<AuditEvent>>,
    key_history: Mutex<HashMap<String, Vec<AuditEvent>>>,
}

impl AuditLog {
    pub fn new() -> Self {
        AuditLog {
            events: Mutex::new(Vec::new()),
            key_history: Mutex::new(HashMap::new()),
        }
    }

    pub fn record(
        &self,
        event_type: AuditEventType,
        key_id: String,
        user: String,
        success: bool,
        details: Option<String>,
    ) -> Result<(), String> {
        let event = AuditEvent {
            event_type,
            key_id: key_id.clone(),
            user,
            timestamp: Utc::now().timestamp(),
            success,
            details,
        };

        // Record in main events log
        self.events
            .lock()
            .map_err(|e| format!("Failed to lock events: {}", e))?
            .push(event.clone());

        // Record in key history
        let mut history = self.key_history
            .lock()
            .map_err(|e| format!("Failed to lock key history: {}", e))?;

        history
            .entry(key_id)
            .or_insert_with(Vec::new)
            .push(event);

        Ok(())
    }

    pub fn get_key_history(&self, key_id: &str) -> Result<Vec<AuditEvent>, String> {
        let history = self.key_history
            .lock()
            .map_err(|e| format!("Failed to lock key history: {}", e))?;

        Ok(history.get(key_id).cloned().unwrap_or_default())
    }

    pub fn get_failed_attempts(&self) -> Result<Vec<AuditEvent>, String> {
        let events = self.events
            .lock()
            .map_err(|e| format!("Failed to lock events: {}", e))?;

        Ok(events
            .iter()
            .filter(|event| !event.success)
            .cloned()
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_logging() {
        let audit_log = AuditLog::new();
        let key_id = "test-key";
        let user = "test-user";

        // Test event recording
        assert!(audit_log.record(
            AuditEventType::KeyCreation,
            key_id.to_string(),
            user.to_string(),
            true,
            None
        ).is_ok());

        // Test key history retrieval
        let history = audit_log.get_key_history(key_id).unwrap();
        assert_eq!(history.len(), 1);
        assert!(history[0].success);

        // Test failed attempts
        assert!(audit_log.record(
            AuditEventType::KeyAccess,
            key_id.to_string(),
            user.to_string(),
            false,
            Some("Access denied".to_string())
        ).is_ok());

        let failed = audit_log.get_failed_attempts().unwrap();
        assert_eq!(failed.len(), 1);
        assert!(!failed[0].success);
    }
}