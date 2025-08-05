#![allow(dead_code)]
use chrono::Utc;
use std::sync::{ Mutex};
use std::collections::HashMap;
use log::{info, error};
use serde::{Serialize, Deserialize};
use crate::kms::store::KeyStore;


const ROTATION_INTERVAL_DAYS: i64 = 30;
const MIN_ENTROPY_THRESHOLD: f64 = 7.5;

#[derive(Debug, Serialize, Deserialize)]
pub struct RotationPolicy {
    pub max_age_days: u32,
    pub force_rotation: bool,
    pub require_backup: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RotationResult {
    pub key_id: String,
    pub rotation_time: i64,
    pub success: bool,
    pub entropy_score: f64,
    pub rotated_by: String,
    pub new_version: u32,
}

pub struct KeyRotator {
    store: KeyStore,
    last_rotation: Mutex<HashMap<String, i64>>,
}

impl KeyRotator {
    pub fn new(store: KeyStore) -> Self {
        KeyRotator {
            store,
            last_rotation: Mutex::new(HashMap::new()),
        }
    }

    pub fn rotate_key(&self, key_id: &str, user: String,
                      force: bool) -> Result<RotationResult, String> {
        let now = Utc::now().timestamp();
        let mut last_rotation = self.last_rotation.lock()
            .map_err(|e| format!("Failed to lock rotation times: {}", e))?;

        // Check if rotation is needed
        if !force {
            if let Some(last_time) = last_rotation.get(key_id) {
                let days_since_rotation = (now - last_time) / (24 * 3600);
                if days_since_rotation < ROTATION_INTERVAL_DAYS {
                    return Err(format!("Key rotation not yet due. Days remaining: {}",
                                       ROTATION_INTERVAL_DAYS - days_since_rotation));
                }
            }
        }

        info!("Rotating key {} requested by {}", key_id, user);

        // Generate new key
        let mut new_key = vec![0u8; 32];
        getrandom::getrandom(&mut new_key)
            .map_err(|e| {
                error!("Failed to generate random data: {}", e);
                format!("Failed to generate random data: {}", e)
            })?;

        // Calculate entropy
        let entropy_score = self.calculate_entropy(&new_key);
        if entropy_score < MIN_ENTROPY_THRESHOLD {
            let err = format!("Insufficient entropy in generated key: {:.2}", entropy_score);
            error!("{}", err);
            return Err(err);
        }

        // Update key with versioning
        self.store.update_key(key_id, new_key, entropy_score, user.clone())?;

        // Update rotation time
        last_rotation.insert(key_id.to_string(), now);

        let result = RotationResult {
            key_id: key_id.to_string(),
            rotation_time: now,
            success: true,
            entropy_score,
            rotated_by: user,
            new_version: self.store.list_keys()?
                .into_iter()
                .find(|(k, _)| k == key_id)
                .map(|(_, meta)| meta.version)
                .unwrap_or(1),
        };

        info!("Successfully rotated key {} (version {})", key_id, result.new_version);
        Ok(result)
    }

    fn calculate_entropy(&self, data: &[u8]) -> f64 {
        let mut frequency = [0u32; 256];
        for &byte in data {
            frequency[byte as usize] += 1;
        }

        let len = data.len() as f64;
        let mut entropy = 0.0;

        for &count in &frequency {
            if count > 0 {
                let probability = count as f64 / len;
                entropy -= probability * probability.log2();
            }
        }

        entropy
    }

    pub fn check_rotation_status(&self, key_id: &str) -> Result<Option<i64>, String> {
        let last_rotation = self.last_rotation.lock()
            .map_err(|e| format!("Failed to lock rotation times: {}", e))?;

        Ok(last_rotation.get(key_id).copied())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_rotation() {
        let store = KeyStore::new();
        let rotator = KeyRotator::new(store);
        let key_id = "test-rotation";
        let user = "olafcio42".to_string();

        // Initial key creation
        rotator.store.store_key(
            key_id.to_string(),
            vec![0u8; 32],
            crate::kms::store::KeyType::Primary,
            8.0,
            user.clone(),
        ).unwrap();

        // Force rotation
        let result = rotator.rotate_key(key_id, user.clone(), true);
        assert!(result.is_ok());

        let rotation = result.unwrap();
        assert_eq!(rotation.key_id, key_id);
        assert!(rotation.success);
        assert!(rotation.entropy_score >= MIN_ENTROPY_THRESHOLD);
        assert_eq!(rotation.rotated_by, user);
        assert_eq!(rotation.new_version, 2);
    }

    #[test]
    fn test_version_management() {
        let store = KeyStore::new();
        let rotator = KeyRotator::new(store);
        let key_id = "test-versioning";
        let user = "olafcio42".to_string();

        // Initial key
        rotator.store.store_key(
            key_id.to_string(),
            vec![1u8; 32],
            crate::kms::store::KeyType::Primary,
            8.0,
            user.clone(),
        ).unwrap();

        // Multiple rotations
        for i in 0..3 {
            let result = rotator.rotate_key(key_id, user.clone(), true).unwrap();
            assert_eq!(result.new_version, i + 2);

            // Verify old version is still accessible
            let old_key = rotator.store.get_key_version(key_id, i + 1).unwrap();
            assert!(old_key.is_some());
        }
    }
}