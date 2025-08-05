
#![allow(dead_code)]
mod rotate;
mod keygen;
mod store;
mod audit;

use chrono::Utc;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use crate::kms::store::KeyStore;


pub struct RotationPolicy {
    pub max_age_days: u32,
    pub force_rotation: bool,
    pub require_backup: bool,
}

#[derive(Debug)]
pub struct RotationResult {
    pub key_id: String,
    pub rotation_time: i64,
    pub success: bool,
}

pub struct KeyRotator {
    store: KeyStore,
    last_rotation: Mutex<HashMap<String, i64>>,
}

#[derive(Clone)]
pub struct EphemeralKeyManager {
    keys: Arc<Mutex<HashMap<String, EphemeralKeyData>>>,
}

pub struct EphemeralKeyData {
    pub timestamp: i64,
    pub key_id: String,
    pub entropy_score: f64,
}

impl KeyRotator {
    pub fn new(store: KeyStore) -> Self {
        KeyRotator {
            store,
            last_rotation: Mutex::new(HashMap::new()),
        }
    }

    pub fn rotate_key(&self, key_id: &str) -> Result<RotationResult, String> {
        let mut new_key = vec![0u8; 32];
        getrandom::getrandom(&mut new_key)
            .map_err(|e| format!("Failed to generate new key: {}", e))?;

        let rotation_time = Utc::now().timestamp();
        self.last_rotation.lock()
            .map_err(|e| format!("Failed to lock rotation times: {}", e))?
            .insert(key_id.to_string(), rotation_time);

        Ok(RotationResult {
            key_id: key_id.to_string(),
            rotation_time,
            success: true,
        })
    }
}

impl EphemeralKeyManager {
    pub fn new() -> Self {
        EphemeralKeyManager {
            keys: Arc::new(Mutex::new(HashMap::new())),
        }
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

    pub fn regenerate_key(&self, key_id: &str) -> Result<(), String> {
        let mut keys = self.keys.lock().map_err(|e| e.to_string())?;

        let mut key_data = vec![0u8; 32];
        getrandom::getrandom(&mut key_data)
            .map_err(|e| format!("Failed to generate random data: {}", e))?;

        let entropy_score = self.calculate_entropy(&key_data);
        if entropy_score < 7.5 {
            return Err("Generated key has insufficient entropy".to_string());
        }

        keys.insert(key_id.to_string(), EphemeralKeyData {
            timestamp: Utc::now().timestamp(),
            key_id: key_id.to_string(),
            entropy_score,
        });

        Ok(())
    }

    pub fn check_and_rotate_keys(&self) -> Result<(), String> {
        let keys = self.keys.lock().map_err(|e| e.to_string())?;
        let now = Utc::now().timestamp();

        let expired_keys: Vec<String> = keys.iter()
            .filter(|(_, data)| (now - data.timestamp) >= 24 * 60 * 60)
            .map(|(key_id, _)| key_id.clone())
            .collect();

        // Release the lock before calling regenerate_key to avoid deadlock
        drop(keys);

        for key_id in expired_keys {
            self.regenerate_key(&key_id)?;
        }

        Ok(())
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

        let result = rotator.rotate_key(key_id);
        assert!(result.is_ok());

        let rotation = result.unwrap();
        assert_eq!(rotation.key_id, key_id);
        assert!(rotation.success);
    }

    #[test]
    fn test_ephemeral_key_regeneration() {
        let manager = EphemeralKeyManager::new();
        let key_id = "test-ephemeral";

        assert!(manager.regenerate_key(key_id).is_ok());

        let keys = manager.keys.lock().unwrap();
        let key_data = keys.get(key_id).unwrap();

        assert!(key_data.entropy_score >= 7.5);
        assert_eq!(key_data.key_id, key_id);
    }

    #[test]
    fn test_ephemeral_key_rotation() {
        let manager = EphemeralKeyManager::new();
        let key_id = "test-rotation";

        assert!(manager.regenerate_key(key_id).is_ok());

        assert!(manager.check_and_rotate_keys().is_ok());
    }
}