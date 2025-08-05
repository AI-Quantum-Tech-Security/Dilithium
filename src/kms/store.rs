#![allow(dead_code)]
use std::collections::HashMap;
use std::sync::Mutex;
use chrono::{Utc};
use serde::{Serialize, Deserialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyMetadata {
    pub key_type: KeyType,
    pub created_at: i64,
    pub last_rotated: Option<i64>,
    pub version: u32,
    pub entropy_score: f64,
    pub rotated_by: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum KeyType {
    Primary,
    Secondary,
    Backup,
}

pub struct KeyStore {
    keys: Mutex<HashMap<String, Vec<u8>>>,
    metadata: Mutex<HashMap<String, KeyMetadata>>,
    versions: Mutex<HashMap<String, HashMap<u32, Vec<u8>>>>,
}

impl KeyStore {
    pub fn new() -> Self {
        KeyStore {
            keys: Mutex::new(HashMap::new()),
            metadata: Mutex::new(HashMap::new()),
            versions: Mutex::new(HashMap::new()),
        }
    }

    pub fn store_key(&self, key_id: String, key_data: Vec<u8>, key_type: KeyType,
                     entropy_score: f64, user: String) -> Result<(), String> {
        let mut keys = self.keys.lock()
            .map_err(|e| format!("Failed to lock keys: {}", e))?;
        let mut metadata = self.metadata.lock()
            .map_err(|e| format!("Failed to lock metadata: {}", e))?;
        let mut versions = self.versions.lock()
            .map_err(|e| format!("Failed to lock versions: {}", e))?;

        keys.insert(key_id.clone(), key_data.clone());

        let version_map = versions.entry(key_id.clone())
            .or_insert_with(HashMap::new);
        version_map.insert(1, key_data);

        metadata.insert(key_id, KeyMetadata {
            key_type,
            created_at: Utc::now().timestamp(),
            last_rotated: None,
            version: 1,
            entropy_score,
            rotated_by: user,
        });

        Ok(())
    }

    pub fn update_key(&self, key_id: &str, new_key_data: Vec<u8>,
                      entropy_score: f64, user: String) -> Result<(), String> {
        let mut keys = self.keys.lock()
            .map_err(|e| format!("Failed to lock keys: {}", e))?;
        let mut metadata = self.metadata.lock()
            .map_err(|e| format!("Failed to lock metadata: {}", e))?;
        let mut versions = self.versions.lock()
            .map_err(|e| format!("Failed to lock versions: {}", e))?;

        if let Some(meta) = metadata.get_mut(key_id) {
            let new_version = meta.version + 1;

            // Store the new key version
            let version_map = versions.entry(key_id.to_string())
                .or_insert_with(HashMap::new);
            version_map.insert(new_version, new_key_data.clone());

            // Update current key
            keys.insert(key_id.to_string(), new_key_data);

            // Update metadata
            meta.last_rotated = Some(Utc::now().timestamp());
            meta.version = new_version;
            meta.entropy_score = entropy_score;
            meta.rotated_by = user;

            Ok(())
        } else {
            Err("Key not found".to_string())
        }
    }

    pub fn get_key_version(&self, key_id: &str, version: u32) -> Result<Option<Vec<u8>>, String> {
        let versions = self.versions.lock()
            .map_err(|e| format!("Failed to lock versions: {}", e))?;

        Ok(versions.get(key_id)
            .and_then(|ver_map| ver_map.get(&version))
            .cloned())
    }

    pub fn get_key(&self, key_id: &str) -> Result<Option<Vec<u8>>, String> {
        let keys = self.keys.lock()
            .map_err(|e| format!("Failed to lock keys: {}", e))?;
        Ok(keys.get(key_id).cloned())
    }

    pub fn delete_key(&self, key_id: &str) -> Result<bool, String> {
        let mut keys = self.keys.lock()
            .map_err(|e| format!("Failed to lock keys: {}", e))?;
        let mut metadata = self.metadata.lock()
            .map_err(|e| format!("Failed to lock metadata: {}", e))?;
        let mut versions = self.versions.lock()
            .map_err(|e| format!("Failed to lock versions: {}", e))?;

        let key_existed = keys.remove(key_id).is_some();
        metadata.remove(key_id);
        versions.remove(key_id);

        Ok(key_existed)
    }

    pub fn list_keys(&self) -> Result<Vec<(String, KeyMetadata)>, String> {
        let metadata = self.metadata.lock()
            .map_err(|e| format!("Failed to lock metadata: {}", e))?;
        Ok(metadata.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
    }
}