use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

use hmac::{Hmac, Mac};
use sha1::Sha1;
use tauri::Manager;
use tauri_plugin_clipboard_manager::ClipboardExt;

type HmacSha1 = Hmac<Sha1>;

// ============================================================================
// TOTP GENERATION (RFC 6238)
// ============================================================================

fn base32_decode(input: &str) -> Result<Vec<u8>, String> {
    base32::decode(base32::Alphabet::RFC4648 { padding: true }, input)
        .ok_or_else(|| "Failed to decode Base32 secret".to_string())
}

fn generate_totp_internal(secret: &[u8], counter: u64) -> String {
    let counter_bytes: [u8; _] = counter.to_be_bytes();

    
    let mut mac: hmac::digest::core_api::CoreWrapper<hmac::HmacCore<hmac::digest::core_api::CoreWrapper<sha1::Sha1Core>>> = HmacSha1::new_from_slice(secret)
        .expect("HMAC can take key of any size");
    mac.update(&counter_bytes);
    let result = mac.finalize();
    let hmac_bytes: hmac::digest::generic_array::GenericArray<u8, hmac::digest::typenum::UInt<hmac::digest::typenum::UInt<hmac::digest::typenum::UInt<hmac::digest::typenum::UInt<hmac::digest::typenum::UInt<hmac::digest::typenum::UTerm, hmac::digest::consts::B1>, hmac::digest::consts::B0>, hmac::digest::consts::B1>, hmac::digest::consts::B0>, hmac::digest::consts::B0>> = result.into_bytes();

    let offset = (hmac_bytes[19] & 0x0f) as usize;
    let p: u32 = u32::from_be_bytes([
        hmac_bytes[offset],
        hmac_bytes[offset + 1],
        hmac_bytes[offset + 2],
        hmac_bytes[offset + 3],
    ]);
    
    let otp = (p & 0x7fff_ffff) % 1_000_000;

    format!("{:06}", otp)
}

// ============================================================================
// TAURI COMMANDS
// ============================================================================

#[tauri::command]
fn generate_totp(secret: String, counter: u64) -> Result<String, String> {
    let secret_bytes: Vec<u8> = base32_decode(&secret)?;

    Ok(generate_totp_internal(&secret_bytes, counter))
}

#[tauri::command]
fn save_keys(app: tauri::AppHandle, content: String) -> Result<(), String> {
    let file_path: PathBuf = get_keys_file_path(&app)?;
    eprintln!("save_keys: writing to {:?}, {} bytes", file_path, content.len());
    fs::write(file_path, content).map_err(|e| format!("Failed to save keys: {}", e))?;
    eprintln!("save_keys: write completed");
    Ok(())
}

#[tauri::command]
fn load_keys(app: tauri::AppHandle) -> Result<Vec<(String, String)>, String> {
    let file_path = get_keys_file_path(&app)?;

    eprintln!("load_keys: loading from {:?}", file_path);

    if !file_path.exists() {
        return Ok(vec![]);
    }

    let file = fs::File::open(&file_path)
        .map_err(|e| format!("Failed to open keys file: {}", e))?;
    let reader = BufReader::new(file);

    let mut keys = vec![];

    for line in reader.lines() {
        let line = line.map_err(|e| format!("Failed to read line: {}", e))?;
        let line = line.trim();

        if line.is_empty() {
            continue;
        }

        if let Some((name, secret)) = line.split_once('=') {
            keys.push((
                name.trim().to_string(),
                secret.trim().to_string(),
            ));
        }
    }

    Ok(keys)
}

#[tauri::command]
fn add_key(app: tauri::AppHandle, name: String, secret: String) -> Result<(), String> {
    let file_path = get_keys_file_path(&app)?;
    eprintln!("add_key: file_path={:?}, name='{}'", file_path, name);

    let mut keys: Vec<(String, String)> = if file_path.exists() {
        let file = fs::File::open(&file_path)
            .map_err(|e| format!("Failed to open keys file: {}", e))?;
        let reader = BufReader::new(file);
        let mut k = vec![];

        for line in reader.lines() {
            let line = line.map_err(|e| format!("Failed to read line: {}", e))?;
            let line = line.trim();
            if !line.is_empty() {
                if let Some((n, s)) = line.split_once('=') {
                    k.push((n.trim().to_string(), s.trim().to_string()));
                }
            }
        }
        
    } else {
        vec![]
    };


    keys.retain(|(k, _)| k != &name);
    
    keys.push((name, secret));

    let mut file = fs::File::create(&file_path)
        .map_err(|e| format!("Failed to create keys file: {}", e))?;
    eprintln!("add_key: writing {} key(s) to {:?}", keys.len(), file_path);

    for (k, s) in keys {
        writeln!(file, "{}={}", k, s)
            .map_err(|e| format!("Failed to write key: {}", e))?;
    }

    Ok(())
}

#[tauri::command]
fn delete_key(app: tauri::AppHandle, name: String) -> Result<(), String> {
    let file_path = get_keys_file_path(&app)?;
    eprintln!("delete_key: file_path={:?}, name='{}'", file_path, name);

    if !file_path.exists() {
        return Ok(());
    }

    let file = fs::File::open(&file_path)
        .map_err(|e| format!("Failed to open keys file: {}", e))?;
    let reader = BufReader::new(file);
    let mut keys = vec![];

    for line in reader.lines() {
        let line = line.map_err(|e| format!("Failed to read line: {}", e))?;
        let line = line.trim();
        if !line.is_empty() {
            if let Some((n, s)) = line.split_once('=') {
                if n.trim() != name {
                    keys.push((n.trim().to_string(), s.trim().to_string()));
                }
            }
        }
    }


    let mut file = fs::File::create(&file_path)
        .map_err(|e| format!("Failed to create keys file: {}", e))?;

    for (k, s) in keys {
        writeln!(file, "{}={}", k, s)
            .map_err(|e| format!("Failed to write key: {}", e))?;
    }

    Ok(())
}

#[tauri::command]
fn copy_to_clipboard(app: tauri::AppHandle, totp: String) -> Result<(), String> {
    app.clipboard()
        .write_text(totp)
        .map_err(|e| format!("Failed to copy to clipboard: {}", e))
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

fn get_keys_file_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("Failed to resolve app data directory: {}", e))?;

    fs::create_dir_all(&dir)
        .map_err(|e| format!("Failed to create app data directory {:?}: {}", dir, e))?;

    let new_path = dir.join("uv-auth-keys.env");


    if !new_path.exists() {
        #[cfg(desktop)]
        {
            if let Some(old_path) = legacy_keys_file_path() {
                if old_path.exists() {
                
                    let _ = fs::copy(&old_path, &new_path);
                }
            }
        }
    }

    Ok(new_path)
}

#[cfg(desktop)]
fn legacy_keys_file_path() -> Option<PathBuf> {
    dirs::home_dir().map(|home| home.join(".uv-auth-keys.env"))
}

// ============================================================================
// TAURI MAIN
// ============================================================================

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .invoke_handler(tauri::generate_handler![
            generate_totp,
            save_keys,
            load_keys,
            add_key,
            delete_key,
            copy_to_clipboard
        ]) 
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
