use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

use hmac::{Hmac, Mac};
use sha1::Sha1;
use tauri_plugin_clipboard_manager::ClipboardExt;

type HmacSha1 = Hmac<Sha1>;

// ============================================================================
// TOTP GENERATION (RFC 6238)
// ============================================================================

/// Decodes a Base32 string and returns the raw bytes.
fn base32_decode(input: &str) -> Result<Vec<u8>, String> {
    base32::decode(base32::Alphabet::RFC4648 { padding: true }, input)
        .ok_or_else(|| "Failed to decode Base32 secret".to_string())
}

/// Generates a 6-digit TOTP using HMAC-SHA1 dynamic truncation (RFC 6238).
fn generate_totp_internal(secret: &[u8], counter: u64) -> String {
    // Convert counter to 8-byte big-endian
    let counter_bytes: [u8; _] = counter.to_be_bytes();

    // Compute HMAC-SHA1
    let mut mac: hmac::digest::core_api::CoreWrapper<hmac::HmacCore<hmac::digest::core_api::CoreWrapper<sha1::Sha1Core>>> = HmacSha1::new_from_slice(secret)
        .expect("HMAC can take key of any size");
    mac.update(&counter_bytes);
    let result = mac.finalize();
    let hmac_bytes: hmac::digest::generic_array::GenericArray<u8, hmac::digest::typenum::UInt<hmac::digest::typenum::UInt<hmac::digest::typenum::UInt<hmac::digest::typenum::UInt<hmac::digest::typenum::UInt<hmac::digest::typenum::UTerm, hmac::digest::consts::B1>, hmac::digest::consts::B0>, hmac::digest::consts::B1>, hmac::digest::consts::B0>, hmac::digest::consts::B0>> = result.into_bytes();

    // Dynamic truncation (RFC 6238 Section 5.3)
    let offset = (hmac_bytes[19] & 0x0f) as usize;
    let p: u32 = u32::from_be_bytes([
        hmac_bytes[offset],
        hmac_bytes[offset + 1],
        hmac_bytes[offset + 2],
        hmac_bytes[offset + 3],
    ]);

    // Apply mask to clear sign bit and get 6-digit code
    let otp = (p & 0x7fff_ffff) % 1_000_000;

    // Return as zero-padded 6-digit string
    format!("{:06}", otp)
}

// ============================================================================
// TAURI COMMANDS
// ============================================================================

#[tauri::command]
fn generate_totp(secret: String, counter: u64) -> Result<String, String> {
    // Decode Base32 secret
    let secret_bytes: Vec<u8> = base32_decode(&secret)?;

    // Generate and return TOTP
    Ok(generate_totp_internal(&secret_bytes, counter))
}

#[tauri::command]
fn save_keys(content: String) -> Result<(), String> {
    let file_path: PathBuf = get_keys_file_path()?;
    eprintln!("save_keys: writing to {:?}, {} bytes", file_path, content.len());
    fs::write(file_path, content).map_err(|e| format!("Failed to save keys: {}", e))?;
    eprintln!("save_keys: write completed");
    Ok(())
}

#[tauri::command]
fn load_keys() -> Result<Vec<(String, String)>, String> {
    let file_path = get_keys_file_path()?;

    eprintln!("load_keys: loading from {:?}", file_path);

    // If file doesn't exist, return empty list
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

        // Skip empty lines
        if line.is_empty() {
            continue;
        }

        // Parse KEY_NAME=SECRET
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
fn add_key(name: String, secret: String) -> Result<(), String> {
    let file_path = get_keys_file_path()?;
    eprintln!("add_key: file_path={:?}, name='{}'", file_path, name);

    // Read existing keys
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
        k
    } else {
        vec![]
    };

    // Remove duplicate if exists
    keys.retain(|(k, _)| k != &name);

    // Add new key
    keys.push((name, secret));

    // Write back to file
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
fn delete_key(name: String) -> Result<(), String> {
    let file_path = get_keys_file_path()?;
    eprintln!("delete_key: file_path={:?}, name='{}'", file_path, name);

    if !file_path.exists() {
        return Ok(());
    }

    // Read existing keys
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

    // Write back to file
    let mut file = fs::File::create(&file_path)
        .map_err(|e| format!("Failed to create keys file: {}", e))?;

    for (k, s) in keys {
        writeln!(file, "{}={}", k, s)
            .map_err(|e| format!("Failed to write key: {}", e))?;
    }

    Ok(())
}

#[tauri::command]
fn copy_to_clipboard(app: tauri::AppHandle<tauri::Wry>, totp: String) -> Result<(), String> {
    app.clipboard()
        .write_text(totp)
        .map_err(|e| format!("Failed to copy to clipboard: {}", e))
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

fn get_keys_file_path() -> Result<PathBuf, String> {
    let home = dirs::home_dir().ok_or("Could not determine home directory")?;
    Ok(home.join(".uv-auth-keys.env"))
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
