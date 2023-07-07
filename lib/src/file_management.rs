use std::fs::{File, OpenOptions, Permissions};
use std::io::{BufReader, BufWriter, Write};
use std::io::prelude::*;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use serde::{Deserialize, Serialize};
use serde_json::{Result, Value};
use hex;
use chrono::Utc;

// Threshold for max key guesses
const CONST_KEY_GUESS_THRESHOLD: u8 = 5;
const CONST_MAX_AUTH_RATE: f64 = 0.01;      // 20 requests per 1000 ms
const CONST_MIN_AUTH_RATE: f64 = 0.005;

// File path of the used commitments list
fn get_commitments_file_path(senderID: u32) -> String {
    format!(".nizk-auth/mut_comm_{}.txt", senderID)
}

// File path of the intrusion detection data
fn get_intrusion_file_path(senderID: u32) -> String {
    format!(".nizk-auth/intrusion_data_{}.json", senderID)
}

// Set the file permissions to 0o600, so that only the user can write to it
fn shrink_file_permissions(path: String) {
    let mut perms = Permissions::from_mode(0o600);
    std::fs::set_permissions(&path, perms).expect("Failed to set file permissions");
}

fn create_parent_dirs(file_path: String) {
    let path = Path::new(&file_path);

    // Create parent directories if they don't already exist
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            if let Err(err) = std::fs::create_dir_all(parent) {
                eprintln!("Failed to create parent directories: {}", err);
            }
        }
    }
}

// Check if an old commitment is being reused again
pub fn check_commitment(senderID: u32, commitment: [u8; 32]) -> bool {
    // Get path instance
    let file_path = get_commitments_file_path(senderID);
    let file_path_copy = get_commitments_file_path(senderID);
    let path = Path::new(&file_path);

    // Convert bytes into string for comparision
    let mut commitement_str = hex::encode(&commitment);

    // Check if path already exists
    if path.exists() {
        // Open the file again for appending, in read mode as well
        let file = OpenOptions::new()
            .read(true)
            .append(true)
            .open(path)
            .expect("Failed to open file!\n");

        // Wrap the file in a buffered reader to read its contents
        let mut commitment_exists = false;
        let reader = BufReader::new(file);

        // Compare lines
        for line in reader.lines() {
            let line_str = line.unwrap();
            if line_str.eq(&commitement_str) {
                println!("Commitment already exists in commitments list, Risk of Replay attack!\n");
                commitment_exists = true;
                break;
            }
        }

        if !commitment_exists {
            // Open the file again for appending, and get write buffer
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .append(true)
                .open(path)
                .expect("Failed to open file!\n");

            let mut writer = BufWriter::new(file);

            // Write Commitment into the file followed by a new line
            writer.write_all(commitement_str.as_bytes()).expect("Failed to append commitment to the old file\n");
            writer.write_all(b"\n").expect("Failed to write to file\n");

            // Flush the writer to ensure all data is written to the file
            writer.flush().expect("Failed to flush file\n");
        }

        return !commitment_exists;
    }else {
        // Create parent directories if they don't already exist
        create_parent_dirs(get_commitments_file_path(senderID));

        // Create file and set the file permissions so that only the user can write to it
        let mut file = File::create(file_path).unwrap();
        shrink_file_permissions(file_path_copy);

        // Wrap the file in a buffered writer to improve performance
        let mut writer = BufWriter::new(file);

        // Write Commitment into the file followed by a new line
        let comm_str: String = hex::encode(&commitment);
        writer.write_all(comm_str.as_bytes()).expect("Failed to write commitment to the new file");
        writer.write_all(b"\n").expect("Failed to write to file");
        writer.flush().expect("Failed to flush file");

        true
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Intrusion {
    asym_counter: u8,
    sym_counter: u8,
    start_timestamp: i64,
    rejections: u16,
    dos_attack: bool,
}

// Update the last intrusion system values
pub fn manage_intrusion(senderID: u32, schnorr_proof: bool, mac_tag: bool) {
    // Check if file exists and create file if it does not exist
    let file_path = get_intrusion_file_path(senderID);
    let path = Path::new(&file_path);
    if !path.exists() {
        println!("Path does not exist\n");
        // Define Data
        let (asym, sym) = get_counter_values(schnorr_proof, mac_tag);
        let timestamp = Utc::now().timestamp_millis();
        let intrusion = Intrusion {
            asym_counter: asym,
            sym_counter: sym,
            start_timestamp: timestamp,
            rejections: 1,
            dos_attack: false,
        };

        // Convert Data to a JSON
        let json_string = serde_json::to_string(&intrusion).unwrap();

        // Create parent directories if they does not exist
        let file_path = get_intrusion_file_path(senderID);
        create_parent_dirs(file_path);

        // Create File with json content
        let file_path = get_intrusion_file_path(senderID);
        let path = Path::new(&file_path);
        let mut file = File::create(&path).unwrap();
        file.write_all(json_string.as_bytes());

        // Shrink file permissions
        let file_path = get_intrusion_file_path(senderID);
        shrink_file_permissions(file_path);
    }
    // File exists! Read content and modify data
    else {
        // Get current timestamp
        let timestamp = Utc::now().timestamp_millis();

        // Open file and read content as Intrusion struct
        let mut intrusion = read_intrusion_data(senderID);

        // Calculate rejection rate
        let rejection_rate: f64 = intrusion.rejections as f64 / (timestamp - intrusion.start_timestamp) as f64;
        println!("Current rejection rate = {:?}\n", rejection_rate);
        // println!("Rejection rate = {:?}", rejection_rate);
        // println!("Max rate = {:?}", CONST_MAX_AUTH_RATE);
        // println!("Min rate = {:?}", CONST_MIN_AUTH_RATE);

        // Dos
        if (rejection_rate > CONST_MAX_AUTH_RATE) && (intrusion.rejections > 10) {
            intrusion.dos_attack = true;
            println!("Auth rejection rate is too high. Risk of DoS Attack!\n")
        } else if rejection_rate < CONST_MIN_AUTH_RATE {
            intrusion.rejections = 0;
            intrusion.dos_attack = false;
            intrusion.start_timestamp = timestamp;
        }

        // Modify data
        let (asym, sym) = get_counter_values(schnorr_proof, mac_tag);
        intrusion.asym_counter = intrusion.asym_counter + asym;
        intrusion.sym_counter = intrusion.sym_counter + sym;
        intrusion.rejections = intrusion.rejections + 1;

        // Convert to String and write it to file
        let json_string = serde_json::to_string(&intrusion).unwrap();
        let file_path = get_intrusion_file_path(senderID);
        let path = Path::new(&file_path);
        let mut file = File::create(&path).unwrap();
        file.write_all(json_string.as_bytes());
    }
}

// Check if a key is compromised or if a brute force attack is being conducted
pub fn check_intrusion(senderID: u32) -> (bool, bool, bool) {
    // Open file and read content as Intrusion struct
    let mut intrusion = read_intrusion_data(senderID);

    // Check if a key is compromised
    let mut asym_comp: bool = false;
    let mut sym_comp: bool = false;
    if intrusion.asym_counter > CONST_KEY_GUESS_THRESHOLD {
        asym_comp = true;
    }
    if intrusion.sym_counter > CONST_KEY_GUESS_THRESHOLD {
        sym_comp = true;
    }

    // Return verification result
    (asym_comp, sym_comp, intrusion.dos_attack)
}

fn read_intrusion_data(senderID: u32) -> Intrusion {
    // Open file and read content as Intrusion struct
    let file_path = get_intrusion_file_path(senderID);
    let path = Path::new(&file_path);
    let file = File::open(&path).unwrap();
    let reader = BufReader::new(file);
    let mut intrusion: Intrusion = serde_json::from_reader(reader).unwrap();
    intrusion
}

// Return which counters to increment
fn get_counter_values(schnorr_proof: bool, mac_tag: bool) -> (u8, u8) {
    // Check if a key is guessed correctly
    if !mac_tag & !schnorr_proof {
        (0, 0)
    }
    // Shared secret key may be compromised
    else if mac_tag & !schnorr_proof {
        (0, 1)
    }
    // EC Private key may be compromised
    else {
        (1, 0)
    }
}

// Init intrusion data
pub fn init_data(senderID: u32) {
    // Check if file exists and create file if it does not exist
    let file_path = get_intrusion_file_path(senderID);
    let path = Path::new(&file_path);
    if path.exists() {
        // Open file and read content as Intrusion struct
        let mut intrusion = read_intrusion_data(senderID);

        // Get current timestamp
        let timestamp = Utc::now().timestamp_millis();
        intrusion.start_timestamp = timestamp;
        intrusion.asym_counter = 0;
        intrusion.sym_counter = 0;
        intrusion.rejections = 0;
        intrusion.dos_attack = false;

        // Convert to String and write it to file
        let json_string = serde_json::to_string(&intrusion).unwrap();
        let file_path = get_intrusion_file_path(senderID);
        let path = Path::new(&file_path);
        let mut file = File::create(&path).unwrap();
        file.write_all(json_string.as_bytes());
    }
}