use std::fs::{File, OpenOptions, Permissions};
use std::io::{BufReader, BufWriter, Write};
use std::io::prelude::*;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use hex;


fn get_file_path(senderID: u32) -> String {
    format!(".nizk-auth/mut_comm_{}.txt", senderID)
}


pub fn check_commitment(senderID: u32, commitment: [u8; 32]) -> bool {
    // Get path instance
    let file_path = get_file_path(senderID);
    let file_path_copy = get_file_path(senderID);
    let path = Path::new(&file_path);

    // Convert bytes into string for comparision
    let mut commitement_str = hex::encode(&commitment);
    println!("Commitment string = {:?}\n", commitement_str);

    // Check if path already exists
    if path.exists() {
        println!("Commitment file {:?} already exists!\n", file_path);

        // Open the file again for appending, in read mode as well
        let file = OpenOptions::new()
            .read(true)
            .append(true)
            .open(file_path)
            .expect("Failed to open file \n");

        // Wrap the file in a buffered reader to read its contents
        let mut commitment_exists = false;
        let reader = BufReader::new(file);
        for line in reader.lines() {
            let line_str = line.unwrap();
            println!("line: {:?}\n", line_str);
            if line_str.eq(&commitement_str) {
                println!("Commitment already exists in commitments list, Risk of Replay attack!\n");
                commitment_exists = true;
                break;
            }
        }

        if !commitment_exists {
            // Open the file again for appending, in read mode as well
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .append(true)
                .open(file_path_copy)
                .expect("Failed to open file \n");

            // Wrap the file in a buffered writer to improve performance
            let mut writer = BufWriter::new(file);

            // Write Commitment into the file followed by a new line
            writer.write_all(commitement_str.as_bytes()).expect("Failed to append commitment to the old file\n");
            writer.write_all(b"\n").expect("Failed to write to file\n");

            // Flush the writer to ensure all data is written to the file
            writer.flush().expect("Failed to flush file\n");
        }

        return !commitment_exists;
    }else {
        println!("Commitment file {:?} does not exist!\n", file_path);

        // Create parent directories if they don't already exist
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                if let Err(err) = std::fs::create_dir_all(parent) {
                    eprintln!("Failed to create parent directories: {}", err);
                }
            }
        }

        // Create file
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .open(file_path)
            .expect("Failed to create file");

        // Set the file permissions to 0o600 (i.e., rw-------) so that only the user can write to it
        let mut perms = Permissions::from_mode(0o600);
        std::fs::set_permissions(&file_path_copy, perms).expect("Failed to set file permissions");

        // Wrap the file in a buffered writer to improve performance
        let mut writer = BufWriter::new(file);

        // Write Commitment into the file followed by a new line
        let comm_str: String = hex::encode(&commitment);
        writer.write_all(comm_str.as_bytes()).expect("Failed to write commitment to the new file");
        writer.write_all(b"\n").expect("Failed to write to file");

        // Flush the writer to ensure all data is written to the file
        writer.flush().expect("Failed to flush file");

        true
    }
}
