use std::string::FromUtf8Error;
use rand::RngCore;
use base64::{Engine as _, engine::{self, general_purpose}};
extern crate keyring;


#[derive(Debug)]
pub enum SecretKeyErrors {
    UnableToStoreKeyInOS(*const keyring::Error),
    UnableToGetKeyFromOS(*const keyring::Error),
    UnableToEncodeString(base64::EncodeSliceError),
    UnableToDecodeString(base64::DecodeError),
    UnableToDeleteKeyFromOS(*const keyring::Error),
    UnableToGetStrFromVec(FromUtf8Error),
}


// Struct that has secret key info
pub struct MyKey {
    pub username: *const str,
    entry: keyring::Entry,
    key: Vec<u8>,
}

impl MyKey {
    // Create a new instance of MyKey
    pub fn new(username: &str, key_size: usize) -> Result<MyKey, SecretKeyErrors> {

        // Set the KEYRING_BACKEND environment variable to SecretService
        std::env::set_var("KEYRING_BACKEND", "secret_service");

        let entry = keyring::Entry::new("schnorr_nizk_auth_service", username).unwrap();


        // Generate an instance of MyKey
        let mut my_key = MyKey {
            username,
            entry,
            key: vec![0; key_size],
        };

        // Check if a key already exists
        match my_key.get_secret_key_from_os() {
            // Retrieve stored key if found
            Ok(secret_key) => {
                println!("Key found stored in the OS. Retrieving Key from OS.\n");
                my_key.key = secret_key;
            },
            Err(e) => {
                println!("Read key Error is: {:?}\n", e);
                // Generate a new random Key, since no key was found, and assign it to MyKey
                println!("Key not found in the OS! Creating a new Key.\n");
                let key = my_key.generate_random_key(key_size);
                my_key.key = key;

                // Store Key in the OS
                if let Err(e) = my_key.store_secret_key(){
                    println!("Error is: {:?}\n", e);
                    Err(e).expect("Couldn't store key in the OS.")
                }
            }
        }

        // Return my_key
        Ok(my_key)
    }

    // Immutable access
    pub fn get_key(&self) -> &Vec<u8> {
        &self.key
    }

    pub fn get_username(&self) -> *const str {
        *&self.username
    }

    // Change key of the function. This requires the MyKey instance to be declared as mutable
    pub fn reset_key(&mut self, new_key: Vec<u8>) -> Result<(), SecretKeyErrors> {
        // Ignore error if occurred
        let _ = self.delete_secret_key_from_os();
        self.key = new_key;
        if let Err(e) = self.store_secret_key() {
            Err(e)
        }else {
            Ok(())
        }
    }

    // Generate a random key
    pub fn generate_random_key(&self, size: usize) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let mut key = vec![0; size];
        rng.fill_bytes(&mut key);

        // Return generated key
        key
    }

    // Store a secret key
    fn store_secret_key(&self) -> Result<(), SecretKeyErrors> {
        // Convert byte array into str to Store it
        // let mut vec: Vec<u8> = vec![];
        // vec.clone_from(&self.key);
        let secret = general_purpose::STANDARD.encode(&self.key);
        if let Err(e) = &self.entry.set_password(&secret) {
            println!("Lib error is: {:?}", e);
            Err(SecretKeyErrors::UnableToStoreKeyInOS(e))
        } else {
            Ok(())
        }
    }

    // Retrieve a secret key from Stored value in the os
    fn get_secret_key_from_os(&self) -> Result<Vec<u8>, SecretKeyErrors> {
        // let mut secret = &self.entry.get_password();
        match &self.entry.get_password(){
            Ok(secret) => {
                // let my_str: &str = secret;
                // let val = my_str.as_bytes().to_vec();
                match general_purpose::STANDARD.decode(secret) {
                    Ok(key) => {
                        Ok(key)
                    },
                    Err(e) => Err(SecretKeyErrors::UnableToDecodeString(e))
                }
            },
            Err(e) => {
                println!("Read error from keyring: {:?}\n", e);
                Err(SecretKeyErrors::UnableToGetKeyFromOS(e))
            }
        }
    }

    // Delete a secret key
    pub fn delete_secret_key_from_os(&self) -> Result<(), SecretKeyErrors> {
        if let Err(e) = &self.entry.delete_password() {
            Err(SecretKeyErrors::UnableToDeleteKeyFromOS(e))
        } else {
            Ok(())
        }
    }
}
