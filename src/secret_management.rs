extern crate linux_keyutils;
use linux_keyutils::{Key, KeyRing, KeyError, KeyRingIdentifier};
use linux_keyutils::{KeyPermissionsBuilder, Permission};
use rand::RngCore;


#[derive(Debug)]
pub enum SecretKeyErrors {
    KeyRingNotFound(KeyError),
    UnableToStoreKeyInOS(KeyError),
    UnableToChangeKeyPermissions(KeyError),
    UnableToChangeKeyValue(KeyError),
    UnableToGetKeyFromOS(KeyError),
    UnableToDeleteKeyFromOS(KeyError),
}

// Struct that has secret key info
pub struct MyKey {
    pub key_description: *const str,
    ring: KeyRing,
    key: Vec<u8>,
}

impl MyKey {
    // Create a new instance of MyKey
    pub fn new(key_description: &str, key_size: usize) -> Result<MyKey, SecretKeyErrors> {
        // Define keyring of current key
        // See [KeyRingIdentifier] and `man 2 keyctl` for more information on default
        // keyrings for processes.
        match KeyRing::from_special_id(KeyRingIdentifier::User, false) {
            Ok(ring) => {
                // Generate an instance of MyKey struct
                let mut my_key = MyKey {
                    key_description,
                    ring,
                    key: vec![0; key_size],
                };

                // Check if a key already exists
                match ring.search(key_description) {
                    // Retrieve stored key if found
                    Ok(secret_key) => {
                        println!("Key found stored in the OS. Retrieving Key from OS.\n");
                        my_key.key = secret_key.read_to_vec().unwrap();
                    },
                    Err(e) => {
                        println!("Read key Error is: {:?}\n", e);
                        // Generate a new random Key, since no key was found, and assign it to MyKey
                        println!("Key not found in the OS! Creating a new Key.\n");
                        let key = my_key.generate_random_key(key_size);
                        my_key.key = key;

                        // Store key in Keyring
                        match ring.add_key(key_description, &my_key.key) {
                            Ok(ring_key) => {
                                println!("Successfully saved Key in OS. \n");

                                // Define Key Permissions
                                // https://docs.rs/linux-keyutils/latest/src/linux_keyutils/permissions.rs.html#33
                                let perms = KeyPermissionsBuilder::builder()
                                    .posessor(Permission::ALL)
                                    .user(Permission::ALL)
                                    .group(Permission::VIEW)
                                    .build();

                                // Set key permissions
                                if let Err(e) = ring_key.set_perms(perms){
                                    println!("Error is: {:?}\n", e);
                                    return Err(SecretKeyErrors::UnableToChangeKeyPermissions(e));
                                }
                            },
                            Err(e) => {
                                println!("Error is: {:?}\n", e);
                                return Err(SecretKeyErrors::UnableToStoreKeyInOS(e));
                            }
                        }
                    }
                }

                // Return my_key
                Ok(my_key)
            },
            Err(e) => {
                println!("Error is: {:?}\n", e);
                Err(SecretKeyErrors::KeyRingNotFound(e))
            }
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

    // Immutable access
    pub fn get_key(&self) -> &Vec<u8> {
        &self.key
    }

    pub fn get_key_description(&self) -> *const str {
        *&self.key_description
    }

    // Change key of the function. This requires the MyKey instance to be declared as mutable
    pub fn update_key_in_ring(&mut self, new_key: Vec<u8>) -> Result<(), SecretKeyErrors> {
        // Read key instance from keyring
        let key = self.retrieve_key_from_ring().unwrap();

        // Update key in keyring
        if let Err(e) = key.update(&new_key){
            println!("Error is: {:?}\n", e);
            return Err(SecretKeyErrors::UnableToChangeKeyValue(e));
        }

        // Save temporary value in struct for rapid access
        self.key = new_key;
        Ok(())
    }

    // Retrieve a secret key from Stored value in the os
    fn retrieve_key_from_ring(&self) -> Result<Key, SecretKeyErrors> {
        // ToDo: Maybe try to use a safe operation instead of insafe here
        let description = unsafe {&*self.get_key_description()};
        match &self.ring.search(&description){
            Ok(secret) => {
                Ok(*secret)
            },
            Err(e) => {
                println!("Couldn't Read key from ring: {:?}\n", e);
                return Err(SecretKeyErrors::UnableToGetKeyFromOS(*e));
            }
        }
    }

    // Delete a secret key
    pub fn delete_key_from_ring(&self) -> Result<(), SecretKeyErrors> {
        // Read key instance from keyring
        let key = self.retrieve_key_from_ring().unwrap();

        if let Err(e) = key.invalidate() {
            return  Err(SecretKeyErrors::UnableToDeleteKeyFromOS(e));
        } else {
            Ok(())
        }
    }
}
