mod secret_management;
pub mod schnorr_identification;
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use std::thread;
use crate::secret_management::MyKey;
pub mod file_management;

// Constants for defining a role of a protocol initiator or a receiver.
pub const CONST_INITIATOR_ROLE: u8 = 0;
pub const CONST_RECEIVER_ROLE: u8 = 1;

// Const for defining protocol stages
const CONST_NEXT_STEP_REQUIRED: u8 = 0;
const CONST_COMMITMENT: u8 = 1;
const CONST_COMMITMENT_AND_CHALLENGE: u8 = 2;
const CONST_CHALLENGE_AND_RESPONSE: u8 = 3;
const CONST_RESPONSE: u8 = 4;

// For knowing that the response can be verified or not
pub const CONST_RESPONSE_CANNOT_BE_VERIFIED: u8 = 0;
pub const CONST_RESPONSE_CAN_BE_VERIFIED_AFTER_GENERATING_RESPONSE: u8 = 1;
pub const CONST_RESPONSE_CAN_BE_VERIFIED: u8 = 2;
pub const CONST_RECEIVED_WRONG_REQUEST_ID: u8 = 3;

// For checking if no other values needs to be generated
pub const CONST_NO_OTHER_VALUES_TO_GENERATE: u8 = 0;
pub const CONST_NEXT_VALUES_HAS_TO_BE_GENERATED: u8 = 1;

// Return an instance of MyKey of the key corresponding to the key description
pub fn get_key_instance(key_description: &str, key_size: usize, key: Option<Vec<u8>>) -> Result<secret_management::MyKey, secret_management::SecretKeyErrors> {
    let my_key = secret_management::MyKey::new(key_description, 32, key);
    my_key
}

pub fn get_int_mut_auth_instance(sender_ID: u32, recipient_ID: u32, role: u8) -> IntMutAuth {
    let mut ins = IntMutAuth::new(sender_ID, recipient_ID, role);
    ins
}

// Struct for interactive mutual authentication for secret key sharing
pub struct IntMutAuth {
    pub sender_ID: u32,
    pub recipient_ID: u32,
    pub role: u8,
    stage: u8,
    my_random_int: Scalar,
    my_commitment: [u8; 32],
    my_challenge: Scalar,
    my_response: [u8; 32],
    recipient_commitment: [u8; 32],
    recipient_challenge: Scalar,
    recipient_response: [u8; 32],
}

// ToDo: Add verifying if an interactive mutual authentication is allowed
// ToDo: Add verifying last saved commitments
impl IntMutAuth {
    // Create a new instance of Int_mut_auth
    pub fn new(sender_ID: u32, recipient_ID: u32, role: u8) -> IntMutAuth {
        // Generate random secret scalar and Commitment
        let my_random_int = schnorr_identification::generate_random_scalar();
        let my_commitment = (my_random_int * &ED25519_BASEPOINT_POINT).compress().to_bytes();

        // Init protocol variables
        let my_challenge = Scalar::from_bytes_mod_order([0u8; 32]);
        let my_response = [0u8; 32];
        let recipient_commitment = [0u8; 32];
        let recipient_challenge = Scalar::from_bytes_mod_order([0u8; 32]);
        let recipient_response = [0u8; 32];

        // Define the request type
        let mut stage =  CONST_COMMITMENT;
        if role == CONST_RECEIVER_ROLE {
            stage = CONST_COMMITMENT_AND_CHALLENGE;
        }

        // Genrate Instance of interactive mutual authentication struct
        let mut int_mut_auth = IntMutAuth {
            sender_ID,
            recipient_ID,
            role,
            stage,
            my_random_int,
            my_commitment,
            my_challenge,
            my_response,
            recipient_commitment,
            recipient_challenge,
            recipient_response,
        };

        // Return
        int_mut_auth
    }

    // Add Recipient Commitment
    pub fn add_recipient_values(&mut self, request_type: u8, val1: [u8; 32], val2: Option<[u8; 32]>) -> u8 {
        match request_type {
            CONST_NEXT_STEP_REQUIRED => {
                println!("1. Received request type {:?} from {:?}\n", request_type, &self.recipient_ID);
                CONST_RESPONSE_CANNOT_BE_VERIFIED
            },
            CONST_COMMITMENT => {
                self.recipient_commitment = val1;
                println!("2. Received request type {:?} from {:?}\n", request_type, &self.recipient_ID);
                CONST_RESPONSE_CANNOT_BE_VERIFIED
            },
            CONST_COMMITMENT_AND_CHALLENGE => {
                self.recipient_commitment = val1;
                self.recipient_challenge = Scalar::from_bytes_mod_order(val2.unwrap());
                println!("3. Received request type {:?} from {:?}\n", request_type, &self.recipient_ID);
                CONST_RESPONSE_CANNOT_BE_VERIFIED
            },
            CONST_CHALLENGE_AND_RESPONSE => {
                self.recipient_challenge = Scalar::from_bytes_mod_order(val1);
                self.recipient_response = val2.unwrap();
                println!("4. Received request type {:?} from {:?}\n", request_type, &self.recipient_ID);
                CONST_RESPONSE_CAN_BE_VERIFIED_AFTER_GENERATING_RESPONSE
            },
            CONST_RESPONSE => {
                self.recipient_response = val1;
                println!("5. Received request type {:?} from {:?}\n", request_type, &self.recipient_ID);
                CONST_RESPONSE_CAN_BE_VERIFIED
            },
            _ => {
                CONST_RECEIVED_WRONG_REQUEST_ID
            },
        }
    }

    // Generate challenge
    pub fn gen_next_values(&mut self) -> ([u8; 32], Option<[u8; 32]>, u8) {
        match self.stage {
            CONST_COMMITMENT => {
                // Define next stage and return Commitment
                self.stage = CONST_CHALLENGE_AND_RESPONSE;
                println!("6. Sended request type 1 to {:?}\n", self.recipient_ID);
                (self.my_commitment, None, CONST_COMMITMENT)
            },
            CONST_COMMITMENT_AND_CHALLENGE => {
                // Generate Challenge
                let challenge = schnorr_identification::generate_random_32bytes();
                self.my_challenge = Scalar::from_bytes_mod_order(challenge);

                // Define next stage and return commitment and challenge
                self.stage = CONST_RESPONSE;
                println!("7. Sended request type 2 to {:?}\n", self.recipient_ID);
                (self.my_commitment, Some(challenge), CONST_COMMITMENT_AND_CHALLENGE)
            },
            CONST_CHALLENGE_AND_RESPONSE => {
                // Generate Challenge
                let challenge = schnorr_identification::generate_random_32bytes();
                self.my_challenge = Scalar::from_bytes_mod_order(challenge);

                // Calculate response
                let response = self.gen_proof();
                self.my_response = response;
                println!("8. Sended request type 3 to {:?}\n", self.recipient_ID);
                (challenge, Some(response), CONST_CHALLENGE_AND_RESPONSE)
            },
            CONST_RESPONSE => {
                // ToDo: Add response calculation
                let response = self.gen_proof();
                self.my_response = response;
                println!("9. Sended request type 4 to {:?}\n", self.recipient_ID);
                (response, None, CONST_RESPONSE)
            },
            _ => {
                // ToDo: Change This to be an error or a message code with a significance
                (self.my_commitment, None, CONST_NEXT_STEP_REQUIRED)
            },
        }
    }

    // Generate Proof
    fn gen_proof(&self) -> [u8; 32] {
        // Fetch secret key, necessary for the proof and convert it to Scalar type
        let desciption = format!("PrivateKey:{}", &self.sender_ID);
        let my_secret_key = get_key_instance(&desciption, 32, None).unwrap();
        let key: &[u8] = my_secret_key.get_key();
        let secret_key_bytes: [u8; 32] = <[u8; 32]>::try_from(key).unwrap();
        let secret_key_sc = Scalar::from_bytes_mod_order(secret_key_bytes);

        // Generate Proof
        let proof = schnorr_identification::generate_proof_response(self.my_random_int,
                                                                    secret_key_sc,
                                                                    self.recipient_challenge);
        // Return Proof
        proof
    }

    // Verify proof
    pub fn verify_proof(&self) -> bool {
        // Check if commitment is never used to protect against replay attacks
        if !file_management::check_commitment(self.recipient_ID, self.recipient_commitment) {
            return false;
        } else {
            println!("Commitment was never used, continue verification.\n");
        }

        // Fetch Public Key of the recipient
        let desciption = format!("PublicKey:{}", &self.recipient_ID);
        let recipient_pubkey = get_key_instance(&desciption, 32, None).unwrap();

        // Convert Key into [u8; 32] format
        let key: &[u8] = recipient_pubkey.get_key();
        let key_bytes: [u8; 32] = <[u8; 32]>::try_from(key).unwrap();

        // Verify proof
        let proof = (self.recipient_commitment, self.my_challenge, self.recipient_response);
        let accepted = schnorr_identification::verify_int_proof(key_bytes, proof);

        // Calculate the shared secret key
        // Todo: Maybe consider running this code in a seperate thread if it takes too much time to run
        if accepted == true {
            self.calculate_shared_secret_key();
        }

        // Return verification results
        accepted
    }

    fn calculate_shared_secret_key(&self) {
        // Calculate shared secret key
        let commitment = schnorr_identification::bytes_to_edwards(&self.recipient_commitment);
        let shared_secret_key = (self.my_random_int * commitment).compress().to_bytes();

        // Hash the shared secret key
        let hashed_shared_Secret = schnorr_identification::sha3_256(&shared_secret_key, None, None, None);
        let key_vec = Vec::from(hashed_shared_Secret);
        let key_vec_copy = Vec::from(hashed_shared_Secret);
        println!("{:?} Calculated shared Secret key as: {:?}", self.sender_ID, hashed_shared_Secret);

        // Save the shared key in the OS
        let desciption = format!("SharedSecretKey:{}:{}",&self.sender_ID, &self.recipient_ID);
        let mut mykey = get_key_instance(&desciption, 32, Some(key_vec)).unwrap();

        // Check if key value was changed during initiation of Mykey instance or not. Change it if not
        if mykey.get_key() != &key_vec_copy {
            mykey.update_key_in_ring(key_vec_copy).unwrap();
        }

        // Initiate the shared counter and save it in the OS
        let mut shared_counter: u32 = 1;
        let shared_counter_vec = Vec::from(shared_counter.to_be_bytes());
        let shared_counter_vec_copy = Vec::from(shared_counter.to_be_bytes());
        let desciption = format!("SharedCounter:{}:{}",&self.sender_ID, &self.recipient_ID);
        let mut mykey = get_key_instance(&desciption, 4, Some(shared_counter_vec)).unwrap();

        // Check if key value was changed during initiation of Mykey instance or not. Change it if not
        if mykey.get_key() != &shared_counter_vec_copy {
            mykey.update_key_in_ring(shared_counter_vec_copy).unwrap();
        }

    }

    // For Debugging
    pub fn print_debug(&self) {
        println!("\n--- All Values together ---");
        println!("Sender ID: {:?}", &self.sender_ID);
        println!("Recipient ID: {:?}", &self.recipient_ID);
        println!("role: {:?}", &self.role);
        println!("stage: {:?}", &self.stage);
        println!("my_random_int: {:?}", &self.my_random_int);
        println!("my_commitment: {:?}", &self.my_commitment);
        println!("my_challenge: {:?}", &self.my_challenge);
        println!("my_response: {:?}", &self.my_response);
        println!("recipient_commitment: {:?}", &self.recipient_commitment);
        println!("recipient_challenge: {:?}", &self.recipient_challenge);
        println!("recipient_response: {:?}\n", &self.recipient_response);
    }
}

// Struct for mutual authentication using the NIZKP
pub struct NIZKMutAuth {
    pub sender_ID: u32,
    pub recipient_ID: u32,
    initiator: bool,
    my_random_int: Scalar,
    my_commitment: [u8; 32],
    my_challenge: [u8; 32],
    my_response: [u8; 32],
    recipient_commitment: [u8; 32],
    recipient_challenge: [u8; 32],
    recipient_response: [u8; 32],
    proof_accepted: bool,
}

impl NIZKMutAuth {
    // Create a new instance of Int_mut_auth
    pub fn new(sender_ID: u32, recipient_ID: u32, sender_proof: Option<([u8; 32], [u8; 32], [u8; 32])>) -> (NIZKMutAuth, ([u8; 32], [u8; 32], [u8; 32])) {
        // Generate random secret scalar and Commitment
        let my_random_int = schnorr_identification::generate_random_scalar();
        let my_commitment = (my_random_int * &ED25519_BASEPOINT_POINT).compress().to_bytes();

        // Init variables
        let mut initiator = true;
        let mut recipient_commitment = [0u8; 32];
        let mut recipient_challenge = [0u8; 32];
        let mut recipient_response = [0u8; 32];

        // Check if we have recipient proof or if we need to init the values
        match sender_proof {
            Some((commitment, challenge, response)) => {
                initiator = false;
                recipient_commitment = commitment;
                recipient_challenge = challenge;
                recipient_response = response;
            },
            None => {

            }
        }

        // Init protocol variables
        let my_challenge = [0u8; 32];
        let my_response = [0u8; 32];
        let proof_accepted = false;

        // Genrate Instance of interactive mutual authentication struct
        let mut nizk_mut_auth = NIZKMutAuth {
            sender_ID,
            recipient_ID,
            initiator,
            my_random_int,
            my_commitment,
            my_challenge,
            my_response,
            recipient_commitment,
            recipient_challenge,
            recipient_response,
            proof_accepted,
        };

        // Generate NIZK proof
        let (commitment, challenge, response) = nizk_mut_auth.nizk_proof();

        // Return
        (nizk_mut_auth, (commitment, challenge, response))
    }

    fn nizk_proof(&mut self) -> ([u8; 32], [u8; 32], [u8; 32]){
        // Fetch secret key and shared secret key
        let (privkey, _) = get_32byte_key(format!("PrivateKey:{}", self.sender_ID));
        let (sharedkey, mut sk) = get_32byte_key(format!("SharedSecretKey:{}:{}", self.sender_ID, self.recipient_ID));

        // Fetch shared counter value
        let (shared_counter, mut sc) = get_shared_counter(self.sender_ID, self.recipient_ID);

        // Calculate proof
        let (r, commitment, challenge, response) = schnorr_identification::nizk_proof(privkey,
                                                                                      sharedkey,
                                                                                      shared_counter);

        // Save values
        self.my_random_int = r;
        self.my_commitment = commitment;
        self.my_challenge = challenge;
        self.my_response = response;

        (commitment, challenge, response)
    }

    // Add proof values of recipient. This function should be called only by the initiator
    pub fn add_recipient_values(&mut self, proof: ([u8; 32], [u8; 32], [u8; 32])) {
        let (commitment, challenge, response) = proof;
        self.recipient_commitment = commitment;
        self.recipient_challenge = challenge;
        self.recipient_response = response;
    }

    // Verif recipient's proof
    pub fn verify_proof(&mut self) -> bool {
        // Fetch Public key of the sender, shared secret key, and shared counter
        let (pubkey, _) = get_32byte_key(format!("PublicKey:{}", self.recipient_ID));
        let (sharedkey, _) = get_32byte_key(format!("SharedSecretKey:{}:{}", self.sender_ID, self.recipient_ID));
        let (shared_counter, _) = get_shared_counter(self.sender_ID, self.recipient_ID);

        // Verify proof
        let (schnorr, mac) = schnorr_identification::verify_nizk_proof(pubkey,
                                                                       sharedkey,
                                                                       shared_counter,
                                                                       (self.recipient_commitment,
                                                                        self.recipient_challenge,
                                                                        self.recipient_response));
        // Save verification result
        let accepted = schnorr && mac;
        self.proof_accepted = accepted;

        // Check intrusion
        if !accepted {
            file_management::manage_intrusion(self.recipient_ID, schnorr, mac);
        }

        accepted
    }

    // Return session key
    pub fn calculate_session_key(&self) -> [u8; 32] {
        // Check if proof was accepted
        if self.proof_accepted {
            // Calculate shared session key
            let commitment = schnorr_identification::bytes_to_edwards(&self.recipient_commitment);
            let session_key = (self.my_random_int * commitment).compress().to_bytes();

            // Hash the shared secret key
            let hashed_session_key = schnorr_identification::sha3_256(&session_key, None, None, None);
            println!("{:?} Calculated session key as: {:?}\n", self.sender_ID, hashed_session_key);

            // Update used values
            if self.initiator {
                update_used_values(self.sender_ID,
                                   self.recipient_ID,
                                   self.my_response,
                                   Some(&self.recipient_response));
            } else {
                update_used_values(self.sender_ID,
                                   self.recipient_ID,
                                   self.recipient_response,
                                   Some(&self.my_response));
            }

            hashed_session_key
        } else {
            [0u8; 32]
        }
    }
}

// Function to read shared counter from OS
fn get_shared_counter(my_ID: u32, receiver_ID: u32) -> ([u8; 4], MyKey) {
    // Fetch Counter from OS
    let desciption = format!("SharedCounter:{}:{}", my_ID, receiver_ID);
    let mut counter_instance = get_key_instance(&desciption, 4, None).unwrap();
    let shared_counter: &[u8] = counter_instance.get_key();
    let shared_counter_bytes: [u8; 4] = <[u8; 4]>::try_from(shared_counter).unwrap();

    // Return counter
    (shared_counter_bytes, counter_instance)
}

// Fetch any 32 byte key from OS
fn get_32byte_key(description: String) -> ([u8; 32], MyKey) {
    let mut mykey = get_key_instance(&description, 32, None).unwrap();
    let key_ins: &[u8] = mykey.get_key();
    let key: [u8; 32] = <[u8; 32]>::try_from(key_ins).unwrap();

    (key, mykey)
}

// ToDo: Add errors handling in case a key is not available !?
pub fn gen_nizk_proof(my_ID: u32, receiver_ID: u32) -> ([u8; 32], [u8; 32], [u8; 32]) {
    // Fetch secret key and shared secret key
    let (privkey, _) = get_32byte_key(format!("PrivateKey:{}", my_ID));
    let (sharedkey, mut sk) = get_32byte_key(format!("SharedSecretKey:{}:{}", my_ID, receiver_ID));

    // Fetch shared counter value
    let (shared_counter, mut sc) = get_shared_counter(my_ID, receiver_ID);

    let (_, commitment, challenge, response) = schnorr_identification::nizk_proof(privkey,
                                                                                  sharedkey,
                                                                                  shared_counter);
    // Update shared counter and shared secret key
    update_used_values(my_ID, receiver_ID, response, None);

    // Return NIZK Proof
    (commitment, challenge, response)
}

pub fn verify_nizk_proof(my_ID: u32, sender_ID: u32, proof: ([u8; 32], [u8; 32], [u8; 32])) -> bool {
    // Fetch Public key of the sender, shared secret key, and shared counter
    let (pubkey, _) = get_32byte_key(format!("PublicKey:{}", sender_ID));
    let (sharedkey, _) = get_32byte_key(format!("SharedSecretKey:{}:{}", my_ID, sender_ID));
    let (shared_counter, _) = get_shared_counter(my_ID, sender_ID);

    // Get the commitment and the challenge response
    let (commitment, challenge, response) = proof;
    let (schnorr, mac) = schnorr_identification::verify_nizk_proof(pubkey,
                                                                   sharedkey,
                                                                   shared_counter,
                                                                   proof);
    // Update shared values if proof was accepted
    let accepted = schnorr && mac;
    if accepted == true {
        update_used_values(my_ID, sender_ID, response, None);
    } else {
        println!("Verifier {} did not update values", my_ID);
        // Check intrusion
        file_management::manage_intrusion(sender_ID, schnorr, mac);
    }

    // Return verification result
    accepted
}

// Update counter and secret key after each use
fn update_used_values(my_ID: u32, other_ID: u32, response: [u8; 32], additional_data: Option<&[u8]>) {
    // Fetch shared secret key and shared counter value
    let (sharedkey, mut sharedkey_ins) = get_32byte_key(format!("SharedSecretKey:{}:{}", my_ID, other_ID));
    let (shared_counter, mut shared_counter_ins) = get_shared_counter(my_ID, other_ID);

    // Convert counter into u32 and increment it
    let mut counter_value: u32 = u32::from_be_bytes(shared_counter);
    counter_value = counter_value + 1;

    // Calculate the new shared secret key
    let new_key = schnorr_identification::sha3_256(&sharedkey,
                                                   Some(counter_value.to_be_bytes().as_ref()),
                                                   Some(&response),
                                                   additional_data);
    println!("Generated new Key using hash.\n");

    // Update new key in OS
    // let mut sharedkey_ins = get_key_instance(&format!("SharedSecretKey:{}:{}", my_ID, other_ID), None).unwrap();
    // let mut sharedkey_ins = get_key_instance(&format!("SharedSecretKey:{}:{}", my_ID, other_ID), 32, Some(Vec::from(new_key))).unwrap();
    sharedkey_ins.update_key_in_ring(Vec::from(new_key)).unwrap();
    println!("{} updated the shared key! as {:?}\n", my_ID, new_key);

    // Update Counter in OS
    counter_value = counter_value + 1;
    shared_counter_ins.update_key_in_ring(Vec::from(counter_value.to_be_bytes())).unwrap();
    println!("{} updated the shared counter! as {:?}\n", my_ID, counter_value);
}

// Check if there is a compromised key
pub fn check_intrusion(senderID: u32) -> (bool, bool) {
    file_management::check_intrusion(senderID)
}
