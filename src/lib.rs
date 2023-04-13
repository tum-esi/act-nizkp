mod secret_management;
pub mod schnorr_identification;
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;

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
pub fn get_key_instance(key_description: &str) -> Result<secret_management::MyKey, secret_management::SecretKeyErrors> {
    let my_key = secret_management::MyKey::new(key_description, 32);
    my_key
}

pub fn get_int_mut_auth_instance(recipient_ID: u32, role: u8) -> IntMutAuth {
    let mut ins = IntMutAuth::new(recipient_ID, role);
    ins
}

// Struct for interactive mutual authentication for secret key sharing
pub struct IntMutAuth {
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

impl IntMutAuth {
    // Create a new instance of Int_mut_auth
    pub fn new(recipient_ID: u32, role: u8) -> IntMutAuth {
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

                // ToDo: Add response calculation
                let response = [0u8; 32];
                println!("8. Sended request type 3 to {:?}\n", self.recipient_ID);
                (challenge, Some(response), CONST_CHALLENGE_AND_RESPONSE)
            },
            CONST_RESPONSE => {
                // ToDo: Add response calculation
                let response = [0u8; 32];
                println!("9. Sended request type 4 to {:?}\n", self.recipient_ID);
                (response, None, CONST_RESPONSE)
            },
            _ => {
                // ToDo: Change This to be an error or a message code with a significance
                (self.my_commitment, None, CONST_NEXT_STEP_REQUIRED)
            },
        }
    }

    pub fn verify_proof(&self) -> bool {
        // ToDo: Add True response verification
        true
    }

    pub fn print_debug(&self) {
        println!("\n--- All Values together ---");
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
