extern crate rand;
use rand::{thread_rng, RngCore};
use tiny_keccak::{Hasher, Kmac, Sha3};

extern crate curve25519_dalek;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};


// Generate a random 32-byte value
pub fn generate_random_32bytes() -> [u8; 32] {
    let mut rng = thread_rng();
    let mut random: [u8; 32] = [0; 32];
    rng.fill_bytes(&mut random);

    // Return generated key
    random
}

// Generate a new public-private key pair for the device.
pub fn key_gen() -> ([u8; 32], [u8; 32]) {
    // Generate private key as a 32-byte randon value and as type Scalar
    let random_bytes = generate_random_32bytes();
    let private_key = Scalar::from_bytes_mod_order(random_bytes);
    // let private_key = Scalar::from_bytes_mod_order(<[u8; 32]>::try_from(random_bytes).unwrap());

    // Calculate public key using ED25519_BASEPOINT_POINT
    let public_key = (private_key * &ED25519_BASEPOINT_POINT).compress().to_bytes();

    // Return Public and Private Key pair
    (public_key, private_key.to_bytes())
}

// Generate a random 32-byte value with type Scalar
pub fn generate_random_scalar() -> Scalar {
    let random_bytes = generate_random_32bytes();
    Scalar::from_bytes_mod_order(random_bytes)
}

// Generate a Hash using sha3
pub fn sha3_256(arg1: &[u8], arg2: Option<&[u8]>, arg3: Option<&[u8]>, arg4: Option<&[u8]>) -> [u8; 32] {
    // Define a kmac instance
    let mut sha3_instance = Sha3::v256();

    // Include main arg into data
    sha3_instance.update(arg1);

    // Check the optional args
    let args = [arg2, arg3, arg4];
    for arg in args.iter() {
        match arg {
            Some(x) => {
                sha3_instance.update(x);
            },
            None => {

            }
        }
    }

    // Generate Hash
    let mut digest = [0u8; 32];
    sha3_instance.finalize(&mut digest);

    // Return result
    digest
}

// Generate a Kmac Tag
pub fn kmac_256(key: [u8; 32], arg1: &[u8], arg2: Option<&[u8]>, arg3: Option<&[u8]>) -> [u8; 32] {
    // Define a kmac instance
    let mut kmac_instance = Kmac::v256(&key, b"");

    // Include main arg into data
    kmac_instance.update(arg1);

    // Check the optional args
    let args = [arg2, arg3];
    for arg in args.iter() {
        match arg {
            Some(x) => {
                kmac_instance.update(x);
            },
            None => {

            }
        }
    }

    // Generate Tag
    let mut tag = [0u8; 32];
    kmac_instance.finalize(&mut tag);

    // Return Tag
    tag
}

// Calculate the response
pub fn generate_proof_response(random_secret: Scalar, private_key: Scalar, challenge: Scalar) -> [u8; 32] {
    // Compute the response
    (random_secret + private_key * &challenge).to_bytes()
}

// Todo: Make interactive mutual auth private and manage Auth initiation

// Generate a proof that the device knows the private key, using Non-Interactive Zero-Knowledge
// ToDo: Add counter management
// ToDo: Add counter to MAC function
pub fn nizk_proof(private_key: [u8; 32], shared_secret_key: [u8; 32], shared_counter: [u8; 4]) -> (Scalar, [u8; 32], [u8; 32], [u8; 32]) {
    // Turn private key into Scalar
    let private_key_sc = Scalar::from_bytes_mod_order(private_key);

    // The prover generates a random number k and the commitment
    let r = generate_random_scalar();
    let commitment = (r * &ED25519_BASEPOINT_POINT).compress().to_bytes();

    // Generate challenge using KMAC function with a random value
    let challenge = kmac_256(shared_secret_key,
                                &commitment,
                                Some(&shared_counter),
                                None);

    // Convert challenge into a Scalar
    let c = Scalar::from_bytes_mod_order(challenge);

    // Compute the proof
    let response = generate_proof_response(r, private_key_sc, c);

    // Return commitment, challenge, and response
    (r, commitment, challenge, response)
}

// Turn bytes value into Edward points.
pub fn bytes_to_edwards(bytes: &[u8; 32]) -> EdwardsPoint {
    let compressed = CompressedEdwardsY(*bytes);
    compressed.decompress().unwrap()
}

// Verify if the challenge is generated correctly using the MAC Tag
fn verify_challenge(shared_secret: [u8; 32], shared_counter: [u8; 4], commitment: [u8; 32], challenge: [u8; 32]) -> bool {
    // Generate expected challenge using KMAC function with a random value
    let expected_challenge = kmac_256(shared_secret,
                                      &commitment,
                                      Some(&shared_counter),
                                      None);

    return challenge == expected_challenge;
}

// Verify the proof
pub fn verify_nizk_proof(public_key: [u8; 32], shared_secret: [u8; 32], shared_counter: [u8; 4],
                    proof: ([u8; 32], [u8; 32], [u8; 32])) -> (bool, bool) {

    // Convert compressed public key into an Edwards point
    let public_key_ed = bytes_to_edwards(&public_key);

    // Get the commitment and the challenge response
    let (commitment, challenge, response) = proof;

    // Verify Challenge generation
    let challenge_accepted = verify_challenge(shared_secret, shared_counter, commitment, challenge);

    // Convert values for schnorr verification
    let commitment_ed = bytes_to_edwards(&commitment);
    let challenge_sc = Scalar::from_bytes_mod_order(challenge);
    let response_sc = Scalar::from_bytes_mod_order(response);

    // Compute the rhs and the lhs of the expected result
    let lhs = response_sc * &ED25519_BASEPOINT_POINT;
    let rhs = commitment_ed + challenge_sc * public_key_ed;

    // Compare the received commitment and the expected result
    return (lhs == rhs, challenge_accepted);
}

// Verify the proof
pub fn verify_int_proof(public_key: [u8; 32], proof: ([u8; 32], Scalar, [u8; 32])) -> bool {

    // Convert compressed public key into an Edwards point
    let public_key_ed = bytes_to_edwards(&public_key);

    // Get the commitment and the challenge response
    let (commitment, challenge_sc, response) = proof;

    // Convert values for schnorr verification
    let commitment_ed = bytes_to_edwards(&commitment);
    let response_sc = Scalar::from_bytes_mod_order(response);

    // Compute the rhs and the lhs of the expected result
    let lhs = response_sc * &ED25519_BASEPOINT_POINT;
    let rhs = commitment_ed + challenge_sc * public_key_ed;

    // Compare the received commitment and the expected result
    return lhs == rhs;
}

