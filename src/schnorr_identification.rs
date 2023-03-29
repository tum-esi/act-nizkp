extern crate rand;
use rand::{thread_rng, RngCore};

extern crate curve25519_dalek;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};


// Generate a random 32-byte value
fn generate_random_32bytes() -> [u8; 32] {
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
fn generate_random_scalar() -> (Scalar) {
    let random_bytes = generate_random_32bytes();
    Scalar::from_bytes_mod_order(random_bytes)
}

// Calculate the response
fn generate_proof_response(random_secret: Scalar, private_key: Scalar, challenge: Scalar) -> [u8; 32] {
    // Compute the response
    (random_secret + private_key * &challenge).to_bytes()
}

// Prove that the device knows the private key
pub fn prove(private_key: [u8; 32]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    // Turn private key into Scalar
    let private_key_sc = Scalar::from_bytes_mod_order(private_key);

    // The prover generates a random number k and the commitment
    let r = generate_random_scalar();
    let commitment = (r * &ED25519_BASEPOINT_POINT).compress().to_bytes();

    // Challenge c supposed to come from the verifier and has to be random This will be a Hash in our case
    let c = generate_random_scalar();
    let challenge = c.to_bytes();

    // Compute the proof
    let response = generate_proof_response(r, private_key_sc, c);

    // Return commitment, challenge, and response
    (commitment, challenge, response)
}

// Turn bytes value into Edward points.
fn bytes_to_edwards(bytes: &[u8; 32]) -> EdwardsPoint {
    let compressed: CompressedEdwardsY = CompressedEdwardsY(*bytes);
    compressed.decompress().unwrap()
}

// Verify the proof
pub fn verify(public_key: [u8; 32], proof: ([u8; 32], [u8; 32], [u8; 32])) -> bool {
    // Convert compressed public key into an Edwards point
    let public_key_ed = bytes_to_edwards(&public_key);

    // Get the commitment and the challenge response
    let (commitment, challenge, response) = proof;
    let commitment_ed = bytes_to_edwards(&commitment);
    let challenge_sc = Scalar::from_bytes_mod_order(challenge);
    let response_sc = Scalar::from_bytes_mod_order(response);

    // Compute the rhs and the lhs of the expected result
    let lhs = response_sc * &ED25519_BASEPOINT_POINT;
    let rhs = commitment_ed + challenge_sc * public_key_ed;

    // Compare the received commitment and the expected result
    return lhs == rhs;
}
