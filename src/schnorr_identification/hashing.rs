use tiny_keccak::{Hasher, Kmac, Sha3};


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
                println!("Arg ignored.")
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
                println!("Arg ignored.")
            }
        }
    }

    // Generate Tag
    let mut tag = [0u8; 32];
    kmac_instance.finalize(&mut tag);

    // Return Tag
    tag
}
