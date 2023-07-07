use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::io::prelude::*;
use schnorr_nizk;
use serde::{Deserialize, Serialize};
use std::env;
use chrono::prelude::*;
use std::time::{Instant};


// ID's of client and server
const MY_ID: u32 = 100000;
const SERVER_ID: u32 = 200000;
const SERVER_ADDRESS: &str = "000.000.0.00:8000";

// Data to send and receive
#[derive(Debug, Serialize, Deserialize)]
struct DataExchange {
    auth_type: u8,
    request_type: u8,
    message: Option<String>,
    value_1: [u8; 32],
    value_2: Option<[u8; 32]>,
    value_3: Option<[u8; 32]>,
}

fn shared_key_agreement() {
    // Prepare data to be send
    // Create an instance of Mutual auth as an initiator role and get the values to send
    let mut int_mut_auth = schnorr_nizk::get_int_mut_auth_instance(MY_ID,SERVER_ID, schnorr_nizk::CONST_INITIATOR_ROLE);
    let (my_commitment, val_2, my_req_type) = int_mut_auth.gen_next_values();

    // Create a data struct with all info
    let data_struct = DataExchange {
        auth_type: 0,
        request_type: my_req_type,
        message: None,
        value_1: my_commitment,
        value_2: val_2,
        value_3: None,
    };

    // Convert data to String
    let json_string = serde_json::to_string(&data_struct).unwrap();

    // Connect to TCP Stream at port 8000 (defined in tcp_server.rs)
    let mut stream = TcpStream::connect(SERVER_ADDRESS).expect("connection failed");
    let mut stream_copy = stream.try_clone().expect("Failed to clone stream\n");

    // Send message
    println!("Sending first message:");
    stream.write_all(json_string.as_bytes()).expect("write failed");
    stream.write_all(b"\n").expect("Failed to write to server");
    println!("Message sent! Reading server response...");

    // Define server response reader and enter a loop for sending and receiving messages
    let mut reader = BufReader::new(stream_copy);
    loop {
        // Read server response
        let mut response = String::new();
        reader.read_line(&mut response).expect("Read server response failed!\n");
        let response_str = response.trim();
        print!("Got response from server: {}\n", response_str);

        // Convert response into a DataExchange struct
        let mut data: DataExchange = serde_json::from_str(response_str).unwrap();

        // Enter received values to our int_mut_auth instance
        let response_state = int_mut_auth.add_recipient_values(data.request_type, data.value_1, data.value_2);

        // Check if we still need to send data or not
        if (response_state == schnorr_nizk::CONST_RESPONSE_CANNOT_BE_VERIFIED) ||
            (response_state == schnorr_nizk::CONST_RESPONSE_CAN_BE_VERIFIED_AFTER_GENERATING_RESPONSE) {

            // Generate data to send
            let (val1, val2, my_req_type) = int_mut_auth.gen_next_values();
            let data_to_send = DataExchange {
                auth_type: 0,
                request_type: my_req_type,
                message: None,
                value_1: val1,
                value_2: val2,
                value_3: None,
            };
            let json_string = serde_json::to_string(&data_to_send).unwrap();

            // Send data
            println!("Sending data:");
            stream.write_all(json_string.as_bytes()).expect("write failed");
            stream.write_all(b"\n").expect("Failed to write to server");
            println!("Message sent!");
        }

        // Check if we need to verify the proof
        if (response_state == schnorr_nizk::CONST_RESPONSE_CAN_BE_VERIFIED_AFTER_GENERATING_RESPONSE) ||
            (response_state == schnorr_nizk::CONST_RESPONSE_CAN_BE_VERIFIED) {

            // Verify the proof
            let accepted = int_mut_auth.verify_proof();
            println!("Client {} verified proof of Server {}, result: {}\n", MY_ID, SERVER_ID, accepted);

            // Exist the loop since verification is complete
            break;
        }
    }
}

// NIZK Auth
fn test_nizk_auth_speed(m: String, m_copy: String) {
    // Connect to TCP Stream at port 8000 (defined in tcp_server.rs)
    let mut stream = TcpStream::connect(SERVER_ADDRESS).expect("connection failed");
    let mut stream_copy = stream.try_clone().expect("Failed to clone stream\n");

    // Generate NIZK Proof
    let (commitment, challenge, mut response) = schnorr_nizk::gen_nizk_proof(MY_ID, SERVER_ID, m, true);

    // Prepare data to send
    let data = DataExchange {
        auth_type: 123,
        request_type: 0,
        message: Some(m_copy),
        value_1: commitment,
        value_2: Some(challenge),
        value_3: Some(response),
    };

    // Convert data to String
    let json_string = serde_json::to_string(&data).unwrap();

    // Send message
    stream.write_all(json_string.as_bytes()).expect("write failed");
    stream.write_all(b"\n").expect("Failed to write to server");

    // Define server response reader and enter a loop for sending and receiving messages
    let mut reader = BufReader::new(stream_copy);
    let mut response = String::new();
    reader.read_line(&mut response).expect("Read server response failed!\n");
}


// NIZK Auth
fn nizk_auth(m: String, m_copy: String, fake_schnorr: bool, fake_mac: bool) {
    // Connect to TCP Stream at port 8000 (defined in tcp_server.rs)
    let mut stream = TcpStream::connect(SERVER_ADDRESS).expect("connection failed");

    // Generate NIZK Proof
    println!("Generating NIZK Proof");
    // Set if keys has to be updated after generation
    let mut update = true;
    if fake_schnorr || fake_mac {
        update = false;
    }

    let (commitment, challenge, mut response) = schnorr_nizk::gen_nizk_proof(MY_ID, SERVER_ID, m, update);

    // Fake schnorr proof
    if fake_schnorr {
        println!("Schnoor proof is faked");
        let (fake_response, _) = schnorr_nizk::gen_random_key_pair();
        response = fake_response;
    }

    // Save message in a mutable variable
    let mut my_message = String::from(m_copy);
    println!("message: {:?}", my_message);

    // Fake Mac Tag
    if fake_mac {
        println!("Mac Tag is faked");
        my_message = String::from(format!("fake message to make a fake Mac test proof {:?}", schnorr_nizk::generate_random_32bytes()));
    }
    println!("message: {:?}", my_message);
    // Prepare data to send
    let data = DataExchange {
        auth_type: 1,
        request_type: 0,
        message: Some(my_message),
        value_1: commitment,
        value_2: Some(challenge),
        value_3: Some(response),
    };

    // Convert data to String
    let json_string = serde_json::to_string(&data).unwrap();

    // Send message
    println!("Sending NIZK message:");
    stream.write_all(json_string.as_bytes()).expect("write failed");
    stream.write_all(b"\n").expect("Failed to write to server");
    println!("Message sent!\n");
}

// Generate a session key between two devices
fn session_key() {
    // Connect to TCP Stream at port 8000 (defined in tcp_server.rs)
    let mut stream = TcpStream::connect(SERVER_ADDRESS).expect("connection failed");
    let mut stream_copy = stream.try_clone().expect("Failed to clone stream\n");

    // Generate NIZK Proof
    println!("Generating NIZK Mutual Auth Proof");
    let (mut nizk_ins, (commitment, challenge, response)) = schnorr_nizk::NIZKMutAuth::new(MY_ID, SERVER_ID, None);

    // Prepare data to send
    let data = DataExchange {
        auth_type: 2,
        request_type: 0,
        message: None,
        value_1: commitment,
        value_2: Some(challenge),
        value_3: Some(response),
    };

    // Convert data to String
    let json_string = serde_json::to_string(&data).unwrap();

    // Send message
    println!("Sending NIZK Mutual Auth request:");
    stream.write_all(json_string.as_bytes()).expect("write failed");
    stream.write_all(b"\n").expect("Failed to write to server");
    println!("Message sent!\n");

    // Read server response
    let mut reader = BufReader::new(stream_copy);
    let mut response = String::new();
    reader.read_line(&mut response).expect("Read server response failed!\n");
    let response_str = response.trim();
    print!("Got response from server: {}\n", response_str);

    // Convert response into a DataExchange struct
    let mut data: DataExchange = serde_json::from_str(response_str).unwrap();

    // Add data to NIZK Auth and verify proof
    nizk_ins.add_recipient_values((data.value_1, data.value_2.unwrap(), data.value_3.unwrap()));
    let verify = nizk_ins.verify_proof();
    println!("Client verified server's proof, result = {:?}\n\n", verify);

    // Calculate session key
    let s_key = nizk_ins.calculate_session_key();
    println!("Client calculated session key as: {:?}\n", s_key);
}

fn fake_nizk_auth(dos_attack: bool) {
    let mut counter: u32 = 0;

    loop {
        // Connect to TCP Stream at port 8000 (defined in tcp_server.rs)
        let mut stream = TcpStream::connect(SERVER_ADDRESS).expect("connection failed");

        // Generate NIZK Proof
        println!("Generating fake random NIZK Proof values");
        let (commitment, _) = schnorr_nizk::gen_random_key_pair();
        let (response, _) = schnorr_nizk::gen_random_key_pair();
        let challenge = schnorr_nizk::generate_random_32bytes();
        let message = format!("fake test proof {:?}", schnorr_nizk::generate_random_32bytes());

        // Prepare data to send
        let data = DataExchange {
            auth_type: 1,
            request_type: 0,
            message: Some(message),
            value_1: commitment,
            value_2: Some(challenge),
            value_3: Some(response),
        };

        // Convert data to String
        let json_string = serde_json::to_string(&data).unwrap();

        // Send message
        println!("Sending NIZK message:");
        stream.write_all(json_string.as_bytes()).expect("write failed");
        stream.write_all(b"\n").expect("Failed to write to server");
        println!("Message sent!\n");

        // Increment counter for dos attack
        if dos_attack {
            counter = counter + 1;
        }

        // Condition to break from loop
        if (!dos_attack) || (counter == 1000) {
            break;
        }
    }
}

// Help function for entering the variables
fn print_help() {
    println!("\n----------------------------------------------------------------------------\n");
    println!("Usage: ./tcp_client <auth_type> [message]");
    println!("auth_type can be one of: exchange_keys, sharedsecretkey, nizk, sessionkey, fake, semi_fake_asymmetric, semi_fake_symmetric, dos_attack, testnizkspeed\n");
    println!("exchange_keys: Init and Exchange Asymmetric keys between client and server for test purposes.");
    println!("After running this, sharedsecretkey command has to be executed for a new shared secret key compatible with the current key.");
    println!("Note: This has to be replaced by a real trusted authority in future.\n");
    println!("sharedsecretkey: will generate a secret shared key between client and server, to use for NIZK Authentication!");
    println!("nizk: will send a Non-Interactive Authentication proof to the Server.");
    println!("sessionkey: will calculate a session secret key that can be used for end-to-end secure communication.");
    println!("fake: will generate a random fake NIZK proof.");
    println!("semi_fake_asymmetric: will generate a semi random fake NIZK proof, where the asymmetric key is correct and the Schnorr Proof is valid, but with a valid Mac Tag.");
    println!("semi_fake_symmetric: will generate a semi random fake NIZK proof, where the symmetric shared key is correct and the MAC Tag is valid, but with a valid Schnorr proof.");
    println!("dos_attack: will send 1000 fake NIZK proofs quickly to mimic a DoS attack.\n");
    println!("If auth_type is nizk, testnizkspeed, semi_fake_asymmetric, or semi_fake_symmetric, a message must be provided.\n");
    println!("PLEASE NOTE: For speed testing you can modify iteration number in tcp_client.rs, you have to change IP Adress to a valid one of Server.");
    println!("PLEASE NOTE: For testing NIZK Auth speed, a seperate command, testnizkspeed, is provided, since it requires an additional response compared to the normal NIZK.");
    println!("PLEASE NOTE: For accurate speed results, please comment all the prints of the console!\n");
    println!("----------------------------------------------------------------------------\n");
}

// Exchange keys for testing purposes
fn exchange_keys() {
    // Connect to TCP Stream at port 8000 (defined in tcp_server.rs)
    // 192.168.0.21 for inside wlan and 127.0.0.1 for local computer
    let mut stream = TcpStream::connect(SERVER_ADDRESS).expect("connection failed");
    let mut stream_copy = stream.try_clone().expect("Failed to clone stream\n");

    // Generate random key pair
    let (public_key, private_key) = schnorr_nizk::gen_random_key_pair();
    println!("Generated Pub key: {:?}\n\nPrivKey: {:?}\n", public_key, private_key);
    let desc_priv = format!("PrivateKey:{}", MY_ID);
    let desc_pub = format!("PublicKey:{}", MY_ID);
    let mut my_key_priv = schnorr_nizk::get_key_instance(&desc_priv, 32, Some(private_key.to_vec())).unwrap();
    let mut my_key_pub = schnorr_nizk::get_key_instance(&desc_pub, 32, Some(public_key.to_vec())).unwrap();

    // Update keys in Ring. This is important because if the key already exists
    // then it will not be changed without this step
    my_key_priv.update_key_in_ring(private_key.to_vec());
    my_key_pub.update_key_in_ring(public_key.to_vec());

    // Send public key to Server
    // Prepare data to send
    let data = DataExchange {
        auth_type: 11,
        request_type: 0,
        message: None,
        value_1: public_key,
        value_2: None,
        value_3: None,
    };

    // Convert data to String
    let json_string = serde_json::to_string(&data).unwrap();

    // Send message
    println!("Sending NIZK Mutual Auth request:");
    stream.write_all(json_string.as_bytes()).expect("write failed");
    stream.write_all(b"\n").expect("Failed to write to server");
    println!("Message sent!\n");

    // Read server response
    let mut reader = BufReader::new(stream_copy);
    let mut response = String::new();
    reader.read_line(&mut response).expect("Read server response failed!\n");
    let response_str = response.trim();
    print!("Got response from server: {}\n", response_str);

    // Convert response into a DataExchange struct
    let mut data: DataExchange = serde_json::from_str(response_str).unwrap();
    let desc_pub = format!("PublicKey:{}", SERVER_ID);
    let mut server_key_pub = schnorr_nizk::get_key_instance(&desc_pub, 32, Some(data.value_1.to_vec())).unwrap();

    // Make sure to update key in Ring, in case an old key with same ID exists
    server_key_pub.update_key_in_ring(data.value_1.to_vec());
}

// Main function
fn main() {
    let iterations = 1;

    // Read arguments
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_help();
        return;
    }

    // Check requested auth type
    let auth_type = &args[1];
    match auth_type.as_str() {
        "exchange_keys" => {
            exchange_keys();
        }
        "sharedsecretkey" => {
            println!("\nAuthentication type: Shared Secret Key chosen:");
            println!("Starting interactive mutual auth...\n");

            let mut all_measurements: Vec<f32> = Vec::new();

            for i in 0..iterations {
                // Measure duration of each one
                let start = Instant::now();

                // Interactive mutual auth for shared secret key agreement
                shared_key_agreement();

                // Calculate Duration
                let duration = (start.elapsed().as_secs_f32()) * 1_000.0;
                all_measurements.push(duration);
            }

            println!("All Measurements for Int Mut Auth:\n{:?}\n", all_measurements);

        }
        "nizk" => {
            if args.len() < 3 {
                println!("Error: No message provided for NIZK authentication");
                return;
            }
            let message = &args[2];
            println!("\nAuthentication type: NIZK\n");
            let (m, m_copy) = (message.to_owned(), message.to_owned());
            nizk_auth(m, m_copy, false, false);

        }
        "testnizkspeed" => {
            if args.len() < 3 {
                println!("Error: No message provided for NIZK authentication");
                return;
            }
            let message = &args[2];
            println!("\nAuthentication type: NIZK\n");

            let mut all_measurements: Vec<f32> = Vec::new();
            for i in 0..iterations {
                let (m, m_copy) = (message.to_owned(), message.to_owned());

                // Measure duration of each one
                let start = Instant::now();

                test_nizk_auth_speed(m, m_copy);

                // Calculate Duration
                let duration = (start.elapsed().as_secs_f32()) * 1_000.0;
                all_measurements.push(duration);
            }

            println!("All Measurements for NIZK Auth:\n{:?}\n", all_measurements);

        }
        "sessionkey" => {
            println!("\nAuthentication type: Session Key");
            let mut all_measurements: Vec<f32> = Vec::new();
            for i in 0..iterations {

                // Measure duration of each one
                let start = Instant::now();

                session_key();

                // Calculate Duration
                let duration = (start.elapsed().as_secs_f32()) * 1_000.0;
                all_measurements.push(duration);
            }

            println!("All Measurements for NIZK Mut Auth:\n{:?}\n", all_measurements);
        }
        "fake" => {
            println!("\nFake NIZK Auth");
            fake_nizk_auth(false);
        }
        "semi_fake_asymmetric" => {
            if args.len() < 3 {
                println!("Error: No message provided for semi_fake_asymmetric NIZK authentication");
                return;
            }
            let message = &args[2];
            let (m, m_copy) = (message.to_owned(), message.to_owned());

            println!("\nGenerating a fake proof with a valid schnorr proof and an invalid random Mac Tag:");
            nizk_auth(m, m_copy, false, true);
        }
        "semi_fake_symmetric" => {
            if args.len() < 3 {
                println!("Error: No message provided for semi_fake_symmetric NIZK authentication");
                return;
            }
            let message = &args[2];
            let (m, m_copy) = (message.to_owned(), message.to_owned());

            println!("\nGenerating a fake proof with a valid Mac Tag and an invalid random Schnorr Proof:");
            nizk_auth(m, m_copy, true, false);
        }
        "dos_attack" => {
            println!("\nMimic a Dos Attack:");
            fake_nizk_auth(true);
            println!("Dos attack ended!\n");
        }
        _ => {
            println!("Error: Invalid authentication type");
            print_help();
            return;
        }
    }
}
