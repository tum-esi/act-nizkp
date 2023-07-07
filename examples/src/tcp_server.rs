use std::net::{TcpListener, TcpStream};
use std::io::prelude::*;
use std::{io, thread};
use schnorr_nizk;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use std::collections::HashMap;
use std::net::IpAddr;

// ID's of client and server
const MY_ID: u32 = 200000;
const CLIENT_ID: u32 = 100000;
const SERVER_ADDRESS: &str = "000.000.0.00:8000";

// Block duration if a DoS attack is detected
const BLOCK_DURATION: Duration = Duration::from_secs(10);

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

// Callback function to handle an incoming connection
fn handle_connection(stream: TcpStream, block_map: Arc<Mutex<HashMap<IpAddr, SystemTime>>>) {
    // Read received message
    let mut stream_copy = stream.try_clone().expect("Failed to clone stream\n");
    let mut stream_copy_2 = stream.try_clone().expect("Failed to clone stream\n");
    let mut reader = io::BufReader::new(stream);
    let mut message = String::new();
    reader.read_line(&mut message).expect("Read server response failed!\n");
    let message_str = message.trim();
    println!("Got response from client: {}\n", message_str);

    // Convert message into a DataExchange struct
    let mut data: DataExchange = serde_json::from_str(message_str).unwrap();

    match data.auth_type {
        // Interactive Mutual Auth for key Agreement
        0 => {
            // Get instance of IntMutAuth and add received values
            let mut int_mut_auth = schnorr_nizk::get_int_mut_auth_instance(MY_ID,CLIENT_ID, schnorr_nizk::CONST_RECEIVER_ROLE);
            int_mut_auth.add_recipient_values(data.request_type, data.value_1, data.value_2);

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
            stream_copy.write_all(json_string.as_bytes()).expect("write failed");
            stream_copy.write_all(b"\n").expect("Failed to write to server");
            println!("Message sent!");

            // Read last data
            message.clear();
            reader.read_line(&mut message).expect("Read server response failed!\n");
            let message_str = message.trim();
            print!("Got response from client: {}\n", message_str);

            // Convert message into a DataExchange struct and add recipient values
            let mut last_data: DataExchange = serde_json::from_str(message_str).unwrap();
            int_mut_auth.add_recipient_values(last_data.request_type, last_data.value_1, last_data.value_2);

            // Generate next values
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
            stream_copy.write_all(json_string.as_bytes()).expect("write failed");
            stream_copy.write_all(b"\n").expect("Failed to write to server");
            println!("Message sent!");

            // Verify proof
            let accepted = int_mut_auth.verify_proof();
            println!("Server {} verified proof of Client {}, result: {}\n", MY_ID, CLIENT_ID, accepted);
        },

        // NIZK Authentication
        1 => {
            // Verify proof
            println!("\nVerifying NIZK Proof of client: {}", CLIENT_ID);
            let result = schnorr_nizk::verify_nizk_proof(MY_ID,
                                                         CLIENT_ID,
                                                         data.message.unwrap(),
                                                         (data.value_1, data.value_2.unwrap(), data.value_3.unwrap()),
                                                         true);

            if !result {
                println!("\nProof not accepted, Checking intrusion...");
                let (asym, sym, dos) = schnorr_nizk::check_intrusion(CLIENT_ID);
                println!("Asymmetric keypair are compromised ?: {:?}", asym);
                println!("Shared symmetric secret key is compromised ?: {:?}", sym);
                println!("Dos attack is being conducted ?: {:?}\n", dos);

                if dos {
                    println!("Dos attack detected! Blocking client...");

                    // Get client IP Address
                    let client_ip = stream_copy_2.peer_addr().unwrap().ip();

                    // Add client to Block map
                    let mut block_map_guard = block_map.lock().unwrap();
                    block_map_guard.entry(client_ip).or_insert(SystemTime::now());
                    drop(block_map_guard);

                    // Sleep thread to unblock client later
                    println!("Client blocked!");
                    thread::sleep(BLOCK_DURATION);
                    println!("Block duration end... Unblocking client...");

                    // Remove expired block record
                    block_map_guard = block_map.lock().unwrap();
                    block_map_guard.remove(&client_ip);
                    println!("Client unblocked!\n");
                }

            }

            println!("Result of NIZK Proof of client {} is: {}\n", CLIENT_ID ,result);
        },

        // Session Key (NIZK Mut Auth)
        2 => {
            // Verify proof and send own proof
            println!("\nVerifying NIZK Mutual Auth of client: {}", CLIENT_ID);
            let (mut nizk_ins, (commitment, challenge, response)) = schnorr_nizk::NIZKMutAuth::new(MY_ID, CLIENT_ID, Some((data.value_1, data.value_2.unwrap(), data.value_3.unwrap())));
            let verify = nizk_ins.verify_proof();
            println!("Server verified NIZK mutual auth proof of client, result = {:?}\n", verify);

            // Send proof
            let data_to_send = DataExchange {
                auth_type: 2,
                request_type: 0,
                message: None,
                value_1: commitment,
                value_2: Some(challenge),
                value_3: Some(response),
            };
            let json_string = serde_json::to_string(&data_to_send).unwrap();

            // Send data
            println!("Sending proof of server:");
            stream_copy.write_all(json_string.as_bytes()).expect("write failed");
            stream_copy.write_all(b"\n").expect("Failed to write to server");
            println!("Proof sent!");

            // Calculate session key
            let s_key = nizk_ins.calculate_session_key();
            println!("Server calculated session key as: {:?}\n", s_key);
        }

        // Generate new keys and Exchange Public Keys
        11 => {
            let desc_pub = format!("PublicKey:{}", CLIENT_ID);
            let mut client_key_pub = schnorr_nizk::get_key_instance(&desc_pub, 32, Some(data.value_1.to_vec())).unwrap();
            client_key_pub.update_key_in_ring(data.value_1.to_vec());

            // Generate own public private key pairs
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

            // Send data
            stream_copy.write_all(json_string.as_bytes()).expect("write failed");
            stream_copy.write_all(b"\n").expect("Failed to write to server");
            println!("Public key sent!");
        }

        // For testing the speed of nizk proof. It has less checks and no prints and extra response
        123 => {
            // Verify proof
            let result = schnorr_nizk::verify_nizk_proof(MY_ID,
                                                         CLIENT_ID,
                                                         data.message.unwrap(),
                                                         (data.value_1, data.value_2.unwrap(), data.value_3.unwrap()),
                                                         true);

            // Send response
            stream_copy.write_all("verified".as_bytes()).expect("write failed");
            stream_copy.write_all(b"\n").expect("Failed to write to server");
        },

        _ => {

        },
    }
}

// Main function of the TCP Server
fn main() {
    // Init intrusion data
    schnorr_nizk::init_intrusion_counters(CLIENT_ID);
    println!("\nReset intrusion values since server is restarted!\n");

    // Random port, just for the example
    // 192.168.0.21 for inside wlan and 127.0.0.1 for local computer
    // 192.168.0.196 My RP
    let listener = TcpListener::bind(SERVER_ADDRESS).expect("could not start server");

    // Maintain a map of blocked client IP addresses and their block start times
    let block_map: Arc<Mutex<HashMap<IpAddr, SystemTime>>> = Arc::new(Mutex::new(HashMap::new()));

    // Accept incoming connections and get a TcpStream
    for connection in listener.incoming() {
        match connection {
            Ok(stream) => {
                println!("Received a connection from Client IP: {:?}", stream.peer_addr().unwrap());

                // Check if client is blocked from Doing and ignore them if true
                let block_map_clone = block_map.clone();
                let block_map_clone_2 = block_map.clone();
                let mut stream_copy = stream.try_clone().expect("Failed to clone stream\n");
                let client_ip = stream_copy.peer_addr().unwrap().ip();

                let mut block_map_guard = block_map_clone_2.lock().unwrap();
                if let Some(block_start_time) = block_map_guard.get(&client_ip) {
                    if block_start_time.elapsed().unwrap() < BLOCK_DURATION {
                        println!("Client IP is blocked from making new connections, waiting until unlocked...");

                        // Continue to next iteration of loop to ignore the current request
                        continue;
                    } else {
                        // Remove expired block record
                        block_map_guard.remove(&client_ip);
                    }
                }

                // Handle connexion
                thread::spawn(|| {
                    handle_connection(stream, block_map_clone);
                });
            }
            Err(e) => {
                print!("Connection failed! {}\n", e);
            }
        }
    }
}
