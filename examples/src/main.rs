use std::borrow::BorrowMut;
use std::fmt::format;
use schnorr_nizk;
use chrono::prelude::*;
use std::time::{Instant};

fn main() {
    // ID's of A and B
    let AID: u32 = 10000;
    let BID: u32 = 20000;
    let iterations = 5000;

    /*
    ************************************************************************************************
    ********************** Generate Key Pair For A and B for Testing Purposes **********************
    ************************************************************************************************
    */
    // Run this one time to have a key pair for A and for B

    // Generate A's Key Pair
    // Update keys in case old keys already exists
    let (pub_kA, priv_kA) = schnorr_nizk::gen_random_key_pair();
    println!("my pub key = {:?}\nmy priv key = {:?}\n", pub_kA, priv_kA);

    let desc = format!("PublicKey:{}", AID);
    let mut my_key = schnorr_nizk::get_key_instance(&desc, 32,Some(Vec::from(pub_kA))).unwrap();
    my_key.update_key_in_ring(Vec::from(pub_kA));

    let desc = format!("PrivateKey:{}", AID);
    let mut my_key = schnorr_nizk::get_key_instance(&desc, 32,Some(Vec::from(priv_kA))).unwrap();
    my_key.update_key_in_ring(Vec::from(priv_kA));

    // Generate B's Key Pair
    let (pub_kB, priv_kB) = schnorr_nizk::gen_random_key_pair();
    println!("Server pub key = {:?}\nServer priv key = {:?}\n", pub_kB, priv_kB);

    let desc = format!("PublicKey:{}", BID);
    let mut my_key = schnorr_nizk::get_key_instance(&desc, 32, Some(Vec::from(pub_kB))).unwrap();
    my_key.update_key_in_ring(Vec::from(pub_kB));

    let desc = format!("PrivateKey:{}", BID);
    let mut my_key = schnorr_nizk::get_key_instance(&desc, 32, Some(Vec::from(priv_kB))).unwrap();
    my_key.update_key_in_ring(Vec::from(priv_kB));

    /*
    ************************************************************************************************
    ***************************** End Generating Key Pair For A and B ******************************
    ************************************************************************************************
    */


    /*
    ************************************************************************************************
    ********************************* Interactive Mutual Auth Test *********************************
    ************************************************************************************************
    */
    println!("\nBegin of interactive mutual auth tests for generating a shared secret key:\n");

    // Save different measures inside a Vec
    let mut all_measurements: Vec<f32> = Vec::new();
    let mut accepted_1 = false;
    let mut accepted_2 = false;

    for i in 0..iterations {
        // Measure duration of each one
        let start = Instant::now();

        // Init A instance and get values to send
        let mut a_int_auth = schnorr_nizk::get_int_mut_auth_instance(AID,BID, schnorr_nizk::CONST_INITIATOR_ROLE);
        let (Acommitment, _, Areq_type) = a_int_auth.gen_next_values();

        // Init B's instance, add received values, and generate values to send
        let mut b_int_auth = schnorr_nizk::get_int_mut_auth_instance(BID,AID, schnorr_nizk::CONST_RECEIVER_ROLE);
        let _ = b_int_auth.add_recipient_values(Areq_type, Acommitment, None);
        let (Bcommitment, Bchallenge, Breq_type) = b_int_auth.gen_next_values();

        // Add received values and generate next values to send
        let _ = a_int_auth.add_recipient_values(Breq_type, Bcommitment, Bchallenge);
        let (Achallenge, Aresponse, Areq_type) = a_int_auth.gen_next_values();

        // Add A's response and Generate own response to send
        let _ = b_int_auth.add_recipient_values(Areq_type, Achallenge, Aresponse);
        let (Bresponse, _, Breq_type) = b_int_auth.gen_next_values();

        // Add received values and verify proof
        let _ = a_int_auth.add_recipient_values(Breq_type, Bresponse, None);
        let a_accepted = a_int_auth.verify_proof();

        // Calculate Duration
        let duration = (start.elapsed().as_secs_f32()) * 1_000.0;
        all_measurements.push(duration);

        // Verify proof of A
        // This is not included in the duration, since it's supposed to be done simultaneously
        let b_accepted = b_int_auth.verify_proof();

        if i == iterations - 1 {
            accepted_1 = a_accepted;
            accepted_2 = b_accepted;
        }
    }

    // Calculate the average run duration
    println!("All measured values:\n{:?}\n", all_measurements);
    let sum: f32 = all_measurements.iter().sum();
    let avg = sum / all_measurements.len() as f32;
    println!("The average execution time is: {}ms\n", avg);
    println!("Result of last verify proofs: {}, {}\n", accepted_1, accepted_2);

    println!("End of Mutual Auth \n\n");
    /*
    ************************************************************************************************
    ******************************* End Interactive Mutual Auth Test *******************************
    ************************************************************************************************
    */

    /*
    ************************************************************************************************
    **************************************** Test NIZK Proof ***************************************
    ************************************************************************************************
    */
    println!("Start NIZK Proof Tests:\n");

    // Save different measures inside a Vec
    let mut all_measurements_gen: Vec<f32> = Vec::new();
    let mut all_measurements_ver: Vec<f32> = Vec::new();
    let mut res = false;

    // Make multiple probes
    for i in 0..iterations {
        /*
        // Display shared key:
        let desciption = format!("SharedSecretKey:{}:{}",AID, BID);
        let mut mykey = schnorr_nizk::get_key_instance(&desciption, 32, None).unwrap();
        println!("Shared key of A: {:?}\n", mykey.get_key());
        let desciption = format!("SharedSecretKey:{}:{}",BID, AID);
        let mut mykey = schnorr_nizk::get_key_instance(&desciption, 32,None).unwrap();
        println!("Shared key of B: {:?}\n", mykey.get_key());

        // Display shared counters
        let desciption = format!("SharedCounter:{}:{}",AID, BID);
        let mut mykey = schnorr_nizk::get_key_instance(&desciption, 32, None).unwrap();
        println!("Shared key of A: {:?}\n", mykey.get_key());
        let desciption = format!("SharedCounter:{}:{}",BID, AID);
        let mut mykey = schnorr_nizk::get_key_instance(&desciption, 32,None).unwrap();
        println!("Shared key of B: {:?}\n", mykey.get_key());
        */

        // Message to be send
        let m = format!("NIZK AUTH message of {:?}", AID);

        // Measure duration of each one
        let start = Instant::now();

        // Generate proof
        let proof = schnorr_nizk::gen_nizk_proof(AID, BID, m, true);

        // Calculate Duration
        let duration = (start.elapsed().as_secs_f32()) * 1_000.0;
        all_measurements_gen.push(duration);

        // Received String
        let m = format!("NIZK AUTH message of {:?}", AID);

        // Measure duration of each one
        let start = Instant::now();

        // Verify NIZK proof
        let result = schnorr_nizk::verify_nizk_proof(BID, AID, m, proof, true);
        let duration = (start.elapsed().as_secs_f32()) * 1_000.0;
        all_measurements_ver.push(duration);

        if i == iterations - 1 {
            res = result;
        }
    }

    // Calculate the average run duration
    println!("All measured values of gen proof:\n{:?}\n", all_measurements_gen);
    let sum: f32 = all_measurements_gen.iter().sum();
    let avg1 = sum / all_measurements_gen.len() as f32;
    println!("The average execution time of generating NIZK proof is: {}ms\n", avg1);

    println!("All measured values of verify proof:\n{:?}\n", all_measurements_ver);
    let sum: f32 = all_measurements_ver.iter().sum();
    let avg2 = sum / all_measurements_ver.len() as f32;
    println!("The average execution time of verifying NIZK proof is: {}ms\n", avg2);
    println!("The average execution time of generating and verifying NIZK proof is: {}ms\n", (avg1 + avg2) as f32);
    println!("Result of last proof is: {:?}\n", res);

    println!("End of NIZK Auth \n\n");

    /*
    ************************************************************************************************
    ************************************** End Test NIZK Proof *************************************
    ************************************************************************************************
    */


    /*
    ************************************************************************************************
    ************************************ Test Mutual NIZK Auth *************************************
    ************************************************************************************************
    */
    println!("Starting non-interactive mutual auth test:\n");

    // Save different measures inside a Vec
    let mut all_measurements: Vec<f32> = Vec::new();
    let mut accepted_1 = false;
    let mut accepted_2 = false;
    let mut same_skey = false;

    for i in 0..iterations {
        // Measure duration of each one
        let start = Instant::now();

        // Generate proof of A
        let (mut nizk_a, proof_a) = schnorr_nizk::NIZKMutAuth::new(AID, BID, None);

        // Add proof of A and Generate proof of B
        let (mut nizk_b, proof_b) = schnorr_nizk::NIZKMutAuth::new(BID, AID, Some(proof_a));

        // Add proof of B to A's Data and verify B's proof and generate session key
        nizk_a.add_recipient_values(proof_b);
        let verify_b = nizk_a.verify_proof();
        let ska = nizk_a.calculate_session_key();

        // Calculate duration
        let duration = (start.elapsed().as_secs_f32()) * 1_000.0;
        all_measurements.push(duration);

        // This is not part of the duration because it's supposed to run simultaneously
        let verify_a = nizk_b.verify_proof();
        let skb = nizk_b.calculate_session_key();

        if i == iterations - 1 {
            same_skey = (ska == skb);
            accepted_1 = verify_b;
            accepted_2 = verify_a;
        }
    }

    println!("All measured values:\n{:?}\n", all_measurements);
    let sum: f32 = all_measurements.iter().sum();
    let avg = sum / all_measurements.len() as f32;
    println!("The average execution time is: {}ms\n", avg);
    println!("Result of last verifications = {:?}, {:?}\n", accepted_1, accepted_2);
    println!("A and B Calculated same session key? = {:?}\n", same_skey);

    println!("End of NIZK Mutual Auth \n\n");

    /*
    ************************************************************************************************
    ********************************** End Test Mutual NIZK Auth ***********************************
    ************************************************************************************************
    */

    /*
    ************************************************************************************************
    ****************** Test of Intrusion Detection/Prevention and Access Control *******************
    ************************************************************************************************
    */
    // Test intrusion detection system
    println!("Start intrusion test:");
    let m = format!("NIZK AUTH message of {:?}", AID);
    let result = schnorr_nizk::verify_nizk_proof(BID, AID, m, ([0u8; 32], [1u8; 32], [2u8; 32]), true);

    println!("Check if a key is compromised:");

    // Get Intrusion Values
    let (asym, sym, dos) = schnorr_nizk::check_intrusion(AID);
    println!("asym key is compromised ?: {:?}", asym);
    println!("sym key is compromised ?: {:?}", sym);
    println!("Dos attack being conducted ?: {:?}\n", dos);

    // Test Access Management system
    // Test resource creation
    let resource_id: u32 = 12345;
    println!("Creating a resource with ID {:?}", resource_id);
    let resp = schnorr_nizk::access_control::add_resource(resource_id, None);
    println!("received response code {}\n", resp);

    // Delete a resource
    println!("Deleting resource with ID {:?}", resource_id);
    let resp = schnorr_nizk::access_control::remove_resource(resource_id);
    println!("received response code {}\n", resp);

    // Create resource with actions
    println!("Recreating resource with ID {:?}", resource_id);
    let mut actions: Vec<Vec<u8>> = Vec::new();
    actions.push(String::from("POST").into_bytes());
    actions.push(String::from("GET").into_bytes());
    actions.push(String::from("SET").into_bytes());
    let resp = schnorr_nizk::access_control::add_resource(resource_id, Some(actions));
    println!("received response code {}\n", resp);

    // Add a new action
    println!("Adding a new action to resource with ID {:?}", resource_id);
    let resp = schnorr_nizk::access_control::add_action_to_resource(resource_id, String::from("DEL").into_bytes());
    println!("received response code {}\n", resp);

    // Add a new action
    println!("Deleting an action to resource with ID {:?}", resource_id);
    let resp = schnorr_nizk::access_control::remove_action_from_resource(resource_id, String::from("POST").into_bytes());
    println!("received response code {}\n", resp);

    // Add device ID to all actions
    println!("Adding device {} to all actions of resource with ID {:?}", AID, resource_id);
    let resp = schnorr_nizk::access_control::add_device_to_all_actions(resource_id, AID);
    println!("received response code {}\n", resp);

    println!("Adding device {} to all actions of resource with ID {:?}", BID, resource_id);
    let resp = schnorr_nizk::access_control::add_device_to_all_actions(resource_id, BID);
    println!("received response code {}\n", resp);

    // Removing device form actions
    println!("Removing device {} from all actions of resource with ID {:?}", AID, resource_id);
    let resp = schnorr_nizk::access_control::remove_device_from_all_actions(resource_id, AID);
    println!("received response code {}\n", resp);

    println!("Removing device {} from last action of resource with ID {:?}", BID, resource_id);
    let resp = schnorr_nizk::access_control::remove_device_from_resource_action(resource_id, String::from("DEL").into_bytes(), BID);
    println!("received response code {}\n", resp);

    // Check access of a device to a resource
    println!("Check if device {} is allowed to access an action of resource with ID {:?}.\nexpected response: false.", AID, resource_id);
    let resp = schnorr_nizk::access_control::check_access(resource_id, String::from("DEL").into_bytes(), AID);
    println!("received response: {}\n", resp);

    println!("Check if device {} is allowed to access an action of resource with ID {:?}.\nexpected response: true.", BID, resource_id);
    let resp = schnorr_nizk::access_control::check_access(resource_id, String::from("GET").into_bytes(), BID);
    println!("received response {}\n", resp);

    /*
    ************************************************************************************************
    *************** End of Test of Intrusion Detection/Prevention and Access Control ***************
    ************************************************************************************************
    */
}
