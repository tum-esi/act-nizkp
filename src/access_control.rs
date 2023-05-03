use std::fs::{File, OpenOptions, Permissions};
use std::io::{BufReader, BufWriter, Write};
use std::io::prelude::*;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use serde::{Deserialize, Serialize};
use serde_json::{Result, Value};
use hex;

#[derive(Debug, Serialize, Deserialize)]
struct ActionsControl {
    actionName: Vec<u8>,
    allowedDevices: Vec<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
struct AccessControl {
    resourceID: u32,
    actions: Vec<ActionsControl>,
}

// File path of the data control detection data
fn get_json_file_path(resourceID: u32) -> String {
    format!(".nizk-auth/access_control/resource_{}.json", resourceID)
}

// Set the file permissions to 0o600, so that only the user can write to it
fn shrink_file_permissions(path: String) {
    let mut perms = Permissions::from_mode(0o600);
    std::fs::set_permissions(&path, perms).expect("Failed to set file permissions");
}

// Create all parent directories for the file
fn create_parent_dirs(file_path: String) {
    let path = Path::new(&file_path);

    // Create parent directories if they don't already exist
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            if let Err(err) = std::fs::create_dir_all(parent) {
                eprintln!("Failed to create parent directories: {}", err);
            }
        }
    }
}

// Create a new Resource
pub fn add_resource(resourceID: u32, actions: Option<Vec<Vec<u8>>>) -> u8 {
    // Get resource file path
    let file_path = get_json_file_path(resourceID);
    let path = Path::new(&file_path);

    // Check if resource already exists
    if path.exists() {
        println!("ResourceID: {:?} already exists, try to delete it first!\n", resourceID);
        return 1;
    }

    // Save Data in AccessControl struct
    let access = match actions {
        // Check if user included actions or not
        Some(all_actions) => {
            // User added actions list, convert it into ActionsStruct
            let mut actions_vec: Vec<ActionsControl> = Vec::new();
            for actionName in all_actions {
                let action = ActionsControl {
                    actionName,
                    allowedDevices: Vec::new(),
                };
                actions_vec.push(action);
            }

            // Generate AccessControl Struct
            AccessControl {
                resourceID,
                actions: actions_vec,
            }
        },

        // User did not include actions -> Create empty AccessControl struct
        None => {
            AccessControl {
                resourceID,
                actions: Vec::new(),
            }
        }
    };

    // Convert struct to a JSON
    let json_string = serde_json::to_string(&access).unwrap();
    println!("Serialized JSON string: {}", json_string);

    // Create parent directories if they does not exist
    let file_path = get_json_file_path(resourceID);
    create_parent_dirs(file_path);

    // Create File with json content
    let file_path = get_json_file_path(resourceID);
    let path = Path::new(&file_path);
    let mut file = File::create(&path).unwrap();
    file.write_all(json_string.as_bytes());

    // Shrink file permissions
    let file_path = get_json_file_path(resourceID);
    shrink_file_permissions(file_path);

    // Return success
    return 0;
}

// Delete a resource from resources list
pub fn remove_resource(resourceID: u32) -> u8 {
    // Check if resource already exists
    let file_path = get_json_file_path(resourceID);
    let path = Path::new(&file_path);
    if path.exists() {
        // Path exists, delete path
        let file_path = get_json_file_path(resourceID);
        match fs::remove_file(file_path) {
            Ok(_) => {
                return 0;
            },
            Err(e) => {
                // Return exit code 2 since file could not be deleted
                println!("Error deleting resource: {}", e);
                return 2;
            },
        }
    }else {
        // Return 1 because resource does not exist
        return 1;
    }
}

// Read data from a saved json file
fn read_access_data(resourceID: u32) -> AccessControl {
    // Open file and read content as AccessControl struct
    let file_path = get_json_file_path(resourceID);
    let path = Path::new(&file_path);
    let file = File::open(&path).unwrap();
    let reader = BufReader::new(file);
    let mut access: AccessControl = serde_json::from_reader(reader).unwrap();
    access
}

// Add a new allowed action to a certain resource
pub fn add_action_to_resource(resourceID: u32, actionName: Vec<u8>) -> u8 {
    // Read access control data for the provided resource ID
    let mut accessData = read_access_data(resourceID);

    // Go through all action in the access control data and find if action already exists
    for (index, action) in accessData.actions.iter().enumerate() {
        if action.actionName == actionName {
            // Action exists
            println!("Action already exists for resource {:?}. Please delete it first to continue.\n", resourceID);
            return 1;
        }
    }

    // Create a struct for the action name
    let action = ActionsControl {
        actionName,
        allowedDevices: Vec::new(),
    };

    // Append the new action to the actions list
    accessData.actions.push(action);

    // Convert to String and write it to file
    let file_path = get_json_file_path(resourceID);
    let path = Path::new(&file_path);
    let json_string = serde_json::to_string(&accessData).unwrap();
    let mut file = File::create(&path).unwrap();
    file.write_all(json_string.as_bytes());

    return 0;
}

// Remove an action from a resource
pub fn remove_action_from_resource(resourceID: u32, actionName: Vec<u8>) -> u8 {
    // Read access control data for the provided resource ID
    let mut accessData = read_access_data(resourceID);

    // Go through all action in the access control data and find if an action matches
    for (index, action) in accessData.actions.iter().enumerate() {
        if action.actionName == actionName {
            // Remove action and break from loop
            accessData.actions.remove(index);
            return 0;
        }
    }

    // Action not removed because it does not exist
    return 1;
}

// Add a device to an action of a resource
pub fn add_device_to_resource_action(resourceID: u32, actionName: Vec<u8>, deviceID: u32) -> u8 {
    // Read access control data for the provided resource ID
    let mut accessData = read_access_data(resourceID);

    // Go through all action in the access control data and find if an action matches
    for (index, action) in accessData.actions.iter().enumerate() {
        if action.actionName == actionName {
            // Add user to the allowed users for this action
            accessData.actions[index].allowedDevices.push(deviceID);
            return 0;
        }
    }

    // Action not found, return 1.
    return 1;
}

pub fn remove_device_from_resource_action(resourceID: u32, actionName: Vec<u8>, deviceID: u32) -> u8 {
    // Read access control data for the provided resource ID
    let mut accessData = read_access_data(resourceID);

    // Go through all action in the access control data and find if an action matches
    for (index, action) in accessData.actions.iter().enumerate() {
        if action.actionName == actionName {
            // Remove user from the allowed users for this action
            for (user_index, userID) in action.allowedDevices.iter().enumerate(){
                if *userID == deviceID {
                    accessData.actions[index].allowedDevices.remove(user_index);
                    return 0;
                }
            }
            // User already not allowed to use that resource
            return 2;
        }
    }

    // Action not found, return 1
    return 1;
}

// Check if a device has access to an action for a certain resource
pub fn check_access(resourceID: u32, actionName: Vec<u8>, deviceID: u32) -> bool {
    // Read access control data for the provided resource ID
    let mut accessData = read_access_data(resourceID);

    // Go through all action in the access control data and find if an action matches
    for (index, action) in accessData.actions.iter().enumerate() {
        if action.actionName == actionName {
            // Action found. Check if user is allowed to use this action
            for (user_index, userID) in action.allowedDevices.iter().enumerate(){
                if *userID == deviceID {
                    return true;
                }
            }
            // User not allowed to use that resource
            return false;
        }
    }

    // Action does not exist
    return false;
}
