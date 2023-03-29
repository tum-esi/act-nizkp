mod secret_management;
mod schnorr_identification;


// Return an instance of MyKey of the key corresponding to the key description
pub fn get_key_instance(key_description: &str) -> Result<secret_management::MyKey, secret_management::SecretKeyErrors> {
    let my_key = secret_management::MyKey::new(key_description, 32);
    my_key
}
