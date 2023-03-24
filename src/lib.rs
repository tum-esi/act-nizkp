mod key_management;

pub fn generate_secret_key(username: &str) {
    let my_key = key_management::MyKey::new(username, 32).unwrap();
    let key = my_key.get_key();
    println!("The secret Key is: {:?}", key);
}
