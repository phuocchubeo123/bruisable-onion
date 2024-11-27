use base64::{engine::general_purpose::STANDARD, Engine};
use bruise_onion::tulip::{tulip_decrypt, tulip_encrypt};
use rsa::{pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPrivateKey, EncodeRsaPublicKey, LineEnding}, sha2::Sha256, Oaep, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use rand::rngs::OsRng;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use bruise_onion::crypto::{read_pubkey_list, read_seckey_list};

fn generate_test_keys() -> (RsaPrivateKey, RsaPublicKey) {
    let mut rng = OsRng;
    let priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("Failed to generate private key");
    let pub_key = RsaPublicKey::from(&priv_key);
    (priv_key, pub_key)
}

fn generate_test_nonces(num_layers: usize) -> Vec<[u8; 12]> {
    vec![[0u8; 12]; num_layers]
}


#[test]
fn test_tulip_encrypt_output_format() {
    // Read the public keys from the files (this is your existing code)
    let (server_ids, server_pubkeys) = read_pubkey_list("PKKeys.txt").expect("Failed to read server public keys from PKKeys.txt");
    let server_nodes = Arc::new(Mutex::new(
        server_ids.into_iter().zip(server_pubkeys.into_iter()).collect::<HashMap<String, RsaPublicKey>>(),
    ));

    println!("Loaded server public keys from PKKeys.txt");

    let (server_ids_2, server_seckeys) = read_seckey_list("SKKeys.txt").expect("Failed to read server secret keys from SKKeys.txt");
    println!("Loaded server secret keys from SKKeys.txt");

    let (usernames, user_pubkeys) = read_pubkey_list("UserKeys.txt").expect("Failed to read user public keys from UserKeys.txt");
    let existing_users = Arc::new(Mutex::new(
        usernames.into_iter().zip(user_pubkeys.into_iter()).collect::<HashMap<String, RsaPublicKey>>(),
    ));

    println!("Loaded existing user public keys from UserKeys.txt");

    // Let's get a recipient key from the existing users (for example, "eileen")
    let recipient_id = "eileen";
    let recipient_pubkey = existing_users.lock().unwrap().get(recipient_id).expect("Recipient key not found").clone();

    // Prepare server keys
    let server_nodes_locked = server_nodes.lock().unwrap();
    let mixers: Vec<(&str, &RsaPublicKey)> = server_nodes_locked.iter().take(3).map(|(id, pubkey)| (id.as_str(), pubkey)).collect();
    let gatekeepers: Vec<(&str, &RsaPublicKey)> = server_nodes_locked.iter().skip(3).take(2).map(|(id, pubkey)| (id.as_str(), pubkey)).collect();

    // Prepare nonces and max_bruise
    let y = generate_test_nonces(mixers.len() + gatekeepers.len());
    let max_bruise = 2;

    // Now, call tulip_encrypt with the data loaded from the files
    let message = "Hello, Onion!";
    let result = tulip_encrypt(
        message,
        &recipient_pubkey,
        recipient_id,
        &mixers[..],  // Pass a slice of mixers
        &gatekeepers[..],  // Pass a slice of gatekeepers
        &y.iter().collect::<Vec<&[u8; 12]>>(),
        &max_bruise,
    );

    println!("Result: {:?}", result);

    assert!(result.is_ok(), "tulip_encrypt failed: {:?}", result);
    let encrypted_tulip = result.unwrap();
    assert!(encrypted_tulip.contains("|"), "Encrypted onion missing separators");

    println!("Done encrypting tulip!");

    // First mixer
    let (mixer_id, mixer_pubkey) = mixers[0];
    let mixer_seckey = server_seckeys[0].clone();

    let pubkey_pem = mixer_pubkey.to_pkcs1_pem(LineEnding::LF).expect("failed to encode public key to PEM");
    println!("Curent pubkey: {}", pubkey_pem);

    let seckey_pem = mixer_seckey.to_pkcs1_pem(LineEnding::LF).expect("failed to encode private key to PEM");
    println!("Current seckey: {}", *seckey_pem);

    println!("Trying to test the first mixer...");

    let result_decrypt = tulip_decrypt(&encrypted_tulip, mixer_id, &mixer_seckey);

    println!("Tulip Decrypt result: {:?}", result_decrypt);


    let mut rng = OsRng; 
    let test_msg = "Hello World";

    let dummy_privkey = RsaPrivateKey::new(&mut rng, 2048).expect("Failed to generate a private key");
    let dummy_pubkey = RsaPublicKey::from(&dummy_privkey);
    let u1 = dummy_pubkey.encrypt(&mut rng, Pkcs1v15Encrypt, test_msg.as_bytes()).expect("Failed to encrypt Hello World!");
    println!("Encrypted Hello World: {}", STANDARD.encode(&u1));
    let u2 = dummy_privkey.decrypt(Pkcs1v15Encrypt, &u1).expect("Failed to decrypt Hello World!"); 
    println!("Decrypted Hello World: {}", STANDARD.encode(&u2));



}
