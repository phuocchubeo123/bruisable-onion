use base64::{engine::general_purpose::STANDARD, Engine};
use bruise_onion::tulip::{tulip_encrypt, process_tulip, tulip_receive};
use rsa::{pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPrivateKey, EncodeRsaPublicKey, LineEnding}, sha2::Sha256, Oaep, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use rand::rngs::OsRng;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use bruise_onion::crypto::{read_pubkey_list, read_seckey_list, generate_pubkey};
use std::thread;
use std::time::Duration;

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
fn test_tulip() {
    // Read the public keys from the files (this is your existing code)
    // let n = 6;
    // let (ids, create_seckeys, create_pubkeys) = generate_pubkey_list(n);

    // match dump_pubkey_list(&ids, &create_pubkeys, "PKKeys.txt") {
    //     Ok(_) => println!("Successfully written pseudo keys to PKKeys.txt!"),
    //     Err(e) => eprintln!("Failed to write to PKKeys.txt: {}", e),
    // };

    // match dump_seckey_list(&ids, &create_seckeys, "SKKeys.txt") {
    //     Ok(_) => println!("Successfully written secret keys of intermediate nodes to SKKeys.txt!"),
    //     Err(e) => eprintln!("Failed to write to SKKeys.txt: {}", e),
    // }

    // println!("Sleeping for 1 second...");
    // thread::sleep(Duration::from_secs(1));
    // println!("Woke up after 1 second!");

    let (server_ids, server_pubkeys) = read_pubkey_list("PKKeys.txt").expect("Failed to read server public keys from PKKeys.txt");
    let server_nodes = Arc::new(Mutex::new(
        server_ids.clone().into_iter().zip(server_pubkeys.clone().into_iter()).collect::<HashMap<String, RsaPublicKey>>(),
    ));
    let server_pubkeys_map = server_ids.clone().into_iter().zip(server_pubkeys.into_iter()).collect::<HashMap<String, RsaPublicKey>>();
    println!("Loaded server public keys from PKKeys.txt");

    let (server_ids_2, server_seckeys) = read_seckey_list("SKKeys.txt").expect("Failed to read server secret keys from SKKeys.txt");
    let server_seckeys_map = server_ids.clone().into_iter().zip(server_seckeys.into_iter()) .collect::<HashMap<String, RsaPrivateKey>>();
    println!("Loaded server secret keys from SKKeys.txt");

    // I will just sample a new user myself, so I do not need to store another list of users privkeys
    let recipient_id = "eileen";
    let (recipient_seckey, recipient_pubkey) = generate_pubkey().expect("Cannot generate new keys for user.");

    // Prepare server keys
    let num_mixers = 4;
    let num_gatekeepers = 3;
    let server_nodes_locked = server_nodes.lock().unwrap();
    let mixers: Vec<(&str, &RsaPublicKey)> = server_nodes_locked.iter().take(num_mixers).map(|(id, pubkey)| (id.as_str(), pubkey)).collect();
    let gatekeepers: Vec<(&str, &RsaPublicKey)> = server_nodes_locked.iter().skip(num_mixers).take(num_gatekeepers).map(|(id, pubkey)| (id.as_str(), pubkey)).collect();

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

    assert!(result.is_ok(), "tulip_encrypt failed: {:?}", result);
    let tulip = result.unwrap();

    println!("Done encrypting tulip!");

    let first_node= mixers[0].0;

    let tulip_result = process_tulip(&tulip, first_node, &server_seckeys_map);
    assert!(tulip_result.is_ok(), "processing tulip failed: {:?}", tulip_result);

    let (recipient, current_tulip) = tulip_result.unwrap();
    assert!(recipient == recipient_id.to_string(), "not the intended recipient!");

    let message_result = tulip_receive(&current_tulip, &recipient_seckey);
    assert!(message_result.is_ok(), "Receiving tulip failed: {:?}", message_result);
    
    let received_message = message_result.unwrap();
    println!("The received message is: {}", received_message);
    assert!(received_message == message.to_string());
}
