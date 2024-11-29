use base64::{engine::general_purpose::STANDARD, Engine};
use bruise_onion::tulip::{tulip_decrypt, tulip_encrypt};
use rsa::{pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPrivateKey, EncodeRsaPublicKey, LineEnding}, sha2::Sha256, Oaep, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use rand::rngs::OsRng;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use bruise_onion::crypto::{generate_pubkey_list, dump_pubkey_list, dump_seckey_list, read_pubkey_list, read_seckey_list};
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
fn test_tulip_encrypt_output_format() {
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
        server_ids.clone().into_iter().zip(server_pubkeys.into_iter()).collect::<HashMap<String, RsaPublicKey>>(),
    ));
    println!("Loaded server public keys from PKKeys.txt");

    let (server_ids_2, server_seckeys) = read_seckey_list("SKKeys.txt").expect("Failed to read server secret keys from SKKeys.txt");
    let server_seckeys_map = server_ids.clone().into_iter().zip(server_seckeys.into_iter()) .collect::<HashMap<String, RsaPrivateKey>>();
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

    assert!(result.is_ok(), "tulip_encrypt failed: {:?}", result);
    let mut tulip = result.unwrap();

    println!("Done encrypting tulip!");

    for mixer_index in 0..3 {
        let mixer_id = mixers[mixer_index].0;
        let mixer_seckey = server_seckeys_map.get(mixer_id).unwrap();

        println!("Trying to test mixer id {}", mixer_id);

        let mut bruise = false;
        if mixer_index == 0 {
            bruise = true;
        }
        let result_decrypt = tulip_decrypt(&tulip, mixer_id, &mixer_seckey, bruise);

        assert!(result_decrypt.is_ok(), "tulip_decrypt failed: {:?}", result_decrypt);

        let (next_id, next_tulip) = result_decrypt.unwrap();
        tulip = next_tulip;

        println!("The next node in the path is {}", next_id);
    }

    for gatekeeper_index in 0..1 {
        let gatekeeper_id = gatekeepers[gatekeeper_index].0;
        let gatekeeper_seckey = server_seckeys_map.get(gatekeeper_id).unwrap();

        println!("Trying to test gatekeeper id {}", gatekeeper_id);

        let result_decrypt = tulip_decrypt(&tulip, gatekeeper_id, &gatekeeper_seckey, false);

        assert!(result_decrypt.is_ok(), "tulip_decrypt failed: {:?}", result_decrypt);

        let (next_id, next_tulip) = result_decrypt.unwrap();
        tulip = next_tulip;

        println!("The next node in the path is {}", next_id);
    }

    let last_gatekeeper = gatekeepers[gatekeepers.len()-1].0;
    let last_gatekeeper_seckey = server_seckeys_map.get(last_gatekeeper).unwrap();

    println!("Trying to test gatekeeper id {}", last_gatekeeper);

    let result_decrypt = tulip_decrypt(&tulip, last_gatekeeper, &last_gatekeeper_seckey, false);

    assert!(result_decrypt.is_ok(), "tulip_decrypt failed: {:?}", result_decrypt);

    let (recipient, next_tulip) = result_decrypt.unwrap();
    tulip = next_tulip;

    println!("The next node in the path is {}", recipient);

    

}
