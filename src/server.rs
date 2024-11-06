extern crate rsa;
mod crypto;

use crypto::{generate_pubkey_list, dump_pubkey_list, reset_user_list, update_user_list};
use rsa::{RsaPublicKey, pkcs1::DecodeRsaPublicKey, RsaPrivateKey, Pkcs1v15Encrypt};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::thread;
use aes_gcm::{Aes256Gcm, Key, Nonce}; 
use aes_gcm::aead::{Aead, NewAead};
use rand::Rng;
use base64::engine::general_purpose;
use base64::Engine;

fn handle_client(
    mut stream: TcpStream,
    clients: Arc<Mutex<HashMap<String, TcpStream>>>,
    existing_users: Arc<Mutex<HashMap<String, RsaPublicKey>>>,
    seckeys: Arc<Mutex<HashMap<usize, RsaPrivateKey>>>, // Server's private keys for decryption
) {
    let mut buffer = [0; 512];

    // Step 1: Receive and store the username for this client
    stream.read(&mut buffer).unwrap();
    let username_and_pem = String::from_utf8_lossy(&buffer[..])
        .trim_matches(char::from(0))
        .trim()
        .to_string();
    
    let mut lines = username_and_pem.lines();
    let username = lines.next().unwrap().to_string();
    let pem = lines.collect::<Vec<&str>>().join("\n");
    let pubkey = RsaPublicKey::from_pkcs1_pem(&pem).expect("Failed to parse public key from PEM");

    println!("User '{}' connected.", username);

    // Add user to the list
    match update_user_list("UserKeys.txt", &username, &pubkey) {
        Ok(_) => println!("Added user to list of existing users!"),
        Err(e) => eprintln!("Error adding user to list of existing users: {}", e),
    };

    // Broadcast the new user's username and public key to all clients
    {
        let clients = clients.lock().unwrap();
        let broadcast_message = format!("{}\n{}", username, pem);
        for (recipient, mut recipient_stream) in clients.iter() {
            recipient_stream.write_all(broadcast_message.as_bytes()).unwrap();
        }
    }

    // Step 2: Add client to the clients HashMap and store the public key in existing_users
    {
        let mut clients = clients.lock().unwrap();
        let mut users = existing_users.lock().unwrap();
        clients.insert(username.clone(), stream.try_clone().unwrap());
        users.insert(username.clone(), pubkey);
        println!("Current users: {:?}", clients.keys().collect::<Vec<_>>());
    }

// Step 3: Listen for messages from the client
loop {
    let size = match stream.read(&mut buffer) {
        Ok(size) if size > 0 => size,
        _ => break,
    };

    // Parse message format "encrypted_message|first_node_id"
    let message = String::from_utf8_lossy(&buffer[..size]).to_string();
    let parts: Vec<&str> = message.splitn(2, "|").collect();

    if parts.len() == 2 {
        let encrypted_message = parts[0].to_string();
        let mut node_id: usize = parts[1].trim().parse().expect("Failed to parse node ID");

        // Initialize current layer to the received encrypted message
        let mut current_encrypted_layer = encrypted_message;

        // Step 4: Process each onion layer (decrypt using server's private key)
        while node_id > 0 {
            let seckeys_locked = seckeys.lock().unwrap();
            // Retrieve the server's private key for the current node
            let server_private_key = seckeys_locked.get(&node_id).expect("No private key for node");

            // Parse the encrypted symmetric key and payload from the current layer
            let layer_parts: Vec<&str> = current_encrypted_layer.splitn(2, "|").collect();
            if layer_parts.len() != 2 {
                eprintln!("Invalid layer format");
                break;
            }

            let enc_sym_key = general_purpose::STANDARD
            .decode(layer_parts[0])
            .expect("Failed to decode encrypted symmetric key");

            let enc_payload = general_purpose::STANDARD
            .decode(layer_parts[1])
            .expect("Failed to decode encrypted payload");

            // Decrypt the symmetric key using the server's private key
            let sym_key = server_private_key
                .decrypt(Pkcs1v15Encrypt, &enc_sym_key)
                .expect("Failed to decrypt symmetric key");

            // initialize AES-GCM with the decrypted symmetric key
            let aes_gcm = Aes256Gcm::new(Key::from_slice(&sym_key));
            let nonce = Nonce::from_slice(&[0; 12]);

            // Decrypt the payload to obtain the next layer or final message
            let decrypted_data = aes_gcm
                .decrypt(nonce, enc_payload.as_ref())
                .expect("Decryption failure");

            // Convert decrypted data to a string to check for the next node
            let decrypted_str = String::from_utf8(decrypted_data).expect("Failed to decode decrypted layer");

            // Separate next node ID and the inner layer
            let payload_parts: Vec<&str> = decrypted_str.splitn(2, "|").collect();
            if payload_parts.len() != 2 {
                eprintln!("Invalid payload format");
                break;
            }

            // Extract the next node ID and the next encrypted layer
            node_id = payload_parts[0].parse::<usize>().expect("Failed to parse node ID");
            current_encrypted_layer = payload_parts[1].to_string();
        }

        // At this point, `current_encrypted_layer` holds the final encrypted message for the recipient
        let final_encrypted_message = current_encrypted_layer;

        // Forward the encrypted message to the intended recipient (additional decryption will be needed by recipient)
        let clients = clients.lock().unwrap();
        if let Some(mut recipient_stream) = clients.get(&username) {
            recipient_stream.write_all(final_encrypted_message.as_bytes()).unwrap();
        }
    }
}


    // Remove client from the list on disconnect
    {
        let mut clients = clients.lock().unwrap();
        let mut users = existing_users.lock().unwrap();
        clients.remove(&username);
        users.remove(&username);
        println!("User '{}' disconnected. Remaining users: {:?}", username, clients.keys().collect::<Vec<_>>());
    }
}

fn main() {
    let listener = TcpListener::bind("127.0.0.1:7878").unwrap();
    let clients = Arc::new(Mutex::new(HashMap::new()));
    let existing_users = Arc::new(Mutex::new(HashMap::new()));
    let seckeys: Arc<Mutex<HashMap<usize, RsaPrivateKey>>> = Arc::new(Mutex::new(HashMap::new()));


    // Generate keys and save them
    println!("Enter the number of intermediate clients: ");
    let mut input_string = String::new();
    io::stdin().read_line(&mut input_string).unwrap();
    let n: usize = input_string.trim().parse().expect("Expected a positive integer!");
    let (ids, seckeys_vec, pubkeys) = generate_pubkey_list(n);

    match dump_pubkey_list(&ids, &pubkeys, "PKKeys.txt") {
        Ok(_) => println!("Successfully written pseudo keys to PKKeys.txt!"),
        Err(e) => eprintln!("Failed to write to PKKeys.txt: {}", e),
    };

    // Reset the user list
    match reset_user_list("UserKeys.txt") {
        Ok(_) => println!("Reset the list in UserKeys.txt!"),
        Err(e) => eprintln!("Failed to reset UserKeys.txt: {}", e),
    };

    // Step 2: Load server public keys and private keys
    {
        let mut users = existing_users.lock().unwrap();
        let mut sec_keys = seckeys.lock().unwrap();

        for (id, pubkey) in ids.iter().zip(pubkeys.iter()) {
            users.insert(id.clone(), pubkey.clone());
        }
        for (id, privkey) in ids.iter().zip(seckeys_vec.iter()) {
            sec_keys.insert(*id, privkey.clone());
        }
        println!("Loaded server public keys and private keys.");
    }

    println!("Server listening on port 7878");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let clients_clone = Arc::clone(&clients);
                let users_clone = Arc::clone(&existing_users);
                let seckeys_clone: Arc<Mutex<HashMap<usize, RsaPrivateKey>>> = Arc::clone(&seckeys);

                thread::spawn(move || {
                    handle_client(stream, clients_clone, users_clone, seckeys_clone);
                });
            }
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }
}
