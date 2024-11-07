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
use base64::{engine::general_purpose::STANDARD, Engine};
use std::io::{BufRead, BufReader};

fn onion_decrypt(
    onion: &str,
    node_secrets: &HashMap<String, RsaPrivateKey>, // Maps node IDs to their private keys
) -> Result<String, Box<dyn std::error::Error>> {
    let mut current_layer = onion.to_string();
    
    // **Step 1**: Loop to decrypt each of the 3 layers, from outermost to innermost
    for _ in 0..3 { // We know there are 3 nodes, so we decrypt 3 layers
        // Split the current layer into three parts: node_id, encrypted symmetric key, and encrypted layer
        let parts: Vec<&str> = current_layer.split('|').collect();
        if parts.len() != 3 {
            return Err("Invalid onion layer format".into());
        }

        let node_id = parts[0];          // Current node's ID
        let enc_sym_key = parts[1];      // Encrypted symmetric key for the current layer
        let encrypted_layer = parts[2];  // The encrypted layer content

        // **Step 2**: Get the private key for the current node
        let node_seckey = node_secrets.get(node_id).ok_or("Node ID not found")?;

        // Decrypt the symmetric key for the current layer using the current node's private key
        let enc_sym_key_bytes = STANDARD.decode(enc_sym_key)?;
        let sym_key_bytes = node_seckey.decrypt(Pkcs1v15Encrypt, &enc_sym_key_bytes)?;

        // **Step 3**: Decrypt the layer content using the symmetric key for the current layer
        let aes_gcm = Aes256Gcm::new(Key::from_slice(&sym_key_bytes));
        let nonce = Nonce::from_slice(&[0; 12]); // Use a constant nonce

        let decrypted_layer = aes_gcm.decrypt(nonce, &*STANDARD.decode(encrypted_layer)?)?;

        // Convert the decrypted layer back to a string for the next iteration
        current_layer = String::from_utf8_lossy(&decrypted_layer).into_owned();

        //println!("Current layer after decryption: {}", current_layer); //debugging
    }

    // **Step 4**: After decrypting all layers, we expect the final layer to contain:
    // 1. The recipient ID
    // 2. The encrypted symmetric key for the recipient
    // 3. The encrypted message

    let parts: Vec<&str> = current_layer.split('|').collect();
    if parts.len() != 3 {
        return Err("Final layer format invalid".into());
    }

    let recipient_id = parts[0];   // Recipient's ID
    let enc_sym_key = parts[1];    // Encrypted symmetric key for the recipient
    let encrypted_message = parts[2]; // The encrypted message

    // step 5: format the final result into a single string compatible with client's parsing
    let result = format!("{}|{}|{}", recipient_id, enc_sym_key, encrypted_message);

    Ok(result) // Return the formatted string to the client
}


fn handle_client(
    mut stream: TcpStream,
    clients: Arc<Mutex<HashMap<String, TcpStream>>>,
    existing_users: Arc<Mutex<HashMap<String, RsaPublicKey>>>,
    seckeys: Arc<Mutex<HashMap<String, RsaPrivateKey>>>, // Server's private keys for decryption
) {
    // eileen : buffer for accumulating data until a complete message is received
    let mut buffer = [0; 512];

    // Step 1: Receive and store the username and PEM key
    stream.read(&mut buffer).unwrap();
    let username_and_pem = String::from_utf8_lossy(&buffer[..])
        .trim_matches(char::from(0))
        .trim()
        .to_string();
    
    // Debugging: Show the raw received data
    println!("Raw received data: {:?}", username_and_pem);

    // Parse the username and PEM key from the received data
    let mut lines = username_and_pem.lines();
    let username = lines.next().unwrap_or_default().to_string();
    let pem = lines.collect::<Vec<&str>>().join("\n");

    // Debugging: Check parsed parts
    println!("Parsed Username: {:?}", username);
    println!("Parsed PEM Key Contents:\n{}", pem);

    // Validate PEM format
    if !pem.starts_with("-----BEGIN RSA PUBLIC KEY-----") || !pem.ends_with("-----END RSA PUBLIC KEY-----") {
        eprintln!("Received invalid PEM format for user '{}': {:?}", username, pem);
        return;
    }

    // Attempt to parse the PEM key
    let pubkey = match RsaPublicKey::from_pkcs1_pem(&pem) {
        Ok(key) => key,
        Err(e) => {
            eprintln!("Failed to parse public key from PEM for user '{}': {:?}", username, e);
            return;
        }
    };

    println!("User '{}' connected with valid PEM key.", username);

    // Add user to the list
    match update_user_list("UserKeys.txt", &username, &pubkey) {
        Ok(_) => println!("Added user to list of existing users!"),
        Err(e) => eprintln!("Error adding user to list of existing users: {}", e),
    };

    // broadcast the new user's username and public key to all clients
    {
        let clients = clients.lock().unwrap();
        let broadcast_message = format!("{}\n{}", username, pem);
        for (recipient, mut recipient_stream) in clients.iter() {
            println!("Broadcasting new key to {}", recipient);
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
    // Step 3: Listen for messages from the client
    let mut reader = BufReader::new(stream);
    let mut buffer = String::new();

    loop {
        // Step 1: Read the incoming message
        buffer.clear(); // Clear previous buffer to store next message

        // Try to read until we get a full message, assuming it is terminated by a newline or other delimiter.
        match reader.read_line(&mut buffer) {
            Ok(0) => {
                // Connection closed, exit the loop
                println!("Client disconnected");
                break;
            }
            Ok(_) => {
                // Clean the received message and debug
                let received_message = buffer.trim().to_string();
                println!("Received message: {:?}", received_message);

                // Step 2: Split the received message format: Recipient_ID|Enc_R_PK(sym_K4)|Enc_symK4(message)
                let parts: Vec<&str> = received_message.split('|').collect();
                println!("Parsed parts: {:?}", parts);

                // Step 3: Ensure the message format has three parts (Recipient ID, Encrypted Public Key, Encrypted Message)
                if parts.len() != 3 {
                    eprintln!("Invalid message format");
                    continue;
                }

                // Step 4: Decrypt the message
                let decrypted_message = match onion_decrypt(&received_message, &seckeys.lock().unwrap()) {
                    Ok(decrypted) => decrypted,
                    Err(e) => {
                        eprintln!("Decryption failed: {}", e);
                        continue;
                    }
                };

                // Step 5: Further process the decrypted message
                let final_decrypted_layer: Vec<&str> = decrypted_message.split('|').collect();
                if final_decrypted_layer.len() != 3 {
                    eprintln!("Decrypted message format invalid");
                    continue;
                }

                // Final recipient ID
                let final_recipient_id = final_decrypted_layer[0];
                let enc_sym_key4 = final_decrypted_layer[1];
                let encrypted_message = final_decrypted_layer[2];

                // Step 6: Find the recipient's stream and send the entire decrypted message
                let clients = clients.lock().unwrap();
                if let Some(mut recipient_stream) = clients.get(final_recipient_id) {
                    let message_to_send = format!("{}|{}|{}", final_recipient_id, enc_sym_key4, encrypted_message);
                    
                    if let Err(e) = recipient_stream.write_all(message_to_send.as_bytes()) {
                        eprintln!("Failed to send message to recipient '{}': {}", final_recipient_id, e);
                    }
                } else {
                    eprintln!("Recipient '{}' not found!", final_recipient_id);
                }
            }
            Err(e) => {
                eprintln!("Failed to read from stream: {}", e);
                break;
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
    let seckeys: Arc<Mutex<HashMap<String, RsaPrivateKey>>> = Arc::new(Mutex::new(HashMap::new()));


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

    // Step 2: Load server public keys and private keys into the HashMaps
    {
        let mut users = existing_users.lock().unwrap();
        let mut sec_keys = seckeys.lock().unwrap();

        // Populate the HashMaps with id -> public key and id -> private key
        for (id, pubkey) in ids.iter().zip(pubkeys.iter()) {
            users.insert(id.clone(), pubkey.clone());
        }

        for (id, privkey) in ids.iter().zip(seckeys_vec.iter()) {
            sec_keys.insert(id.clone(), privkey.clone());
        }

        println!("Loaded server public keys and private keys.");
    }

    // Reset the user list
    match reset_user_list("UserKeys.txt") {
        Ok(_) => println!("Reset the list in UserKeys.txt!"),
        Err(e) => eprintln!("Failed to reset UserKeys.txt: {}", e),
    };

    println!("Server listening on port 7878");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let clients_clone = Arc::clone(&clients);
                let users_clone = Arc::clone(&existing_users);
                let seckeys_clone: Arc<Mutex<HashMap<String, RsaPrivateKey>>> = Arc::clone(&seckeys);

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
