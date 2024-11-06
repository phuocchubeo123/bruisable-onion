extern crate rsa;
mod crypto;

use std::net::TcpStream;
use std::io::{self, Write, Read};
use std::sync::{Arc, Mutex};
use std::thread;
use crypto::{read_pubkey_list, sample_random_path, generate_pubkey};
use rsa::pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey, LineEnding};
use rsa::{RsaPrivateKey, RsaPublicKey, Pkcs1v15Encrypt}; 
use std::collections::HashMap;
use rand::seq::SliceRandom; 
use rand::Rng; 
use aes_gcm::{
    aead::{Aead, NewAead},
    Aes256Gcm, Key, Nonce
}; 
use base64::Engine;  // Make sure to import GenericArray

fn main() {
    match TcpStream::connect("127.0.0.1:7878") {
        Ok(mut stream) => {
            println!("Successfully connected to server on port 7878");

            // Prompt for username
            println!("Enter your username:");
            let mut username = String::new();
            io::stdin().read_line(&mut username).unwrap();

            // phuoc: generate new pubkey
            let (personal_seckey, personal_pubkey) = generate_pubkey().unwrap();
            let pubkey_pem = personal_pubkey.to_pkcs1_pem(LineEnding::LF).expect("failed to encode public key to PEM");
            stream.write_all(format!("{}\n{}",username.trim(), pubkey_pem).as_bytes()).unwrap();

            // phuoc: Read the pubkey list from PKkeys.txt 
            //eileen: read and add to a hashmap for easier/faster use later
            let (server_PKs, server_pubkeys) = read_pubkey_list("PKKeys.txt").expect("Failed to read server public keys from PKKeys.txt");
            println!("Loaded server public keys from PKKeys.txt");

            // Step 3: Load existing users and their public keys from UserKeys.txt into HashMap
            let (usernames, user_pubkeys) = read_pubkey_list("UserKeys.txt").expect("Failed to read user public keys from UserKeys.txt");
            // Wrap existing_users in an Arc<Mutex<...>> for thread-safe access
            let existing_users = Arc::new(Mutex::new(
                usernames.into_iter().zip(user_pubkeys.into_iter()).collect::<HashMap<String, RsaPublicKey>>(),
            ));
            println!("Loaded existing user public keys from UserKeys.txt");

            // Spawn a thread to listen for incoming messages
            // Clone Arc to move into thread
            let mut read_stream = stream.try_clone().unwrap();
            let existing_users_thread = Arc::clone(&existing_users);
            
            thread::spawn(move || {
                let mut buffer = [0; 512];
                // Lock the mutex once, and keep the lock while processing messages
                let mut users_lock = existing_users_thread.lock().unwrap();
            
                while let Ok(size) = read_stream.read(&mut buffer) {
                    if size == 0 {
                        break;
                    }
            
                    let received_message = String::from_utf8_lossy(&buffer[..size]);
            
                    if let Some((new_username, new_pubkey_pem)) = parse_new_user_broadcast(&received_message) {
                        match RsaPublicKey::from_pkcs1_pem(&new_pubkey_pem) {
                            Ok(new_pubkey) => {
                                // Insert new user into the existing_users HashMap
                                users_lock.insert(new_username.clone(), new_pubkey);
                                println!("Added new user {} with public key", new_username);
                            },
                            Err(e) => println!("Failed to decode public key: {}", e),
                        }
                    } else {
                        println!("Received: {}", received_message);
                    }
                }
            });
            
            // Main thread loop for sending messages
            loop {
                println!("Enter recipient:");
                let mut recipient = String::new();
                io::stdin().read_line(&mut recipient).unwrap();
                let recipient = recipient.trim().to_string();
            
                println!("Enter your message:");
                let mut message = String::new();
                io::stdin().read_line(&mut message).unwrap();
                let message = message.trim().to_string();
            
                // Sample set of intermediary nodes for route
                let mut rng = rand::thread_rng();
                let random_ids: Vec<usize> = (0..server_pubkeys.len()).collect();
                let selected_ids: Vec<usize> = random_ids.choose_multiple(&mut rng, 3).cloned().collect();
                println!("This is my routing path node IDs: {:?}", selected_ids);
            
                // Encrypt the initial message for the recipient with their public key
                let recipient_pubkey = match existing_users.lock().unwrap().get(&recipient) {
                    Some(key) => key.clone(), // Clone the RsaPublicKey
                    None => {
                        println!("Recipient's public key not found.");
                        continue; // Skip iteration if recipient's key not found
                    }
                };
            
                let enc_recipient_message = recipient_pubkey
                    .encrypt(&mut rng, Pkcs1v15Encrypt, message.as_bytes())
                    .expect("failed to encrypt message for recipient");
            
                // Combine recipient's username and the encrypted message
                let mut encrypted_message = format!("{}|{}", recipient, base64::engine::general_purpose::STANDARD.encode(&enc_recipient_message));
                let mut enc_layers = Vec::new();
            
                // Onion encryption through selected server public keys
                for (i, id) in selected_ids.iter().rev().enumerate() {
                    let server_pubkey = &server_pubkeys[*id];
            
                    // Generate a random symmetric key for this layer
                    let sym_key = Aes256Gcm::generate_key(&mut rng); // Create a 256-bit key
                    let aes_gcm = Aes256Gcm::new(Key::from_slice(&sym_key)); // Use the key
                    let nonce = Nonce::from_slice(&[0; 12]);
            
                    // Include next node ID in the payload if it's not the last layer
                    let next_node_id = if i < selected_ids.len() - 1 {
                        selected_ids[selected_ids.len() - i - 2] + 1 // ID for the next node, adjusted if zero-based
                    } else {
                        0 // No next node for the last layer
                    };
            
                    // Combine next node ID and the encrypted message for this layer's payload
                    let payload = format!("{}|{}", next_node_id, encrypted_message);
            
                    // Encrypt the payload with the symmetric key
                    let ciphertext = aes_gcm.encrypt(nonce, payload.as_bytes()).expect("encryption failure!");
            
                    // Encrypt the symmetric key with the server's public key
                    let enc_sym_key = server_pubkey
                        .encrypt(&mut rng, Pkcs1v15Encrypt, &sym_key)
                        .expect("failed to encrypt symmetric key");
            
                    // Store the encrypted symmetric key and the ciphertext
                    enc_layers.push((enc_sym_key, ciphertext.clone()));
            
                    // Set the next layer's message as the Base64-encoded ciphertext
                    encrypted_message = base64::engine::general_purpose::STANDARD.encode(&ciphertext);
                }
            
                // Send the final encrypted message and the first node's ID to the server
                let first_node_id = selected_ids[0] + 1; // Send only the first node ID, adjusted if zero-based
                let final_message = format!("{}|{}\n", encrypted_message, first_node_id);
            
                stream.write_all(final_message.as_bytes()).unwrap();
            }
            
        
            
        }
        Err(e) => {
            println!("Failed to connect: {}", e);
        }
    }
}

// eileen: helper function to parse new user broadcast messages
fn parse_new_user_broadcast(message: &str) -> Option<(String, String)> {
    let mut lines = message.lines();
    let username = lines.next()?.to_string();
    let pubkey_pem = lines.collect::<Vec<_>>().join("\n");
    if pubkey_pem.contains("BEGIN RSA PUBLIC KEY") {
        Some((username, pubkey_pem))
    } else {
        None
    }
}