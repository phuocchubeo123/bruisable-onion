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
use base64::engine::general_purpose;
use aes_gcm::{
    aead::{Aead, NewAead},
    Aes256Gcm, Key, Nonce
}; 
use base64::Engine;

fn main() {
    match TcpStream::connect("127.0.0.1:7878") {
        Ok(mut stream) => {
            println!("Successfully connected to server on port 7878");

            // prompt for username
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

            // spawn a thread to listen for incoming messages
            // clone Arc to move into thread
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
            
            // main thread loop for sending messages
            loop {
                println!("Enter recipient:");
                let mut recipient = String::new();
                io::stdin().read_line(&mut recipient).unwrap();
                let recipient = recipient.trim().to_string();
            
                println!("Enter your message:");
                let mut message = String::new();
                io::stdin().read_line(&mut message).unwrap();
                let message = message.trim().to_string();
            
                // sample set of intermediary nodes for route
                let mut rng = rand::thread_rng();
                let random_ids: Vec<usize> = (0..server_pubkeys.len()).collect();
                let selected_ids: Vec<usize> = random_ids.choose_multiple(&mut rng, 3).cloned().collect();
                println!("Routing path node IDs: {:?}", selected_ids);
                
                // NEED TO FIX HARDCODE SOME NODES THAT THE CLIENT CHOOSES

                // encrypt the initial message with a symmetric key for the recipient
                let recipient_pubkey = match existing_users.lock().unwrap().get(&recipient) {
                    Some(key) => key.clone(),
                    None => {
                        println!("Recipient's public key not found.");
                        continue;
                    }
                };
            
                // Generate symmetric key for recipient encryption
                let sym_key1 = Aes256Gcm::generate_key(&mut rng);
                let aes_gcm1 = Aes256Gcm::new(Key::from_slice(&sym_key1));
                let nonce1 = Nonce::from_slice(&[0; 12]); // Constant nonce for simplicity
            
                // encrypt the message with the symmetric key
                let encrypted_message = aes_gcm1.encrypt(nonce1, message.as_bytes()).expect("encryption failure!");

                let enc_sym_key1 = recipient_pubkey
                    .encrypt(&mut rng, Pkcs1v15Encrypt, &sym_key1)
                    .expect("failed to encrypt symmetric key");
            
                // combine encrypted symmetric key and message for the first payload
                // corrected initialization for `layer` using general purpose standard encode
                let mut layer = format!(
                    "{}|{}",
                    general_purpose::STANDARD.encode(&enc_sym_key1),
                    general_purpose::STANDARD.encode(&encrypted_message)
                );
            
                // perform onion encryption for each node
                for (i, id) in selected_ids.iter().rev().enumerate() {
                    let server_pubkey = &server_pubkeys[*id];
            
                    // generate new symmetric key for this layer
                    let sym_key = Aes256Gcm::generate_key(&mut rng);
                    let aes_gcm = Aes256Gcm::new(Key::from_slice(&sym_key));
                    let nonce = Nonce::from_slice(&[0; 12]);
            
                    // Next node ID if not the last layer
                    let next_node_id = if i < selected_ids.len() - 1 {
                        selected_ids[selected_ids.len() - i - 2]
                    } else {
                        0 // no next node for last layer
                    };
            
                    // eombine next node ID with the current layer
                    let payload = format!("{}|{}", next_node_id, layer);
            
                    // encrypt payload with symmetric key
                    let enc_payload = aes_gcm.encrypt(nonce, payload.as_bytes()).expect("encryption failure");
            
                    // encrypt symmetric key with the current node's public key
                    let enc_sym_key = server_pubkey
                        .encrypt(&mut rng, Pkcs1v15Encrypt, &sym_key)
                        .expect("failed to encrypt symmetric key");
            
                    // Update layer with new encrypted symmetric key and payload
                    layer = format!(
                        "{}|{}",
                        general_purpose::STANDARD.encode(&enc_sym_key),
                        general_purpose::STANDARD.encode(&enc_payload)
                    );
                }
            
                // final message with the first node ID
                let first_node_id = selected_ids[0]; // Send only the first node ID
                let final_message = format!("{}|{}\n", layer, first_node_id);
            
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