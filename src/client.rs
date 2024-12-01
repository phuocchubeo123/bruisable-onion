extern crate rsa;
extern crate sha2;
mod crypto;
mod tulip;

use std::net::TcpStream;
use std::io::{self, Write, Read};
use std::sync::{Arc, Mutex};
use std::thread;
use crypto::{read_pubkey_list, generate_pubkey};
use rsa::pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey, LineEnding};
use rsa::{RsaPublicKey, Pkcs1v15Encrypt}; 
use std::collections::HashMap;
use base64::{engine::general_purpose::STANDARD, Engine};
use rand::{rngs::OsRng, RngCore};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Key, Nonce
}; 
use sha2::{Sha256, Digest};
use tulip::{tulip_encrypt, tulip_receive};
mod intermediary_node;

fn main() -> Result<(), Box<dyn std::error::Error>> {
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
            let (server_ids, server_pubkeys) = read_pubkey_list("PKKeys.txt").expect("Failed to read server public keys from PKKeys.txt");

            // create HashMap for server nodes (server ID -> public key)
            let server_nodes = Arc::new(Mutex::new(
                server_ids.into_iter().zip(server_pubkeys.into_iter()).collect::<HashMap<String, RsaPublicKey>>(),
            ));
            println!("Loaded server public keys from PKKeys.txt");

            // load existing users and their public keys from UserKeys.txt into HashMap
            let (usernames, user_pubkeys) = read_pubkey_list("UserKeys.txt").expect("Failed to read user public keys from UserKeys.txt");
            // Wrap existing_users in an Arc<Mutex<...>> for thread-safe access
            let existing_users = Arc::new(Mutex::new(
                usernames.into_iter().zip(user_pubkeys.into_iter()).collect::<HashMap<String, RsaPublicKey>>(),
            ));
            println!("Loaded existing user public keys from UserKeys.txt");

            // ---------- RECEIVING MESSAGES ------------ //

            // spawn a thread to listen for incoming messages
            // clone Arc to move into thread
            let mut read_stream = stream.try_clone().unwrap();
            let existing_users_thread = Arc::clone(&existing_users);
            
            thread::spawn(move || {
                let mut buffer = [0; 512];
                // ensure there is something to fetch from buffer
                while let Ok(size) = read_stream.read(&mut buffer) {
                    if size == 0 {
                        break;
                    }
            
                    let received_message = String::from_utf8_lossy(&buffer[..size]);

                    // eileen step 1: check if the message is new user broadcast
                    if let Some((new_username, new_pubkey_pem)) = parse_new_user_broadcast(&received_message) {
                        match RsaPublicKey::from_pkcs1_pem(&new_pubkey_pem) {
                            Ok(new_pubkey) => {
                                // insert new user into the existing_users HashMap
                                let mut users_lock = existing_users_thread.lock().unwrap();
                                users_lock.insert(new_username.clone(), new_pubkey);
                                println!("Added new user {} with public key", new_username);
                            },
                            Err(e) => {
                                eprintln!("Failed to decode public key for {}: {}", new_username, e);
                            }
                        }
                    } else {
                        // eileen step 2: else it is a regular ciphertext (last layer of the onion)
                        // eileen comments on current implementation and next steps:
                        // split received message format: Recipient_ID|Enc_R_PK(sym_K4)|Enc_symK4(message)
                        // using index 4 here because we are using three intermediary nodes, so the recipient will have index 4
                        // later we will add these indexes into the metadata of the onion, specifically in the part encrypted with the public key
                        // for now this only includes the current symmetric key for the node
                        println!("Raw received message: {}", received_message);

                        let result_message = tulip_receive(&received_message.to_string(), &personal_seckey);
                        assert!(result_message.is_ok(), "tulip_receive failed: {:?}", result_message);

                        let message = result_message.unwrap();
                        println!("Received message: {}", message);
                    }
                }
            });
            
            // eileen edits to main thread loop for sending messages
            // ---------- SENDING ENCRYPTED MESSAGES ------------ //
            loop {
                println!("Enter recipient:");
                let mut recipient = String::new();
                io::stdin().read_line(&mut recipient).unwrap();
                let recipient = recipient.trim().to_string();
            
                println!("Enter your message:");
                let mut message = String::new();
                io::stdin().read_line(&mut message).unwrap();
                let username = username.trim().to_string();
                let no_username_message = message.trim().to_string();
                let message = format!("(from {}) {}", username, no_username_message);




                // encrypt the initial message with a symmetric key for the recipient
                let recipient_pubkey = match existing_users.lock().unwrap().get(&recipient) {
                    Some(key) => key.clone(),
                    None => {
                        println!("Recipient's public key not found.");
                        continue;
                    }
                };

                // lock the server_nodes to safely access it
                let server_nodes_locked = server_nodes.lock().unwrap();

                // phuoc: I will just focus on tulip sampling now, I will need to delete the onion sampling code
                // select up to three mixers from server_nodes, with their IDs and public keys
                println!("Choosing 3 random mixers.");
                let selected_mixers: Vec<(&str, &RsaPublicKey)> = server_nodes_locked
                    .iter()
                    .take(3)  // Get the first three nodes if available
                    .map(|(id, pubkey)| (id.as_str(), pubkey))
                    .collect();


                // ensure we have exactly three nodes for encryption
                if selected_mixers.len() < 3 {
                    println!("Insufficient mixers available for tulip encryption.");
                    continue;
                }

                println!("Choosing 2 random gatekeepers.");
                let selected_gatekeepers: Vec<(&str, &RsaPublicKey)> = server_nodes_locked
                    .iter()
                    .take(2)  // Get the first three nodes if available
                    .map(|(id, pubkey)| (id.as_str(), pubkey))
                    .collect();


                // ensure we have exactly three nodes for encryption
                if selected_gatekeepers.len() < 2 {
                    println!("Insufficient gatekeepers available for tulip encryption.");
                    continue;
                }

                // perform onion encryption using helper function defined below
                // let encrypted_onion = onion_encrypt(&message, &recipient_pubkey, &recipient, &selected_server_nodes)?;

                // tulip encryption
                let nonce_list_len = selected_mixers.len() + selected_gatekeepers.len();
                let nonce_list = vec![&[0; 12]; nonce_list_len];
                let encrypted_tulip = tulip_encrypt(&message, &recipient_pubkey, &recipient, &selected_mixers, &selected_gatekeepers, &nonce_list, &2);

                assert!(encrypted_tulip.is_ok(), "tulip_encrypt failed: {:?}", encrypted_tulip);
                let tulip = encrypted_tulip.unwrap();

                let first_mixer = selected_mixers[0].0.to_string();
                
                let message_to_server = format!(
                    "{}--{}",
                    first_mixer,
                    tulip,
                );
            
                // send onion-encrypted message over the stream
                if let Err(e) = stream.write_all(message_to_server.as_bytes()) {
                    eprintln!("Failed to send message: {}", e);
                } else {
                    println!("Message sent successfully.");
                }
            }
        },
        Err(e) => {
            println!("Failed to connect: {}", e);
        }
    }

    Ok(())
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

