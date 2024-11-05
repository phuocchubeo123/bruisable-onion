extern crate rsa;
mod crypto;

use std::net::TcpStream;
use std::io::{self, Write, Read};
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
            let mut existing_users: HashMap<String, RsaPublicKey> = usernames.into_iter().zip(user_pubkeys.into_iter()).collect();
            println!("Loaded existing user public keys from UserKeys.txt");

            // Spawn a thread to listen for incoming messages
            let mut read_stream = stream.try_clone().unwrap();
            thread::spawn(move || {
                let mut buffer = [0; 512];
                while let Ok(size) = read_stream.read(&mut buffer) {
                    if size == 0 {
                        break;
                    }
                    let received_message = String::from_utf8_lossy(&buffer[..size]);
                    // eileen: check if the incoming message is a broadcast of new user PK 
                    // if so then add to existing_users hashmap.
                    // Check if the received message is a broadcast for a new user
                    if let Some((new_username, new_pubkey_pem)) = parse_new_user_broadcast(&received_message) {
                        match RsaPublicKey::from_pkcs1_pem(&new_pubkey_pem) {
                            Ok(new_pubkey) => {
                                // Add new user and their public key to existed_users HashMap
                                existing_users.insert(new_username.clone(), new_pubkey);
                                println!("Updated users: Added new user {} with public key to internal hashmap.", new_username);
                            },
                            Err(e) => println!("Failed to decode public key: {}", e),
                        }
                    } else {
                        // Handle other messages normally
                        println!("Received: {}", received_message);
                    }
                }
            });

            // Send messages in the main thread
            loop {
                println!("Enter recipient:");
                let mut recipient = String::new();
                io::stdin().read_line(&mut recipient).unwrap();
                let recipient = recipient.trim().to_string();

                println!("Enter your message:");
                let mut message = String::new();
                io::stdin().read_line(&mut message).unwrap();
                let message = message.trim().to_string();

                // eileen: implement onion encryption using symmetric and PK encryption 
                // sample set of intermediary nodes to route message through setting this to be at least three (for now)
                let mut rng = rand::thread_rng();
                let random_ids: Vec<usize> = (0..server_PKs.len()).collect();
                let selected_ids: Vec<usize> = random_ids.choose_multiple(&mut rng, 3).cloned().collect();
                println!("This is my routing path node IDs: {:?}", selected_ids);
                // Prepare the message for onion encryption
                let mut enc_layers = Vec::new();
                let mut encrypted_message = message.clone();
                
                // Encrypt the message through the selected server public keys
                for id in selected_ids.iter().rev() {
                    let server_pubkey = &server_pubkeys[*id]; // Get the selected server public key

                    // Generate a random symmetric key for this layer
                    // Generate a random symmetric key for AES-GCM encryption
                    // In the message encryption part, adjust the AES-GCM key generation:
                    
                    let sym_key = Aes256Gcm::generate_key(&mut rng); // Create a 256-bit key
                    let aes_gcm = Aes256Gcm::new(Key::from_slice(&sym_key)); // Use the key
                    let nonce = Nonce::from_slice(&[0; 12]);

                    // Encrypt the message with the symmetric key
                    let ciphertext: Vec<u8> = aes_gcm.encrypt(nonce, encrypted_message.as_bytes()).expect("encryption failure!");
                    
                    // Encrypt the symmetric key with the server's public key using PKCS#1 v1.5 padding
                    let enc_sym_key = server_pubkey
                        .encrypt(&mut rng, Pkcs1v15Encrypt, &sym_key)
                        .expect("failed to encrypt symmetric key");

                    // Store the encrypted symmetric key and the ciphertext
                    enc_layers.push((enc_sym_key, ciphertext.clone())); 

                    // Set the next layer's message as the ciphertext (Base64 encoded)
                    encrypted_message = base64::engine::general_purpose::STANDARD.encode(&ciphertext);

                }

                // Send the final encrypted message and the selected server IDs to the server
                let final_message = format!("{}|{}\n", encrypted_message, selected_ids.iter().map(|id| (id + 1).to_string()).collect::<Vec<String>>().join(","));
                stream.write_all(final_message.as_bytes()).unwrap();
                
                
                //TO DO LATER: add in random path and encryption
                // Now we need to sample a random path and encrypt the message
                // let (mut random_ids, mut random_pubkeys) = sample_random_path(3, &server_PKs, &existed_users).unwrap(); // Currently I set the path length to be 3
                // random_ids.push(recipient);
                // TODO: How do we update the existed users list here, and how to efficiently find the matching pubkey?
                
                // stream.write_all(message.as_bytes()).unwrap();
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