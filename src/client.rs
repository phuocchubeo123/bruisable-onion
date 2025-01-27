#![allow(warnings)]
extern crate sha2;

mod crypto;
mod tulip;
mod intermediary_node;
mod shared;
mod globals;

use std::time::Instant;
use log::info;
use std::net::TcpStream;
use std::io::{self, Write, Read};
use std::sync::{Arc, Mutex};
use std::thread;
use chrono::Local;
use crypto::{read_pubkey_list};
//use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};
use x25519_dalek::{StaticSecret, PublicKey, EphemeralSecret};
use std::collections::HashMap;
use tulip::{tulip_encrypt, tulip_receive};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    match TcpStream::connect("127.0.0.1:7878") {
        Ok(mut stream) => {
            eprintln!("Successfully connected to server on port 7878");

            // Prompt for username
            eprint!("Enter your username: ");
            io::stderr().flush().unwrap();
            let mut username = String::new();
            io::stdin().read_line(&mut username).unwrap();

            // Generate a new keypair
            let personal_secret = StaticSecret::new(&mut rand::rngs::OsRng);
            let personal_pubkey = PublicKey::from(&personal_secret);
            stream
                .write_all(format!("{}\n{}\n", username.trim(), hex::encode(personal_pubkey.as_bytes())).as_bytes())
                .unwrap();

            // Read the public key list from PKKeys.txt and store in a HashMap
            let (server_ids, server_pubkeys) = read_pubkey_list("PKKeys.txt").expect("Failed to read server public keys from PKKeys.txt");

            let server_nodes = Arc::new(Mutex::new(
                server_ids
                    .into_iter()
                    .zip(server_pubkeys.into_iter())
                    .collect::<HashMap<String, X25519PublicKey>>(),
            ));

            let (usernames, user_pubkeys) = read_pubkey_list("UserKeys.txt").expect("Failed to read user public keys from UserKeys.txt");
            let existing_users = Arc::new(Mutex::new(
                usernames
                    .into_iter()
                    .zip(user_pubkeys.into_iter())
                    .collect::<HashMap<String, X25519PublicKey>>(),
            ));

            // Receiving messages
            let mut read_stream = stream.try_clone().unwrap();
            let existing_users_thread = Arc::clone(&existing_users);
            let personal_secret_key = personal_secret.clone();
            thread::spawn(move || {
                let mut buffer = [0; 512];
                while let Ok(size) = read_stream.read(&mut buffer) {
                    if size == 0 {
                        break;
                    }

                    let received_message = String::from_utf8_lossy(&buffer[..size]);
                    if let Some((new_username, new_pubkey_hex)) = parse_new_user_broadcast(&received_message) {
                        if let Ok(new_pubkey_bytes) = hex::decode(new_pubkey_hex) {
                            if new_pubkey_bytes.len() == 32 {
                                let new_pubkey = X25519PublicKey::from(new_pubkey_bytes.as_slice().try_into().unwrap());
                                let mut users_lock = existing_users_thread.lock().unwrap();
                                users_lock.insert(new_username.clone(), new_pubkey);
                            }
                        }
                    } else {
                        if let Ok(message) = tulip_receive(&received_message, &personal_secret_key) {
                            eprintln!("Received message: {}", message);
                        }
                    }
                }
            });

            // Sending messages
            loop {
                eprintln!("Enter recipient:");
                let mut recipient = String::new();
                io::stdin().read_line(&mut recipient).unwrap();
                let recipient = recipient.trim().to_string();

                eprintln!("Enter your message:");
                let mut message = String::new();
                io::stdin().read_line(&mut message).unwrap();

                let username = username.trim().to_string();
                let no_username_message = message.trim().to_string();
                let message = format!("(from {}) {}", username, no_username_message);

                let recipient_pubkey = match existing_users.lock().unwrap().get(&recipient) {
                    Some(key) => key.clone(),
                    None => {
                        println!("Recipient's public key not found.");
                        continue;
                    }
                };

                // Convert Ed25519 public key to raw bytes
                let ed25519_pub_bytes = recipient_pubkey.as_bytes();

                // Create the corresponding X25519 public key from the raw bytes
                let recipient_x25519_pubkey = X25519PublicKey::from(ed25519_pub_bytes);

                let server_nodes_locked = server_nodes.lock().unwrap();
                if globals::MIXERS + globals::GATEKEEPERS > server_nodes_locked.len() {
                    return Err("MIXERS & GATEKEEPERS global exceeds available intermediary nodes.".into());
                }

                let selected_mixers: Vec<(&str, &X25519PublicKey)> = server_nodes_locked
                    .iter()
                    .take(globals::MIXERS)
                    .map(|(id, pubkey)| (id.as_str(), pubkey))
                    .collect();

                let selected_gatekeepers: Vec<(&str, &X25519PublicKey)> = server_nodes_locked
                    .iter()
                    .skip(globals::MIXERS)
                    .take(globals::GATEKEEPERS)
                    .map(|(id, pubkey)| (id.as_str(), pubkey))
                    .collect();

                if selected_mixers.len() < globals::MIXERS || selected_gatekeepers.len() < globals::GATEKEEPERS {
                    println!("Insufficient nodes available for tulip encryption.");
                    continue;
                }

                let nonce_list_len = selected_mixers.len() + selected_gatekeepers.len();
                let nonce_list = vec![vec![0u8; 12]; nonce_list_len];
                // let nonce_list: Vec<[u8; 12]> = (0..nonce_list_len)
                // .map(|_| rand::random::<[u8; 12]>())
                // .collect();

                let encrypted_tulip = tulip_encrypt(
                    &message,
                    &recipient_x25519_pubkey,
                    &recipient,
                    &selected_mixers,
                    &selected_gatekeepers,
                    &nonce_list,
                    &2,
                );

                match encrypted_tulip {
                    Ok(tulip) => {
                        let first_mixer = selected_mixers[0].0.to_string();
                        let message_to_server = format!("{}--{}", first_mixer, tulip);
                        if let Err(e) = stream.write_all(message_to_server.as_bytes()) {
                            eprintln!("Failed to send message: {}", e);
                        }
                    }
                    Err(e) => eprintln!("Encryption failed: {:?}", e),
                }
            }
        }
        Err(e) => println!("Failed to connect: {}", e),
    }

    Ok(())
}

fn parse_new_user_broadcast(message: &str) -> Option<(String, String)> {
    let mut lines = message.lines();
    let username = lines.next()?.to_string();
    let pubkey_hex = lines.collect::<Vec<_>>().join("\n");
    if pubkey_hex.len() == 64 {
        Some((username, pubkey_hex))
    } else {
        None
    }
}