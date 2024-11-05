extern crate rsa;
mod crypto;

use std::net::TcpStream;
use std::io::{self, Write, Read};
use std::thread;
use crypto::{read_pubkey_list, sample_random_path, generate_pubkey};
use rsa::pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey, LineEnding};
use std::collections::HashMap;
use rsa::RsaPublicKey;

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

            // phuoc: Read the pubkey list from PKkeys.txt //eileen: read and add to a hashmap for easier/faster use later
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

                // Construct the message in the format "recipient: message"
                let formatted_message = format!("{}: {}", recipient, message);

                // Send the message to the server
                stream.write_all(formatted_message.as_bytes()).unwrap();
                
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