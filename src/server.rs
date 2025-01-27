#![allow(warnings)]

mod crypto;
mod tulip;
mod shared;
mod globals;

use crypto::{dump_pubkey_list, generate_pubkey_list, read_pubkey_list, read_seckey_list, update_user_list};
use tulip::process_tulip;
// use rsa::{RsaPublicKey, pkcs1::DecodeRsaPublicKey};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use log::info;
use std::thread;
use std::io::{BufRead, BufReader};
use std::time::Instant;
mod intermediary_node;
use crate::shared::IntermediaryNode; // Import from shared.rs
use x25519_dalek::{PublicKey, StaticSecret};


// receive and forward messages from the client
fn handle_client(
    mut stream: TcpStream,
    clients: Arc<Mutex<HashMap<String, TcpStream>>>,
    //existing_users: Arc<Mutex<HashMap<String, RsaPublicKey>>>,
    node_registry: Arc<Mutex<HashMap<String, IntermediaryNode>>>, // Directly using HashMap here
) {
    let mut buffer = [0; 512];

    // receive and store the username and PEM key
    // stream.read(&mut buffer).unwrap();
    // let username_and_pem = String::from_utf8_lossy(&buffer[..])
    //     .trim_matches(char::from(0))
    //     .trim()
    //     .to_string();

    //from rsa to elliptic curve
    stream.read(&mut buffer).unwrap();
    let username_and_key = String::from_utf8_lossy(&buffer[..])
        .trim_matches(char::from(0))
        .trim()
        .to_string();
    
    // Parse the username and raw key from the received data
    // user should be sending in a format that looks like this: 
        // username
        // aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899
    let mut lines = username_and_key.lines();
    let username = lines.next().unwrap_or_default().to_string();
    let raw_key_hex = lines.collect::<Vec<&str>>().join("");

    // rsa code...
    // // Parse the username and PEM key from the received data
    // let mut lines = username_and_pem.lines();
    // let username = lines.next().unwrap_or_default().to_string();
    // let pem = lines.collect::<Vec<&str>>().join("\n");

    // Debugging: Check parsed parts
    //println!("Parsed Username: {:?}", username);
    //println!("Parsed PEM Key Contents:\n{}", pem);

    // Validate PEM format OLD RSA CODE
    // if !pem.starts_with("-----BEGIN RSA PUBLIC KEY-----") || !pem.ends_with("-----END RSA PUBLIC KEY-----") {
    //     eprintln!("Received invalid PEM format for user '{}': {:?}", username, pem);
    //     return;
    // }

    // // Attempt to parse the PEM key
    // let pubkey = match RsaPublicKey::from_pkcs1_pem(&pem) {
    //     Ok(key) => key,
    //     Err(e) => {
    //         eprintln!("Failed to parse public key from PEM for user '{}': {:?}", username, e);
    //         return;
    //     }
    // };

    // Validate the raw key format
    let raw_key_bytes = match hex::decode(&raw_key_hex) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("Failed to decode raw key for user '{}': {}", username, e);
            return;
        }
    };

    // Attempt to construct the x25519 public key
    let pubkey = match x25519_dalek::PublicKey::from_slice(&raw_key_bytes) {
        Some(key) => key,
        None => {
            eprintln!(
                "Failed to construct x25519 public key for user '{}'. Invalid key data.",
                username
            );
            return;
        }
    };

    // If we reach here, the public key is valid
    println!("User '{}' connected with a valid x25519 public key: {:?}", username, pubkey);

    //println!("User '{}' connected with valid PEM key.", username);

    // Add user to the list
    // match update_user_list("UserKeys.txt", &username, &pubkey) {
    //     Ok(_) => println!("Added user to list of existing users!"),
    //     Err(e) => eprintln!("Error adding user to list of existing users: {}", e),
    // };

    // // broadcast the new user's username and public key to all clients
    // {
    //     let clients = clients.lock().unwrap();
    //     let broadcast_message = format!("{}\n{}", username, pem);
    //     for (recipient, mut recipient_stream) in clients.iter() {
    //         //println!("Broadcasting new key to {}", recipient);
    //         recipient_stream.write_all(broadcast_message.as_bytes()).unwrap();
    //     }
    // }

    // // add client to the clients HashMap and store the public key in existing_users
    // {
    //     let mut clients = clients.lock().unwrap();
    //     //let mut users = existing_users.lock().unwrap();
    //     clients.insert(username.clone(), stream.try_clone().unwrap());
    //     users.insert(username.clone(), pubkey);
    //     eprintln!("Current users: {:?}", clients.keys().collect::<Vec<_>>());
    // }


    {
        let clients = clients.lock().unwrap();

        // Convert public key to base64 for broadcasting
        let broadcast_key = base64::encode(pubkey.as_bytes());
        let broadcast_message = format!("{}\n{}", username, broadcast_key);

        for (recipient, recipient_stream) in clients.iter() {
            // Broadcast the username and public key
            if let Err(e) = recipient_stream.write_all(broadcast_message.as_bytes()) {
                eprintln!("Failed to broadcast key to '{}': {:?}", recipient, e);
            }
        }
    }

    // Add the client and their public key to the HashMap
    {
        let mut clients = clients.lock().unwrap();
        //let mut users = existing_users.lock().unwrap();

        // Store the client's stream and public key
        clients.insert(username.clone(), stream.try_clone().unwrap());
        users.insert(username.clone(), pubkey);
        eprintln!("Current users: {:?}", clients.keys().collect::<Vec<_>>());
    }

    // eileen: listen for messages from client and create reader and buffer. server reads until it receives a newline at end of message to mark complete onion
    let mut reader = BufReader::new(stream);
    let mut buffer = String::new();

    loop {
        // Step 1: Read the incoming message
        buffer.clear(); // clear previous buffer to store next message

        // try to read until we get a full message, assuming it is terminated by newline
        match reader.read_line(&mut buffer) {
            Ok(0) => {
                // Connection closed, exit the loop
                println!("Client disconnected");
                break;
            }
            Ok(_) => {
                // clean the received message and debug
                let received_message = buffer.trim().to_string();
                //println!("Received message: {:?}", received_message);

                // split the received message format: Recipient_ID|Enc_R_PK(sym_K4)|Enc_symK4(message)
                let parts: Vec<&str> = received_message.split("--").collect();
                // println!("Parsed parts: {:?}", parts);

                // ensure the message format has three parts (Recipient ID, Encrypted Public Key, Encrypted Message)
                if parts.len() != 2 {
                    eprintln!("Invalid message format");
                    continue;
                }

                let first_node = parts[0];
                let tulip = parts[1];
                // pass in the node registry instead of the secret keys list. Then allow individual intermediary nodes to do decryption
                let registry = node_registry.lock().unwrap();

                //START TIMER
                let start = Instant::now();
                let tulip_result = process_tulip(tulip, first_node, &registry);
                assert!(tulip_result.is_ok(), "processing tulip failed: {:?}", tulip_result);
                
                let duration = start.elapsed();
                //println!("TIMER START: Time taken to decrypt all intermediary nodes of onion: {:?}", duration);

                let (recipient, current_tulip) = tulip_result.unwrap();

                // find the recipient's stream and send the entire decrypted message
                let clients = clients.lock().unwrap();
                if let Some(mut recipient_stream) = clients.get(&recipient) {
                    if let Err(e) = recipient_stream.write_all(current_tulip.as_bytes()) {
                        eprintln!("Failed to send message to recipient '{}': {}", recipient, e);
                    }
                } else {
                    eprintln!("Recipient '{}' not found!", recipient);
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
        //let mut users = existing_users.lock().unwrap();
        clients.remove(&username);
        //users.remove(&username);
        println!("User '{}' disconnected. Remaining users: {:?}", username, clients.keys().collect::<Vec<_>>());
    }
}


fn main() {
    env_logger::init();
    let listener = TcpListener::bind("127.0.0.1:7878").expect("Failed to bind to address");

    // Shared state
    let clients_mutex = Arc::new(Mutex::new(HashMap::new()));
    let node_registry = Arc::new(Mutex::new(HashMap::<String, IntermediaryNode>::new()));

    // Generate intermediary nodes and have them append their public keys to the PKKeys.txt file
    println!("Enter the number of intermediary clients: ");
    let mut input_string = String::new();
    io::stdin().read_line(&mut input_string).expect("Failed to read input");
    let n: usize = input_string.trim().parse().expect("Expected a positive integer");

    for i in 0..n {
        let id = format!("Node{}", i + 1);
        let node = IntermediaryNode::new(&id);

        // Append the node's public key to the PKKeys.txt file
        if let Err(e) = node.append_pubkey_to_file() {
            eprintln!("Failed to append public key for {}: {}", id, e);
        } else {
            println!("Successfully appended public key for {}", id);
        }

        // Add the node to the registry
        let mut registry = node_registry.lock().expect("Failed to lock node registry mutex");
        registry.insert(id.clone(), node);
    }

    // Start the TCP listener (server continues as before)
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let clients_mutex = Arc::clone(&clients_mutex);
                let node_registry = Arc::clone(&node_registry);

                thread::spawn(move || {
                    handle_client(stream, clients_mutex, node_registry);
                });
            }
            Err(e) => eprintln!("Failed to accept incoming connection: {}", e),
        }
    }
}