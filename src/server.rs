#![allow(warnings)]
extern crate rsa;
mod crypto;
mod tulip;
mod shared;
mod globals;

use crypto::{read_pubkey_list, read_seckey_list, update_user_list};
use tulip::process_tulip;
use rsa::{RsaPublicKey, pkcs1::DecodeRsaPublicKey};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::thread;
use std::io::{BufRead, BufReader};
use std::time::Instant;
mod intermediary_node;
use crate::shared::IntermediaryNode; // Import from shared.rs



// receive and forward messages from the client
fn handle_client(
    mut stream: TcpStream,
    clients: Arc<Mutex<HashMap<String, TcpStream>>>,
    existing_users: Arc<Mutex<HashMap<String, RsaPublicKey>>>,
    node_registry: Arc<Mutex<HashMap<String, IntermediaryNode>>>, // Directly using HashMap here
) {
    let mut buffer = [0; 512];

    // receive and store the username and PEM key
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

    // add client to the clients HashMap and store the public key in existing_users
    {
        let mut clients = clients.lock().unwrap();
        let mut users = existing_users.lock().unwrap();
        clients.insert(username.clone(), stream.try_clone().unwrap());
        users.insert(username.clone(), pubkey);
        println!("Current users: {:?}", clients.keys().collect::<Vec<_>>());
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
                println!("Received message: {:?}", received_message);

                // split the received message format: Recipient_ID|Enc_R_PK(sym_K4)|Enc_symK4(message)
                let parts: Vec<&str> = received_message.split("--").collect();
                println!("Parsed parts: {:?}", parts);

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
                println!("TIMER START: Time taken to decrypt all intermediary nodes of onion: {:?}", duration);

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
        let mut users = existing_users.lock().unwrap();
        clients.remove(&username);
        users.remove(&username);
        println!("User '{}' disconnected. Remaining users: {:?}", username, clients.keys().collect::<Vec<_>>());
    }
}


fn main() {
    let listener = TcpListener::bind("127.0.0.1:7878").unwrap();
    let clients_mutex = Arc::new(Mutex::new(HashMap::new()));
    let pubkeys_mutex = Arc::new(Mutex::new(HashMap::new()));
    let seckeys_mutex = Arc::new(Mutex::new(HashMap::new()));

    // Create the node registry to manage intermediary nodes as a HashMap
    let node_registry = Arc::new(Mutex::new(HashMap::<String, IntermediaryNode>::new()));

    let (ids, pubkeys) = read_pubkey_list("PKKeys.txt").expect("Failed to read server public keys from PKTest.txt");
    let (ids_2, seckeys) = read_seckey_list("SKKeys.txt").expect("Failed to read server secret keys from SKTest.txt");

    // Ensure the ids, pubkeys, and seckeys match in length
    assert_eq!(ids.len(), pubkeys.len(), "Mismatch between ids and public keys");
    assert_eq!(ids_2.len(), seckeys.len(), "Mismatch between ids and secret keys");

    // Load server public keys and private keys into the HashMaps
    {
        let mut pubkeys_map = pubkeys_mutex.lock().unwrap();
        let mut seckeys_map = seckeys_mutex.lock().unwrap();
        let mut registry = node_registry.lock().unwrap();

        // Combine ids, pubkeys, and seckeys and iterate over them
        for (id, pubkey, seckey) in ids.iter().zip(pubkeys.iter()).zip(seckeys.iter()).map(|((id, pubkey), seckey)| (id, pubkey, seckey)) {
            // Insert public and secret keys into the respective HashMaps
            pubkeys_map.insert(id.clone(), pubkey.clone());
            seckeys_map.insert(id.clone(), seckey.clone());

            // Register nodes with the registry of intermediary nodes
            registry.insert(id.clone(), IntermediaryNode { public_key: pubkey.clone(), private_key: seckey.clone(), id: id.clone() });
        }

        // Debug print to check if nodes are properly registered
        println!("Node registry after population:");
        for (id, node) in &*registry {  // Dereference `registry` here
            println!("ID: {}, Public Key: {:?}", id, node.public_key);
        }
        println!("Loaded server public keys and private keys and node registry.");
    }

    // Now start the TCP listener
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let clients_mutex = clients_mutex.clone();
                let pubkeys_mutex = pubkeys_mutex.clone();
                let node_registry = node_registry.clone();

                // Handle the new client in a separate thread
                thread::spawn(move || {
                    handle_client(stream, clients_mutex, pubkeys_mutex, node_registry);
                });
            }
            Err(e) => eprintln!("Failed to accept incoming connection: {}", e),
        }
    }
}
