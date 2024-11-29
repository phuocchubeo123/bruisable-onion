extern crate rsa;
mod crypto;
mod tulip;

use crypto::{read_pubkey_list, read_seckey_list, reset_user_list, update_user_list};
use tulip::{tulip_decrypt, process_tulip};
use rsa::{RsaPublicKey, pkcs1::DecodeRsaPublicKey, RsaPrivateKey, Pkcs1v15Encrypt};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::thread;
use aes_gcm::{Aes256Gcm, Key, Nonce}; 
use aes_gcm::aead::{Aead, AeadCore, KeyInit};
use base64::{engine::general_purpose::STANDARD, Engine};
use std::io::{BufRead, BufReader};

// receive and forward messages from the client
fn handle_client(
    mut stream: TcpStream,
    clients: Arc<Mutex<HashMap<String, TcpStream>>>,
    existing_users: Arc<Mutex<HashMap<String, RsaPublicKey>>>,
    seckeys: Arc<Mutex<HashMap<String, RsaPrivateKey>>>, // Server's private keys for decryption
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

                let first_node= parts[0];
                let tulip = parts[1];

                let tulip_result = process_tulip(tulip, first_node, &seckeys.lock().unwrap());
                assert!(tulip_result.is_ok(), "processing tulip failed: {:?}", tulip_result);

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

    let (ids, pubkeys) = read_pubkey_list("PKKeys.txt").expect("Failed to read server public keys from PKTest.txt");
    let (ids_2, seckeys) = read_seckey_list("SKKeys.txt").expect("Failed to read server secret keys from SKTest.txt");

    // Load server public keys and private keys into the HashMaps
    {
        let mut pubkeys_map = pubkeys_mutex.lock().unwrap();
        let mut seckeys_map = seckeys_mutex.lock().unwrap();

        // Populate the HashMaps with id -> public key and id -> private key
        for (id, pubkey) in ids.iter().zip(pubkeys.iter()) {
            pubkeys_map.insert(id.clone(), pubkey.clone());
        }

        for (id, seckey) in ids.iter().zip(seckeys.iter()) {
            seckeys_map.insert(id.clone(), seckey.clone());
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
                let clients_clone = Arc::clone(&clients_mutex);
                let pubkeys_clone = Arc::clone(&pubkeys_mutex);
                let seckeys_clone: Arc<Mutex<HashMap<String, RsaPrivateKey>>> = Arc::clone(&seckeys_mutex);

                thread::spawn(move || {
                    handle_client(stream, clients_clone, pubkeys_clone, seckeys_clone);
                });
            }
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }
}
