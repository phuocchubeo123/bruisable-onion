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
use tulip::tulip_encrypt;

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

                        let parts: Vec<&str> = received_message.split('|').collect();
                        
                        if parts.len() != 3 { // Most likely does not happen
                            eprintln!("Message received does not have 3 parts!");
                        }

                        let recipient_id = parts[0];
                        let enc_sym_key4 = parts[1];
                        let encrypted_message = parts[2];

                        //println!("Received: recipient_id = {}, enc_sym_key4 = {}, encrypted_message = {}", recipient_id, enc_sym_key4, encrypted_message); //debug

                        // check if this message is for this client (by comparing recipient_id to username)
                        if recipient_id != username.trim() { // Hopefully does not happen
                            eprintln!("Someone else not recorded is sending this message.")
                        }

                        // step 3: decode and decrypt symmetric key with the private key
                        match STANDARD.decode(enc_sym_key4) {
                            Ok(enc_sym_key_bytes) => {
                                //println!("Decoded symmetric key bytes: {:?}", enc_sym_key_bytes);
                                println!("Decoded symmetric key bytes");
                                match personal_seckey.decrypt(Pkcs1v15Encrypt, &enc_sym_key_bytes) {
                                    Ok(sym_key4) => {
                                        //println!("Decrypted symmetric key: {:?}", sym_key4);
                                        println!("Decrypted symmetric key");
                                        // step 4: use the symmetric key to decrypt the message
                                        let aes_gcm4 = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&sym_key4));
                                        let nonce4 = Nonce::from_slice(&[0; 12]); // Same nonce as used in encryption

                                        // decode encrypted message and do error checking
                                        match STANDARD.decode(encrypted_message) {
                                            Ok(encrypted_message_bytes) => {
                                                //println!("Decoded encrypted message: {:?}", encrypted_message_bytes);
                                                println!("Decoded encrypted message");
                                                match aes_gcm4.decrypt(nonce4, encrypted_message_bytes.as_ref()) {
                                                    Ok(decrypted_message) => {
                                                        // convert decrypted message to string and print
                                                        let message_text = String::from_utf8_lossy(&decrypted_message);
                                                        println!("Decrypted message: {}", message_text);
                                                    },
                                                    Err(e) => eprintln!("Failed to decrypt message: {}", e),
                                                }
                                            },
                                            Err(e) => eprintln!("Failed to decode encrypted message: {}", e),
                                        }
                                    },
                                    Err(e) => eprintln!("Failed to decrypt symmetric key: {}", e),
                                }
                            },
                            Err(e) => eprintln!("Failed to decode encrypted symmetric key: {}", e),
                        }
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
                let message = message.trim().to_string();


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
                // select up to three nodes from server_nodes, with their IDs and public keys
                println!("Choosing 3 random intermediary nodes.");
                let selected_server_nodes: Vec<(&str, &RsaPublicKey)> = server_nodes_locked
                    .iter()
                    .take(3)  // Get the first three nodes if available
                    .map(|(id, pubkey)| (id.as_str(), pubkey))
                    .collect();


                // ensure we have exactly three nodes for encryption
                if selected_server_nodes.len() < 3 {
                    println!("Insufficient nodes available for onion encryption.");
                    continue;
                }
                // perform onion encryption using helper function defined below
                let encrypted_onion = onion_encrypt(&message, &recipient_pubkey, &recipient, &selected_server_nodes)?;
                
            
                // send onion-encrypted message over the stream
                if let Err(e) = stream.write_all(encrypted_onion.as_bytes()) {
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


// eileen: basic onion encryption function
// next steps include adding more information in the public key enryption part. 
// right now we only include the symmetric key, next we need to include the index, current recipient, nonce, and verification hashes
fn onion_encrypt(
    message: &str,
    recipient_pubkey: &RsaPublicKey,
    recipient_id: &str,
    server_nodes: &[(&str, &RsaPublicKey)]
) -> Result<String, Box<dyn std::error::Error>> {
    let mut rng = OsRng;

    // STEP 1: Start with the innermost encryption layer for the recipient
    // generate symmetric key for the recipient's layer (sym_K4)
    let sym_key4 = Aes256Gcm::generate_key(&mut rng);
    let aes_gcm4 = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&sym_key4));
    let nonce4 = Nonce::from_slice(&[0; 12]); // Constant nonce for simplicity

    // encrypt message with sym_K4
    let encrypted_message = aes_gcm4.encrypt(nonce4, message.as_bytes())?;

    // Encrypt sym_K4 with the recipient's public key
    let enc_sym_key4 = recipient_pubkey.encrypt(&mut rng, Pkcs1v15Encrypt, &sym_key4)?; //this is where in future edits we need to add R, A, i, y

    // Combine the innermost layer: Recipient_ID, Enc_R_PK(sym_K4), Enc_symK4(message)
    let mut layer = format!(
        "{}|{}|{}",
        recipient_id,
        STANDARD.encode(&enc_sym_key4),
        STANDARD.encode(&encrypted_message)
    );

    //println!("Initial encrypted layer for recipient: {}", layer);
    println!("Done with encrypted layer for recipient");

    // STEP 2: wrap each subsequent layer in reverse order (starting from Node 3)
    for (node_id, node_pubkey) in server_nodes.iter().rev() {
        // Generate symmetric key for the current layer
        let sym_key = Aes256Gcm::generate_key(&mut rng);
        let aes_gcm = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&sym_key));
        let nonce = Nonce::from_slice(&[0; 12]); // Constant nonce for simplicity

        // encrypt the current layer with the symmetric key
        let encrypted_layer = aes_gcm.encrypt(&nonce, layer.as_bytes())?;

        // encrypt the symmetric key with the node's public key
        let enc_sym_key = node_pubkey.encrypt(&mut rng, Pkcs1v15Encrypt, &sym_key)?;

        // combine the current layer format:
        // node ID, Enc_PK_N(sym_K), Enc_symK(layer)
        layer = format!(
            "{}|{}|{}",
            node_id,
            STANDARD.encode(&enc_sym_key),
            STANDARD.encode(&encrypted_layer)
        );
        //println!("Layer after wrapping with node {}: {}", node_id, layer);
        println!("Done wrapping with node : {}", node_id);
    }


    // FINAL layer - Add a newline here to mark the end of the onion message
    let final_onion = format!("{}\n", layer);  // Adding the newline at the very end

    // after completing all layers, `layer` now represents the fully encrypted onion
    Ok(final_onion)
}