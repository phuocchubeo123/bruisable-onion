extern crate rsa;
mod crypto;

use crypto::{generate_pubkey_list, dump_pubkey_list, reset_user_list, update_user_list};
use rsa::{RsaPublicKey, pkcs1::DecodeRsaPublicKey};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::thread;

fn handle_client(mut stream: TcpStream, clients: Arc<Mutex<HashMap<String, TcpStream>>>) {
    let mut buffer = [0; 512];

    //step 1: receive and store  username for this client, trim null characters
    stream.read(&mut buffer).unwrap();
    let username_and_pem = String::from_utf8_lossy(&buffer[..])
        .trim_matches(char::from(0))
        .trim()
        .to_string();

    // TODO: Add error checking here

    let mut lines = username_and_pem.lines();

    let username = lines.next().unwrap().to_string();

    // Every other lines join together to create a PEM
    let pem = lines.collect::<Vec<&str>>().join("\n");
    let pubkey = RsaPublicKey::from_pkcs1_pem(&pem).expect("Failed to parse public key from PEM");

    println!("User '{}' connected.", username);
    println!("User '{} PEM: {}", username, pem);

    match update_user_list("UserKeys.txt", &username, &pubkey) {
        Ok(_) => println!("Added user to list of existing users!"),
        Err(e) => eprintln!("Error adding user to list of existing users: {}", e),
    };

    //step 2: add client to  HashMap and confirm addition
    {
        let mut clients = clients.lock().unwrap();
        clients.insert(username.clone(), stream.try_clone().unwrap());
        println!("Current users: {:?}", clients.keys().collect::<Vec<_>>());
    }

    loop {
        //step 3: Listen for messages
        let size = match stream.read(&mut buffer) {
            Ok(size) if size > 0 => size,
            _ => break,
        };

        //parse message in format "recipient: message"
        let message = String::from_utf8_lossy(&buffer[..size]).to_string();
        let parts: Vec<&str> = message.splitn(2, ": ").collect();

        if parts.len() == 2 {
            let recipient = parts[0].trim().to_string();
            let message_content = format!("{}: {}", username, parts[1]);

            //lock HashMap before trying to send the message
            let clients = clients.lock().unwrap();
            if let Some(mut recipient_stream) = clients.get(&recipient) {
                println!("Sending message to '{}': {}", recipient, message_content);
                recipient_stream.write_all(message_content.as_bytes()).unwrap();
            } else {
                println!("User '{}' not found.", recipient);
            }
        }
    }

    //remove client from list on disconnect
    {
        let mut clients = clients.lock().unwrap();
        clients.remove(&username);
        println!("User '{}' disconnected. Remaining users: {:?}", username, clients.keys().collect::<Vec<_>>());
    }
}

fn main() {
    let listener = TcpListener::bind("127.0.0.1:7878").unwrap();
    let clients = Arc::new(Mutex::new(HashMap::new()));

    // phuoc: generate public keys, private keys and write to PKKeys.txt
    println!("Enter the number of intermediate clients: ");
    let mut input_string = String::new();
    io::stdin().read_line(&mut input_string).unwrap();
    let n: usize = input_string.trim().parse().expect("Expect a positive integer!");
    let (ids, seckeys, pubkeys) = generate_pubkey_list(n);

    match dump_pubkey_list(&ids, &pubkeys, "PKKeys.txt") {
        Ok(_) => println!("Successfully written pseudo keys to PKKeys.txt!"),
        Err(e) => eprintln!("Failed to write to PKKeys.txt: {}", e),
    };
    //////
    
    // phuoc: reset users list
    match reset_user_list("UserKeys.txt") {
        Ok(_) => println!("Reseted the list in UserKeys.txt!"),
        Err(e) => eprintln!("Failed to reset UserKeys.txt: {}", e),
    };


    println!("Server listening on port 7878");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let clients_clone = Arc::clone(&clients);
                thread::spawn(move || {
                    handle_client(stream, clients_clone);
                });
            }
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }
}