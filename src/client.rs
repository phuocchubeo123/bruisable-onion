extern crate rsa;
mod crypto;

use std::net::TcpStream;
use std::io::{self, Write, Read};
use std::thread;
use crypto::{read_pubkey_list, sample_random_path, generate_pubkey};
use rsa::pkcs1::{EncodeRsaPublicKey, LineEnding};

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
            let (ids, pubkeys) = read_pubkey_list("PKKeys.txt").unwrap();
            println!("Downloaded the pubkey list!");
            ////////
            
            // Read the users list from UserKeys.txt
            let (existed_users, existed_pubkeys) = read_pubkey_list("UserKeys.txt").unwrap();
            println!("Downloaded the users list!");

            // Spawn a thread to listen for incoming messages
            let mut read_stream = stream.try_clone().unwrap();
            thread::spawn(move || {
                // TODO: Add something so that the listener knows when a new user has joined
                let mut buffer = [0; 512];
                while match read_stream.read(&mut buffer) {
                    Ok(size) if size > 0 => {
                        println!("Received: {}", String::from_utf8_lossy(&buffer[..size]));
                        true
                    }
                    Ok(_) | Err(_) => false,
                } {}
            });

            // Send messages in the main thread
            loop {
                println!("Enter recipient:");
                let mut recipient = String::new();
                io::stdin().read_line(&mut recipient).unwrap();
                // Now we need to sample a random path and encrypt the message
                let (mut random_ids, mut random_pubkeys) = sample_random_path(3, &ids, &pubkeys).unwrap(); // Currently I set the path length to be 3
                random_ids.push(recipient);
                // TODO: How do we update the existed users list here, and how to efficiently find the matching pubkey?
                
                // stream.write_all(message.as_bytes()).unwrap();
            }
        }
        Err(e) => {
            println!("Failed to connect: {}", e);
        }
    }
}