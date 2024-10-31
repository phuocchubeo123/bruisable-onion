mod crypto;

use std::net::TcpStream;
use std::io::{self, Write, Read};
use std::thread;
use crypto::{read_pubkey_list, sample_random_path};

fn main() {
    match TcpStream::connect("127.0.0.1:7878") {
        Ok(mut stream) => {
            println!("Successfully connected to server on port 7878");

            // Prompt for username
            println!("Enter your username:");
            let mut username = String::new();
            io::stdin().read_line(&mut username).unwrap();
            stream.write_all(username.trim().as_bytes()).unwrap();

            // phuoc: Read the pubkey list from PKkeys.txt
            let (ids, pubkeys) = read_pubkey_list("PKkeys.txt").unwrap();
            println!("Downloaded the pubkey list!");
            ////////

            // Spawn a thread to listen for incoming messages
            let mut read_stream = stream.try_clone().unwrap();
            thread::spawn(move || {
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
                println!("Enter recipient and message (format: recipient: message):");
                let mut message = String::new();
                io::stdin().read_line(&mut message).unwrap();

                // Now we need to sample a random path and encrypt the message
                let (random_ids, random_pubkeys) = sample_random_path(3, &ids, &pubkeys).unwrap(); // Currently I set the path length to be 3
                //////////
                
                stream.write_all(message.as_bytes()).unwrap();
            }
        }
        Err(e) => {
            println!("Failed to connect: {}", e);
        }
    }
}