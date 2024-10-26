use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::thread;

fn handle_client(mut stream: TcpStream, clients: Arc<Mutex<HashMap<String, TcpStream>>>) {
    let mut buffer = [0; 512];

    //step 1: receive and store  username for this client, trim null characters
    stream.read(&mut buffer).unwrap();
    let username = String::from_utf8_lossy(&buffer[..])
        .trim_matches(char::from(0))
        .trim()
        .to_string();
    println!("User '{}' connected.", username);

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