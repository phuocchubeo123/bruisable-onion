use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, SocketAddr};
use std::sync::mpsc;
use std::thread;

const LOCAL: &str = "127.0.0.1:6000";
const MSG_SIZE: usize = 32;

fn sleep() {
    thread::sleep(::std::time::Duration::from_millis(100));
}

fn main() {
    let server = TcpListener::bind(LOCAL).expect("Listener failed to bind.");
    server.set_nonblocking(true).expect("Failed to initiate non-blocking!");

    let mut clients = vec![];
    let (tx, rx) = mpsc::channel::<(String, std::net::SocketAddr)>();
    loop {
        if let Ok((mut socket, addr)) = server.accept() {
            println!("Client {} connected!", addr);

            let tx = tx.clone();
            clients.push(socket.try_clone().expect("Failed to clone client."));

            thread::spawn(move || loop {
                let mut buff = vec![0; MSG_SIZE];

                match socket.read_exact(&mut buff) {
                    Ok(_) => {
                        let msg = buff.into_iter().take_while(|&x| x != 0).collect::<Vec<_>>();
                        let msg = String::from_utf8(msg).expect("Invalid utf8 message!");

                        println!("{}: {:?}", addr, msg);

                        let send_msg = format!("From {}: {:?}", addr, msg);
                        tx.send((send_msg, addr)).expect("failed to send msg to rx");
                    }
                    Err(ref err) if err.kind() == ErrorKind::WouldBlock => (),
                    Err(_) => {
                        println!("Closing conection with {}.", addr);
                        break;
                    }
                }

                sleep();
            });
        }

        if let Ok((msg, sender_addr)) = rx.try_recv() {
            clients = clients.into_iter().filter_map(|mut client| {
                // Check if the client's address is not the sender's address
                if client.peer_addr().expect("Failed to get peer address") != sender_addr {
                    let mut buff = msg.clone().into_bytes();
                    buff.resize(MSG_SIZE, 0);

                    // Try to send the message, and keep the client in the list if successful
                    client.write_all(&buff).map(|_| client).ok()
                } else {
                    Some(client)  // If it's the sender, skip sending but keep the client
                }
            }).collect::<Vec<_>>();
        }

        sleep();
    }
}