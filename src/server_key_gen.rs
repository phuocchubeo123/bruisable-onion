#![allow(warnings)]
mod crypto;
mod intermediary_node;
mod tulip;
mod shared;
mod globals;
use std::io::{self};
use crypto::{generate_pubkey_list, dump_pubkey_list, dump_seckey_list};


fn main() {
    // Generate keys and save them
    println!("Enter the number of intermediate clients: ");
    let mut input_string = String::new();
    io::stdin().read_line(&mut input_string).unwrap();
    let n: usize = input_string.trim().parse().expect("Expected a positive integer!");
    let (ids, seckeys, pubkeys) = generate_pubkey_list(n);
    println!("Successfully generated server keys!");

    match dump_pubkey_list(&ids, &pubkeys, "PKKeys.txt") {
        Ok(_) => println!("Successfully written server public keys to PKKeys.txt!"),
        Err(e) => eprintln!("Failed to write to PKKeys.txt: {}", e),
    };

    match dump_seckey_list(&ids, &seckeys, "SKKeys.txt") {
        Ok(_) => println!("Successfully written server secret keys to SKKeys.txt!"),
        Err(e) => eprintln!("Failed to write to SKKeys.txt: {}", e),
    }

}