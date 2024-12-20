extern crate rand;
extern crate ed25519_dalek;
extern crate x25519_dalek;

use rand::rngs::OsRng;
use rand::{Rng, RngCore};
use ed25519_dalek::{Keypair, PublicKey as Ed25519PublicKey, SecretKey as Ed25519SecretKey};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, SharedSecret};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, BufRead, Write, self};
use base64::decode;
use std::io::{BufReader};
use std::path::Path;
use ed25519_dalek::{SecretKey, PublicKey};
use base64::encode;
use std::io::Result;

pub fn generate_pubkey_list(n: usize) -> (Vec<String>, Vec<EphemeralSecret>, Vec<X25519PublicKey>) {
    let mut ids = Vec::new();
    let mut secrets = Vec::new();
    let mut public_keys = Vec::new();

    let mut rng = OsRng; // Initialize OsRng here

    for i in 1..=n {
        let id = format!("Node {}", i);
        let secret = EphemeralSecret::new(&mut rng); // Pass a mutable reference to OsRng
        let public_key = X25519PublicKey::from(&secret);

        ids.push(id);
        secrets.push(secret);
        public_keys.push(public_key);
        println!("Created keys for id {}", i);
    }

    (ids, secrets, public_keys)
}

pub fn generate_pubkey() -> std::io::Result<(EphemeralSecret, X25519PublicKey)> {
    let mut rng = OsRng; // Initialize OsRng here // Use SystemRandom here for cryptographically secure randomness
    let secret = EphemeralSecret::new(&mut rng); // Generate the private key (EphemeralSecret)
    let public_key = X25519PublicKey::from(&secret); // Derive the public key from the secret

    Ok((secret, public_key)) // Return both the secret and public key
}

// Serialize public keys to file
pub fn dump_pubkey_list(ids: &Vec<String>, public_keys: &[X25519PublicKey], filename: &str) -> std::io::Result<()> {
    let path = Path::new(filename);
    let file = File::create(&path)?;
    let mut writer = BufWriter::new(file);

    for (id, public_key) in ids.iter().zip(public_keys.iter()) {
        writeln!(writer, "ID: {}", id)?;
        writeln!(writer, "Public Key: {}", hex::encode(public_key.as_bytes()))?;
    }

    Ok(())
}

pub fn dump_seckey_list(ids: &Vec<String>, seckeys: &[SecretKey], filename: &str) -> std::io::Result<()> {
    let path = Path::new(filename);
    let file = File::create(&path)?;
    let mut writer = BufWriter::new(file);

    for (id, seckey) in ids.iter().zip(seckeys.iter()) {
        // Write the ID
        writeln!(writer, "ID: {}", id)?;
        // Write the secret key in Base64 format
        let seckey_base64 = encode(seckey.as_bytes());
        writeln!(writer, "{}", seckey_base64)?;
    }

    Ok(())
}

pub fn read_pubkey_list(filename: &str) -> std::io::Result<(Vec<String>, Vec<PublicKey>)> {
    let path = Path::new(filename);
    let file = File::open(&path)?;
    let reader = BufReader::new(file);

    let mut ids = Vec::new();
    let mut pubkeys = Vec::new();

    for line in reader.lines() {
        let line = line?;
        if line.starts_with("ID: ") {
            let id = line["ID: ".len()..].trim().to_string();
            ids.push(id);
        } else {
            // Assume the next line is a Base64-encoded public key
            let decoded_key = decode(&line).expect("failed to decode Base64 public key");
            let pubkey = PublicKey::from_bytes(&decoded_key).expect("failed to parse public key");
            pubkeys.push(pubkey);
        }
    }

    Ok((ids, pubkeys))
}

pub fn read_seckey_list(filename: &str) -> std::io::Result<(Vec<String>, Vec<SecretKey>)> {
    let path = Path::new(filename);
    let file = File::open(&path)?;
    let reader = BufReader::new(file);

    let mut ids = Vec::new();
    let mut seckeys = Vec::new();

    for line in reader.lines() {
        let line = line?;
        if line.starts_with("ID: ") {
            let id = line["ID: ".len()..].trim().to_string();
            ids.push(id);
        } else {
            // Assume the next line is a Base64-encoded secret key
            let decoded_key = decode(&line).expect("failed to decode Base64 secret key");
            let seckey = SecretKey::from_bytes(&decoded_key).expect("failed to parse secret key");
            seckeys.push(seckey);
        }
    }

    Ok((ids, seckeys))
}

pub fn reset_user_list(filename: &str) -> std::io::Result<()> {
    File::create(filename)?;
    Ok(())
}


pub fn update_user_list(filename: &str, id: &String, pubkey: &PublicKey) -> Result<()> {
    let mut file = OpenOptions::new()
        .append(true) // append to the currently existing list of users
        .create(true)
        .open(filename)?;
    let mut writer = BufWriter::new(file);

    // Write the id
    writeln!(writer, "ID: {}", id)?;

    // Write the pubkey as bytes (Ed25519 keys are typically encoded as 32-byte arrays)
    let pubkey_bytes = pubkey.as_bytes();
    writeln!(writer, "PubKey: {:x?}", pubkey_bytes)?;

    Ok(())
}

pub fn sample_random_path(l: usize, ids: &Vec<String>, pubkeys: &[PublicKey]) -> Result<(Vec<String>, Vec<PublicKey>)> {
    let mut rng = rand::thread_rng();
    let mut random_ids = Vec::with_capacity(l);
    let mut random_pubkeys = Vec::with_capacity(l);

    for _ in 0..l {
        let mut num = rng.gen_range(0..ids.len());
        while random_ids.last() == Some(&ids[num]) {
            num = rng.gen_range(0..ids.len());
        }
        random_ids.push(ids[num].clone());
        random_pubkeys.push(pubkeys[num].clone());
    }

    Ok((random_ids, random_pubkeys))
}

// pub struct Onion {
//     onion: Vec<u8>,
// }

// impl Onion {
//     pub fn new(&mut self, msg: &[u8], ids: &[usize], pubkeys: &[RsaPublicKey]) -> Result<(), Box<dyn std::error::Error>> {

//         for layer in (0..ids.len()).rev() {
//             // Get layer id and pubkey
//             let id = ids[layer];
//             let pubkey = pubkeys[layer].clone();

//             // Serialize layer data
//             let data = (id, self.onion.clone());
//             let serialized_data = bincode::serialize(&data)?;

//             // Encrypt the layer
//             let padding_scheme = Oaep::new::<Sha256>();
//             self.onion = pubkey.encrypt(&mut OsRng, padding_scheme, &serialized_data)?;
//         }

//         Ok(())
//     }

//     pub fn peel(&mut self, seckey: &RsaPrivateKey) -> Result<usize, Box<dyn std::error::Error>> {
//         let padding_scheme = Oaep::new::<Sha256>();
//         let serialized_data = seckey.decrypt(padding_scheme, &self.onion)?;

//         // Deserialize the data and take the next id and new onion
//         let (id, new_onion): (usize, Vec<u8>) = bincode::deserialize(&serialized_data)?;
//         self.onion = new_onion.clone();

//         Ok(id)
//     }
// }