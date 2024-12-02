extern crate rsa;
extern crate rand;

use rsa::{RsaPrivateKey, RsaPublicKey, Oaep, sha2::Sha256, pkcs1::{EncodeRsaPublicKey, DecodeRsaPublicKey, EncodeRsaPrivateKey, DecodeRsaPrivateKey, LineEnding}};
use rand::{rngs::OsRng, Rng};
use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, BufRead, Write};
use std::path::Path;
use bincode;

pub fn generate_pubkey_list(n: usize) -> (Vec<String>, Vec<RsaPrivateKey>, Vec<RsaPublicKey>) {
    let mut ids = Vec::new();
    let mut seckeys = Vec::new();
    let mut pubkeys = Vec::new();

    for i in 1..=n {
        let id = format!("Node {}", i);
        let mut rng = OsRng;
        let seckey = RsaPrivateKey::new(&mut rng, 2048).expect("failed to generate private key");
        let pubkey = RsaPublicKey::from(&seckey);

        ids.push(id);
        seckeys.push(seckey);
        pubkeys.push(pubkey);
        println!("Created keys for id {}", i);
    }

    (ids, seckeys, pubkeys)
}

pub fn generate_pubkey() -> std::io::Result<(RsaPrivateKey, RsaPublicKey)> {
    let mut rng = OsRng;
    let seckey = RsaPrivateKey::new(&mut rng, 2048).expect("failed to generate private key");
    let pubkey = RsaPublicKey::from(&seckey);

    Ok((seckey, pubkey))
}

pub fn dump_pubkey_list(ids: &Vec<String>, pubkeys: &[RsaPublicKey], filename: &str) -> std::io::Result<()> {
    let path = Path::new(filename);
    let file = File::create(&path)?;
    let mut writer = BufWriter::new(file);

    for (id, pubkey) in ids.iter().zip(pubkeys.iter()) {
        // Write the ID
        writeln!(writer, "ID: {}", id)?;
        // Write the public key in PKCS#1 PEM format
        let pubkey_pem = pubkey.to_pkcs1_pem(LineEnding::LF).expect("failed to encode public key to PEM");
        writeln!(writer, "{}", pubkey_pem)?;
    }

    Ok(())
}

pub fn dump_seckey_list(ids: &Vec<String>, seckeys: &[RsaPrivateKey], filename: &str) -> std::io::Result<()> {
    let path = Path::new(filename);
    let file = File::create(&path)?;
    let mut writer = BufWriter::new(file);

    for (id, seckey) in ids.iter().zip(seckeys.iter()) {
        // Write the ID
        writeln!(writer, "ID: {}", id)?;
        // Write the public key in PKCS#1 PEM format
        let seckey_pem = seckey.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF).expect("failed to encode public key to PEM");
        writeln!(writer, "{}", *seckey_pem)?;
    }

    Ok(())
}

pub fn read_pubkey_list(filename: &str) -> std::io::Result<(Vec<String>, Vec<RsaPublicKey>)> {
    let path = Path::new(filename);
    let file = File::open(&path)?;
    let mut reader = io::BufReader::new(file);

    let mut ids = Vec::new();
    let mut pubkeys = Vec::new();
    let mut buffer = String::new();

    while reader.read_line(&mut buffer)? > 0 {
        // println!("Current line: {}", buffer);
        if buffer.starts_with("ID: ") {
            let id = buffer["ID: ".len()..].trim().parse::<String>().expect("failed to parse ID");
            ids.push(id);
            buffer.clear();
        } else if buffer.starts_with("-----BEGIN RSA PUBLIC KEY-----") {
            let mut pem = buffer.clone();
            buffer.clear();
            while reader.read_line(&mut buffer)? > 0 {
                pem.push_str(&buffer);
                if buffer.starts_with("-----END RSA PUBLIC KEY-----") {
                    buffer.clear();
                    // println!("FOUND AN END: {}", buffer);
                    break;
                }
                buffer.clear();
            }

            // println!("Current PEM: {}", pem);
            let pubkey = RsaPublicKey::from_pkcs1_pem(&pem).expect("failed to parse public key from PEM");
            pubkeys.push(pubkey);
        }
        buffer.clear();
    }

    Ok((ids, pubkeys))
}

pub fn read_seckey_list(filename: &str) -> std::io::Result<(Vec<String>, Vec<RsaPrivateKey>)> {
    let path = Path::new(filename);
    let file = File::open(&path)?;
    let mut reader = io::BufReader::new(file);

    let mut ids = Vec::new();
    let mut seckeys = Vec::new();
    let mut buffer = String::new();

    while reader.read_line(&mut buffer)? > 0 {
        // println!("Current line: {}", buffer);
        if buffer.starts_with("ID: ") {
            let id = buffer["ID: ".len()..].trim().parse::<String>().expect("failed to parse ID");
            ids.push(id);
            buffer.clear();
        } else if buffer.starts_with("-----BEGIN RSA PRIVATE KEY-----") {
            let mut pem = buffer.clone();
            buffer.clear();
            while reader.read_line(&mut buffer)? > 0 {
                pem.push_str(&buffer);
                if buffer.starts_with("-----END RSA PRIVATE KEY-----") {
                    buffer.clear();
                    // println!("FOUND AN END: {}", buffer);
                    break;
                }
                buffer.clear();
            }

            // println!("Current PEM: {}", pem);
            let seckey = RsaPrivateKey::from_pkcs1_pem(&pem).expect("failed to parse secret key from PEM");
            seckeys.push(seckey);
        }
        buffer.clear();
    }

    Ok((ids, seckeys))
}

pub fn reset_user_list(filename: &str) -> std::io::Result<()> {
    File::create(filename)?;
    Ok(())
}

pub fn update_user_list(filename: &str, id: &String, pubkey: &RsaPublicKey) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .append(true) // append to the currently existing list of users
        .create(true)
        .open(filename)?;
    let mut writer = BufWriter::new(file);

    // Write the id
    writeln!(writer, "ID: {}", id)?;
    // Write the pubkey
    let pubkey_pem = pubkey.to_pkcs1_pem(LineEnding::LF).expect("failed to encode public key to PEM");
    writeln!(writer, "{}", pubkey_pem)?;

    Ok(())
}

pub fn sample_random_path(l: usize, ids: &Vec<String>, pubkeys: &[RsaPublicKey]) -> std::io::Result<(Vec<String>, Vec<RsaPublicKey>)> {
    // Sample a random path from the list of public keys
    // Two adjacent nodes must not be equal

    let mut rng = rand::thread_rng();
    let mut random_path = Vec::with_capacity(l);
    let mut random_ids = Vec::with_capacity(l);
    let mut random_pubkeys = Vec::with_capacity(l);

    for _ in 0..l {
        let mut num = rng.gen_range(0..ids.len());
        while random_path.last() == Some(&num) {
            num = rng.gen_range(0..ids.len());
        }
        random_path.push(num);
        random_ids.push(ids[num].clone());
        random_pubkeys.push(pubkeys[num].clone());
    }

    Ok((random_ids, random_pubkeys))
}

pub struct Onion {
    onion: Vec<u8>,
}

impl Onion {
    pub fn new(&mut self, msg: &[u8], ids: &[usize], pubkeys: &[RsaPublicKey]) -> Result<(), Box<dyn std::error::Error>> {

        for layer in (0..ids.len()).rev() {
            // Get layer id and pubkey
            let id = ids[layer];
            let pubkey = pubkeys[layer].clone();

            // Serialize layer data
            let data = (id, self.onion.clone());
            let serialized_data = bincode::serialize(&data)?;

            // Encrypt the layer
            let padding_scheme = Oaep::new::<Sha256>();
            self.onion = pubkey.encrypt(&mut OsRng, padding_scheme, &serialized_data)?;
        }

        Ok(())
    }

    pub fn peel(&mut self, seckey: &RsaPrivateKey) -> Result<usize, Box<dyn std::error::Error>> {
        let padding_scheme = Oaep::new::<Sha256>();
        let serialized_data = seckey.decrypt(padding_scheme, &self.onion)?;

        // Deserialize the data and take the next id and new onion
        let (id, new_onion): (usize, Vec<u8>) = bincode::deserialize(&serialized_data)?;
        self.onion = new_onion.clone();

        Ok(id)
    }
}