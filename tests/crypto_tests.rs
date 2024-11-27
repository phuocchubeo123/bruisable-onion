use bruise_onion::crypto::{generate_pubkey_list, dump_pubkey_list, dump_seckey_list, read_pubkey_list, read_seckey_list};
use rsa::{pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPrivateKey, EncodeRsaPublicKey, LineEnding}, sha2::Sha256, Oaep, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use rsa::traits::{PublicKeyParts, PrivateKeyParts};
use rand::{rngs::OsRng, Rng};
use std::thread;
use std::time::Duration;

fn are_keys_compatible(privkey: &RsaPrivateKey, pubkey: &RsaPublicKey) -> bool {
    let mut rng = OsRng;
    let message = b"test message";
    println!("Starting compatibility check...");

    // Encrypt with the public key
    let encrypted = match pubkey.encrypt(&mut rng, Pkcs1v15Encrypt, message) {
        Ok(data) => {
            println!("Encryption with public key succeeded.");
            data
        }
        Err(e) => {
            println!("Encryption with public key failed: {}", e);
            return false;
        }
    };

    // Decrypt with the private key
    let decrypted = match privkey.decrypt(Pkcs1v15Encrypt, &encrypted) {
        Ok(data) => {
            println!("Decryption with private key succeeded.");
            data
        }
        Err(e) => {
            println!("Decryption with private key failed: {}", e);
            return false;
        }
    };

    // Check if the decrypted message matches the original
    if decrypted == message {
        println!("Decrypted message matches the original. Keys are compatible.");
        true
    } else {
        println!("Decrypted message does NOT match the original. Keys are NOT compatible.");
        false
    }
}

#[test]
fn test_key_read_write() {
    let n = 2;
    let (ids, seckeys, pubkeys) = generate_pubkey_list(n);

    for i in 0..n {
        let pubkey = pubkeys[i].clone();
        let seckey = seckeys[i].clone();
        println!("Params: {}, {}, {}", seckey.n(), seckey.primes()[0], seckey.primes()[1]);

        let seckey_pem = seckey.to_pkcs1_pem(LineEnding::LF).expect("failed to encode public key to PEM");
        println!("{:?}", seckey_pem);
        println!("Is there a difference?\n{}", *seckey_pem);
        let seckey2 = RsaPrivateKey::from_pkcs1_pem(&(*seckey_pem)).expect("failed to parse public key from PEM");

        let compat = are_keys_compatible(&seckey2, &pubkey);
        if compat {
            println!("Generated {}-th key pair successfully!", i);
        } else {
            println!("Generated {}-th key pair failed!", i);
        }
    }

    match dump_pubkey_list(&ids, &pubkeys, "PKTest.txt") {
        Ok(_) => println!("Successfully written pseudo keys to PKKeys.txt!"),
        Err(e) => eprintln!("Failed to write to PKKeys.txt: {}", e),
    };

    match dump_seckey_list(&ids, &seckeys, "SKTest.txt") {
        Ok(_) => println!("Successfully written secret keys of intermediate nodes to SKKeys.txt!"),
        Err(e) => eprintln!("Failed to write to SKKeys.txt: {}", e),
    }

    println!("Sleeping for 1 second...");
    thread::sleep(Duration::from_secs(1));
    println!("Woke up after 1 second!");

    let (ids, new_pubkeys) = read_pubkey_list("PKTest.txt").expect("Failed to read server public keys from PKTest.txt");
    let (ids_2, new_seckeys) = read_seckey_list("SKTest.txt").expect("Failed to read server secret keys from SKTest.txt");

    for i in 0..n {
        let pubkey = new_pubkeys[i].clone();
        let seckey = new_seckeys[i].clone();

        println!("Params: {}, {}, {}", seckey.n(), seckey.primes()[0], seckey.primes()[1]);

        let compat = are_keys_compatible(&seckey, &pubkey);
        if compat {
            println!("Read {}-th key pair successfully!", i);
        } else {
            println!("Read {}-th key pair failed!", i);
        }
    }
}