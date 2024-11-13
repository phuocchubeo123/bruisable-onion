extern crate rsa;
extern crate sha2;

use std::{cmp::max, str};
use rsa::pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey, LineEnding};
use rsa::{RsaPublicKey, RsaPrivateKey, Pkcs1v15Encrypt}; 
use std::collections::HashMap;
use base64::{engine::general_purpose::STANDARD, Engine};
use rand::{rngs::OsRng, RngCore};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Key, Nonce
}; 
use sha2::{Sha256, Digest};

// phuoc: tulip encryption
// COMPILED BUT NOT TESTED
pub fn tulip_encrypt(
    message: &str,
    recipient_pubkey: &RsaPublicKey,
    recipient_id: &str,
    mixers: &[(&str, &RsaPublicKey)],
    gatekeepers: &[(&str, &RsaPublicKey)],
    y: &[&[u8; 12]],
    max_bruise: &usize
) -> Result<String, Box<dyn std::error::Error>> {
    let mut rng = OsRng; 
    let l1 = mixers.len(); // Number of Mixers
    let l2 = gatekeepers.len(); // Number of Gatekeepers
    let l = l1 + l2 + 1;

    // Step 1: Generating layer keys and master key
    let k: Vec<_> = (0..l)  // layer keys
        .map(|_| Aes256Gcm::generate_key(&mut rng))
        .collect(); 

    let master_key = Aes256Gcm::generate_key(&mut rng); // master key

    // Step 2: Forming the first sepal S for the first mixer
    let mut S_nonce = Vec::<_>::new();
    let mut S_enc = Vec::<_>::new();

    for master_key_block in 0..max_bruise.clone() {
        let mut enc_master_key = master_key.as_slice().to_vec(); // stupid workaround to copy the master key
        let nonce = Aes256Gcm::generate_nonce(&mut rng); // Currently, I use the same nonce for every layer, I hope that it is safe
        for layer_key in k.iter().take(l-1).rev() { // iterate from near-last to first
            let aes_gcm = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&layer_key));
            enc_master_key = aes_gcm.encrypt(&nonce, enc_master_key.as_slice()).expect("Encryption Failed!");
        }

        S_nonce.push(nonce);
        S_enc.push(enc_master_key);
    }

    for null_block in 0..(l1 - max_bruise + 1) {
        let mut enc_null = vec![0u8; master_key.as_slice().to_vec().len()]; // more stupid workaround to have null string with the same length as master key
        let nonce = Aes256Gcm::generate_nonce(&mut rng); // Currently, I use the same nonce for every layer, I hope that it is safe
        for layer_key in k.iter().take(l1+1).rev() { // iterate from first gatekeeper to first
            let aes_gcm = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&layer_key));
            enc_null = aes_gcm.encrypt(&nonce, enc_null.as_slice()).expect("Encrypt Null failed!");
        }

        S_nonce.push(nonce);
        S_enc.push(enc_null);
    }

    // Creating the clasp

    // Creating Tij
    let mut T = Vec::<Vec<_>>::new(); // Tij is the sepal block S1j without the i-1 outermost encryption layers
    T.push(S_enc.clone());
    for (layer_id, layer_key) in (1..l).zip(k.iter().take(l-1)) { // each time peel one layer, left to right
        let aes_gcm = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&layer_key));
        let Ti: Vec<_> = (0..(l1+1))
            .map(|i| aes_gcm.decrypt(&S_nonce[i], T[layer_id-1][i].as_slice()).expect("Cannot decrypt the sepal layer"))
            .collect();
        T.push(Ti);
    }

    // The hash that contains the dummy sepal block would not matter!
    for i in 0..l1 {  // Put a dummy sepal block T_{i, l1+2} in
        let mut enc_rand = vec![0u8; master_key.as_slice().to_vec().len()]; // placeholder for random string with the same length as the master key
        OsRng.fill_bytes(&mut enc_rand); // fill enc_rand with random bytes
        let nonce = Nonce::from_slice(&[0; 12]); // Zero-nonce is okay since it's random anyway 
        for layer_key in k.iter().take(l-1).rev() { // iterate from last gatekeeper to first
            let aes_gcm = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&layer_key));
            enc_rand = aes_gcm.encrypt(&nonce, enc_rand.as_slice()).expect("Creating Clasp: Encrypt rand failed!");
        }
        T[i].push(enc_rand);
    }

    // Creating Aij, vAi

    let mut vA = Vec::<String>::new(); // vA stores all the vAi

    for i in 0..l {
        // hash the ring
        let ell = max(1, l1 + 2 - i);
        let mut vAi = Vec::<_>::new();
        for j in 0..(l1+1) {   // hash the ring
            if i < j && j < l1 + 1 { continue;}
            let mut hasher = Sha256::new();
            for jj in 0..ell {
                hasher.update(T[i][(j + jj) % (l1 + 2)].clone());
            }
            let Aij = hasher.finalize();
            vAi.push(Aij);
        }
        vAi.sort();

        // I try to turn the hashes in vAi into strings and concatenate them here.
        let vAi_string = vAi
            .iter()
            .map(|x| STANDARD.encode(x))
            .collect::<Vec<_>>()
            .join(",");

        vA.push(vAi_string);
    }


    // Step 2: Forming the header and content for the last onion layer
    // indexed l-1 on the path

    // Create content 
    // Global c is for the content

    let aes_gcm_last = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&k[l-1]));
    let nonce_last = Nonce::from_slice(&[0; 12]); // Zero-nonce for the recipient
    let mut c = aes_gcm_last.encrypt(nonce_last, message.as_bytes())?;   // universal variable for content

    // Create header
    // Global E is for the encrypted metadata
    // Global H is for header

    let mut hasher_last = Sha256::new();
    hasher_last.update(c.clone());
    let t_last = hasher_last.finalize(); // tag for the last layer
    let e_last = format!(
        "Recipient|{}|{}|{}", // role, tag, hop index, layer key
        STANDARD.encode(&t_last),
        l-1,
        STANDARD.encode(&k[l-1]),
    );
    let mut E = recipient_pubkey.encrypt(&mut rng, Pkcs1v15Encrypt, &e_last.as_bytes())?;
    let mut H = format!(  // H_l = E_l
        "{}",
        STANDARD.encode(&E) //lower case e decrypted/plaintext, E encrypted/ciphertext
    ); 


    // Step 3: Forming the header and content for the last gatekeeper
    // indexed l2-1 in the gatekeepers list
    // indexed l-2 in the nonce list
    // indexed l-2 on the path

    // Create content
    let aes_gcm_gatekeeper_last = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&master_key));
    let nonce_gatekeeper_last = Nonce::from_slice(y[l-2]); // last gatekeeper nonce for simplicity
    let c = aes_gcm_gatekeeper_last.encrypt(nonce_gatekeeper_last, c.as_slice())?; // content for the last gatekeeper is the encryption of c_last under master_key

    // Global B array for later use also
    let mut B =  Vec::<_>::new();

    let b = format!(   // b_{l-1, 1} = (recipient_id, E_l)
        "{}|{}",
        recipient_id,
        STANDARD.encode(&E)
    );
    B.push(aes_gcm_gatekeeper_last.encrypt(nonce_gatekeeper_last, b.as_bytes()).expect("Cannot encrypt B_{l-1, 1}")); // currently only has B[0]

    // Create tag

    let mut hasher_gatekeeper_last = Sha256::new();
    hasher_gatekeeper_last.update(B[0].clone());
    hasher_gatekeeper_last.update(c.clone());
    let t_gatekeeper_last = hasher_gatekeeper_last.finalize(); // tag for the last gatekeeper

    // Create header

    let e_gatekeeper_last = format!(
        "LastGatekeeper|{}|{}|{}|{}|{}", //role, tag, hop index, layer key, nonce, vector sorted hashes
        STANDARD.encode(&t_gatekeeper_last),
        l-2,
        STANDARD.encode(&k[l-2]),
        STANDARD.encode(y[l-2]),
        vA[l-2],
    );

    let (id_gatekeeper_last, pubkey_gatekeeper_last) = gatekeepers[l2-1];
    E = pubkey_gatekeeper_last.encrypt(&mut rng, Pkcs1v15Encrypt, e_gatekeeper_last.as_bytes())?; // E is encrypted with the pubkey of this node
    H = format!(
        "{}|{}",
        STANDARD.encode(&E),
        STANDARD.encode(&B[0])
    );


    // Step 4: Forming the outer gatekeepers layers
    // indexed from l2-2 to 0 in the gatekeepers list
    // indexed from l-3 to l-l2-1 = l1 in the nonce list
    // indexed from l-3 to l-l2-1 = l1 on the path

    for current_id in (0..(l2-1)).rev() { // current_id from l2-2 to 0
        let hop_index = current_id + l1; 

        let next_gatekeeper_id = gatekeepers[current_id+1].0; // I_{i+1}
        let current_gatekeeper_pubkey = gatekeepers[current_id].1; // pk(P_i)
        let current_layer_key = k[hop_index]; // k_i
        let current_layer_nonce = y[hop_index]; // y_i

        let aes_gcm_gatekeeper = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&current_layer_key));
        let nonce_gatekeeper = Nonce::from_slice(current_layer_nonce); // Constant nonce for simplicity
        let c = aes_gcm_gatekeeper.encrypt(nonce_gatekeeper, c.as_slice())?;  // content

        for i in 0..B.len() {
            B[i] = aes_gcm_gatekeeper.encrypt(nonce_gatekeeper, B[i].as_slice()).expect("Cannot encrypt new B");
        }

        // Create b_{i, 1} //wrap B's in opposite order
        let b_gatekeeper = format!( // b_{i, 1} = (I_{i+1}, E_{i+1}})
            "{}|{}",
            next_gatekeeper_id,
            STANDARD.encode(&E)
        );
        B.push(aes_gcm_gatekeeper.encrypt(nonce_gatekeeper, b.as_bytes()).expect("Cannot encrypt B")); // B_{i, 1} is b_{i, 1} encrypted with k_i

        // Create tag t
        let mut hasher_gatekeeper = Sha256::new();
        for bij in B.iter().rev() {
            hasher_gatekeeper.update(bij);
        }
        hasher_gatekeeper.update(c);
        let t_gatekeeper = hasher_gatekeeper.finalize(); // the tag

        // Create E
        let e_gatekeeper = format!(
            "GateKeeper|{}|{}|{}|{}|{}",
            STANDARD.encode(&t_gatekeeper),
            hop_index,
            STANDARD.encode(&k[hop_index]),
            STANDARD.encode(current_layer_nonce),
            vA[hop_index],
        );

        E = current_gatekeeper_pubkey.encrypt(&mut rng, Pkcs1v15Encrypt, e_gatekeeper.as_bytes())?;

        H = format!(
            "{}|{}",
            STANDARD.encode(&E),
            B.iter().map(|x| STANDARD.encode(&x)).rev().collect::<Vec<_>>().join(","),
        );
    }

    // Step 5: Forming the header and content for the last mixer
    // index l1-1 in the mixers list
    // hop index l1-1

    let aes_gcm_mixer_last = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&k[l1-1]));
    let nonce_mixer_last = Nonce::from_slice(y[l1-1]);
    let c = aes_gcm_mixer_last.encrypt(nonce_mixer_last, c.as_slice())?;  // global c for content

    for i in 0..B.len() { // wrap already existed Bi
        B[i] = aes_gcm_mixer_last.encrypt(nonce_mixer_last, B[i].as_slice()).expect("Cannot encrypt new B");
    }

    // Create b_{i, 1}
    let b_mixer_last = format!( // b_{i, 1} = (I_{i+1}, E_{i+1}})
        "{}|{}",
        gatekeepers[0].0,
        STANDARD.encode(&E)
    );
    B.push(aes_gcm_mixer_last.encrypt(nonce_mixer_last, b.as_bytes()).expect("Cannot encrypt B")); // B_{i, 1} is b_{i, 1} encrypted with k_i

    // Create tag t
    let mut hasher_mixer_last = Sha256::new();
    for bij in B.iter().rev() {
        hasher_mixer_last.update(bij);
    }
    hasher_mixer_last.update(c.clone());
    let t_mixer_last = hasher_mixer_last.finalize(); // the tag

    // Create E
    let e_mixer_last = format!(
        "Mixer|{}|{}|{}|{}|{}",
        STANDARD.encode(&t_mixer_last),
        l1-1,
        STANDARD.encode(&k[l1-1]),
        STANDARD.encode(y[l1-1]),
        vA[l1-1],
    );

    let (id_mixer_last, pubkey_mixer_last) = mixers[l1-1];
    E = pubkey_mixer_last.encrypt(&mut rng, Pkcs1v15Encrypt, e_mixer_last.as_bytes())?;

    H = format!(
        "{}|{}",
        STANDARD.encode(&E),
        B.iter().map(|x| STANDARD.encode(&x)).rev().collect::<Vec<_>>().join(","),
    );

    // Step 6: Forming the outer mixers layers
    // indexed from l1-2 to 0 in the mixers list
    // indexed from l1-2 to 0 in the nonce list
    // indexed from l1-2 to 0 on the path

    for current_id in (0..(l1-1)).rev() { // current_id from l1-1 to 0
        let hop_index = current_id;

        let next_mixer_id = mixers[current_id+1].0; // I_{i+1}
        let current_mixer_pubkey = mixers[hop_index].1; // pk(P_i)
        let current_layer_key = k[hop_index]; // k_i
        let current_layer_nonce = y[hop_index]; // y_i

        let aes_gcm_mixer = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&current_layer_key));
        let nonce_mixer = Nonce::from_slice(current_layer_nonce); // Constant nonce for simplicity
        let c_mixer = aes_gcm_mixer.encrypt(nonce_mixer, c.as_slice())?;  // content

        for i in 0..B.len() {
            B[i] = aes_gcm_mixer.encrypt(nonce_mixer, B[i].as_slice()).expect("Cannot encrypt new B");
        }

        // Create b_{i, 1}
        let b_mixer = format!( // b_{i, 1} = (I_{i+1}, E_{i+1}})
            "{}|{}",
            next_mixer_id,
            STANDARD.encode(&E)
        );
        B.push(aes_gcm_mixer.encrypt(nonce_mixer, b.as_bytes()).expect("Cannot encrypt B")); // B_{i, 1} is b_{i, 1} encrypted with k_i

        // Create tag t
        let mut hasher_mixer = Sha256::new();
        for bij in B.iter().rev() {
            hasher_mixer.update(bij);
        }
        hasher_mixer.update(c_mixer);
        let t_mixer = hasher_mixer.finalize(); // the tag

        // Create E
        let e_mixer = format!(
            "Mixer|{}|{}|{}|{}|{}",
            STANDARD.encode(&t_mixer),
            hop_index,
            STANDARD.encode(&k[hop_index]),
            STANDARD.encode(current_layer_nonce),
            vA[hop_index],
        );

        E = current_mixer_pubkey.encrypt(&mut rng, Pkcs1v15Encrypt, e_mixer.as_bytes())?;

        H = format!(
            "{},{}",
            STANDARD.encode(&E),
            B.iter().map(|x| STANDARD.encode(x)).rev().collect::<Vec<_>>().join(",")
        );
    }


    let final_onion = format!(     // I will change the message format a bit. It will be: Header | Content | Sepal_nonce | Sepal_enc
        "{}|{}|{}|{}\n",
        H,
        STANDARD.encode(&c),
        S_nonce.iter().map(|x| STANDARD.encode(&x)).collect::<Vec<_>>().join(","),
        S_enc.iter().map(|x| STANDARD.encode(&x)).collect::<Vec<_>>().join(","),
    );

    Ok(final_onion)
}

pub fn tulip_decrypt(
    tulip: &str,
    node_id: &str,
    node_seckey: &RsaPrivateKey,
) -> Result<String, Box<dyn std::error::Error>> {
    // This function is only for one node to process the onion that is sent to this node

    let tulip_string = tulip.to_string(); // just a placeholder to translate any &str into string

    let parts: Vec<&str> = tulip_string.split('|').collect();

    if parts.len() != 4 {
        return Err("Invalid onion layer format".into());
    }

    let H = parts[0]; // Header
    let c = parts[1]; // content
    let S_nonce_string = parts[2]; // sepal_nonce
    let S_enc_string = parts[3]; // sepal_enc

    // Step 1: Process header

    let H_string = H.to_string();
    let H_parts: Vec<&str> = H_string.split(',').collect();

    // Process E
    let E = STANDARD.decode(H_parts[0])?; // E_i
    let e = node_seckey.decrypt(Pkcs1v15Encrypt, &E)?;
    let e_string = str::from_utf8(e.as_slice()).unwrap().to_string();
    let e_parts: Vec<&str> = e_string.split('|').collect();

    let t = STANDARD.decode(e_parts[0])?; // t_i

    let role = e_parts[1].to_string(); // role
    if role == "Recipient" {
        eprintln!("Something's wrong! Cannot let the server know the message for recipient!");
    }

    let hop_index_string = e_parts[2].to_string();
    let hop_index = hop_index_string.parse::<usize>().unwrap(); // parse hop_index as usize

    // Get the layer key
    let layer_key = STANDARD.decode(e_parts[3])?;
    let aes_gcm = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&layer_key));

    // Other metadata
    let layer_nonce = STANDARD.decode(e_parts[4])?; 
    let vAi_string = e_parts[5].to_string();


    // Now I want to check vAi_string hashes, does this list include the hash of the sepal?
    // First process the sepal
    let S_nonce = S_nonce_string.split(',').map(|x| STANDARD.decode(x).expect("Failed to decode sepal nonce!")).collect::<Vec<_>>();
    let S_enc = S_enc_string.split(',').map(|x| STANDARD.decode(x).expect("Failed to decode sepal encrypted.")).collect::<Vec<_>>();

    // decrypt, also make sepal for next layer
    for (s_nonce, s_enc) in S_nonce.iter().zip(S_enc.iter()) {
        let nonce = Nonce::from_slice(s_nonce);
        let sepal_block = aes_gcm.decrypt(nonce, s_enc.as_slice())?;
    }


    // Process B

    let mut B = Vec::<_>::new();
    for i in 1..H_parts.len() {
        B.push(STANDARD.decode(H_parts[i]).expect("Decoding Bij failed!"));
    }



    let next_message = "NOT COMPLETE".to_string();

    Ok(next_message)
}