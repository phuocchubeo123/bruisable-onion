use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};


// implement shared.rs because dependencies weren't working if I just used intermediary_node.rs for some reason
// use shared.rs to prevent circular dependencies (which rust doens't like..?)

use base64::{engine::general_purpose::STANDARD, Engine};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use std::str;

use sha2::{Sha256, Digest};
// shared.rs
pub struct IntermediaryNode {
    pub id: String,
    pub public_key: RsaPublicKey,
    pub private_key: RsaPrivateKey,
}

// has it's own id, public, and private key
impl IntermediaryNode {
    // Constructor method to create a new IntermediaryNode
    pub fn new(id: &str, public_key: RsaPublicKey, private_key: RsaPrivateKey) -> Self {
        IntermediaryNode {
            id: id.to_string(),
            public_key,
            private_key,
        }
    }

    //intermediary node uses this to decrypt
    pub fn tulip_decrypt(
        &self,
        tulip: &str,
        bruise: bool,
    ) -> Result<(String, String), Box<dyn std::error::Error>> {
        // This function is only for one node to process the onion that is sent to this node
    
        let tulip_string = tulip.to_string(); // just a placeholder to translate any &str into string
    
        let parts: Vec<&str> = tulip_string.split("||").collect();
    
        //println!("Number of tulip parts: {}", parts.len());
    
        if parts.len() != 5 {
            return Err("Invalid onion layer format".into());
        }
    
        // Step 1: Process header
        let H = parts[0]; // Header
        let H_string = H.to_string();
        let H_parts: Vec<&str> = H_string.split(",,").collect();
    
        // println!("The received header is: {}", H);
        //println!("The header has {} parts!", H_parts.len());
    
    
        // Process E1, which is role | tag | hop_index | key
        let E1 = STANDARD.decode(H_parts[0])?; // E_i
        let e1 = self.private_key.decrypt(Pkcs1v15Encrypt, &E1)?;
        let e1_string = str::from_utf8(e1.as_slice()).unwrap().to_string();
        let e1_parts: Vec<&str> = e1_string.split('|').collect();
    
        //println!("Received e1: {}", e1_string);
    
        // Get role
        let role = e1_parts[0].to_string(); // role
        if role == "Recipient" {
            //eprintln!("Something's wrong! Cannot let the server know the message for recipient!");
        }
    
       // println!("Received the role: {}", role);
    
        // Get hop_index
        let hop_index_string = e1_parts[2].to_string();
        let hop_index = hop_index_string.parse::<usize>().unwrap(); // parse hop_index as usize
    
        //println!("Received the hop index: {}", hop_index);
    
        // Process E2, which is nonce | vA
        let E2 = STANDARD.decode(H_parts[1])?; // E2
        let e2 = self.private_key.decrypt(Pkcs1v15Encrypt, &E2)?;
        let e2_string = str::from_utf8(e2.as_slice()).unwrap().to_string();
        let e2_parts: Vec<&str> = e2_string.split('|').collect();
    
        //println!("Received e2!");
    
        // Get layer key and nonce
        let layer_key = STANDARD.decode(e1_parts[3])?;
        let aes_gcm = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&layer_key));
    
        let layer_nonce_bytes = STANDARD.decode(e2_parts[0])?; 
        let layer_nonce = Nonce::from_slice(&layer_nonce_bytes);
    
        // Get verification hashes for the sepal
        let vAi_string = H_parts[2].to_string();
        let vAi = vAi_string
            .split("..")
            .map(|x| STANDARD.decode(x).expect("Failed to decode a hash in vAi."))
            .map(|x| self.private_key.decrypt(Pkcs1v15Encrypt, &x).expect("Cannot decrypt sepal hash for tulip_decrypt"))
            .collect::<Vec<_>>();
    
        //println!("All the vAi:");
        for vA in vAi.iter() {
            //println!("{}", STANDARD.encode(vA.clone()));
        }
    
        // Step 2: Process the sepal and check the sepal
    
        let S_nonce_string = parts[2]; // sepal_nonce
        let S_enc_string = parts[3]; // sepal_enc
    
        let mut S_nonce = S_nonce_string.split(",,").map(|x| STANDARD.decode(x).expect("Failed to decode sepal nonce!")).collect::<Vec<_>>();
    
        //println!("How many nonces: {}", S_nonce.len());
    
        // for uu in S_enc_string.split(",,") {
        //     println!("{}", uu.to_string());
        //     println!("{:?}", STANDARD.decode(uu).expect("Fail to decode"));
        // }
    
        let mut S_enc = S_enc_string.split(",,").map(|x| STANDARD.decode(x).expect("Failed to decode sepal encrypted.")).collect::<Vec<_>>();
        //println!("How many sepals: {}", S_enc.len());
    
        // decrypt, also make sepal for next layer
        for i in 0..S_nonce.len() {
            let nonce = Nonce::from_slice(&S_nonce[i]);
            S_enc[i] = aes_gcm.decrypt(nonce, S_enc[i].as_slice())?;
        }
    
        // get the hash and check if it is in vAi
        let mut sepal_hasher = Sha256::new();
        for s_enc in S_enc.iter() {
            sepal_hasher.update(s_enc);
        }
    
        let sepal_hash = sepal_hasher.finalize().to_vec();
    
        //println!("The sepal hash is: {}", STANDARD.encode(sepal_hash.clone()));
    
        if vAi.iter().any(|x| x == sepal_hash.as_slice()) == false {
            //eprintln!("Malleable sepal!");
        } else {
            //println!("Received valid sepal!");
        }
    
        // Step 3: Process content and check the tag
        // Here we have two cases: role = LastGatekeeper or role != LastGatekeeper
        if role == "LastGatekeeper" {
            let master_key = S_enc[0].clone();
            let aes_gcm_master = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&master_key));
    
            let c_encrypted = parts[1]; // content
            let c = aes_gcm_master.decrypt(&layer_nonce, &*STANDARD.decode(c_encrypted)?)?;
            //println!("Decrypt content successfully using master key!");
    
            let mut b = STANDARD.decode(H_parts[3]).expect("Decoding B1 for LastGateKeeper failed!");
            b = aes_gcm_master.decrypt(&layer_nonce, b.as_slice())?;
            //println!("Decrypt b successfully using master key!");
    
            let mut content_hasher = Sha256::new();
            content_hasher.update(b.clone());
            content_hasher.update(c.clone());
            let ref_tag = content_hasher.finalize(); // compute the hash of content and blocks
    
            let t = STANDARD.decode(e1_parts[1])?; // read the tag
    
            //println!("The reference tag is: {}", STANDARD.encode(&ref_tag));
            //println!("Received tag: {}", STANDARD.encode(&t));
    
            if t != ref_tag.to_vec() { // hopefully to_vec keeps the hash the same
                //eprintln!("Some party sent the wrong content!");
            } else {
               //println!("The content is verified");
            }
    
            let b_string = String::from_utf8_lossy(&b).into_owned();
            let b_parts = b_string.split("||").collect::<Vec<_>>();
    
    
            let recipient = b_parts[0].to_string();
            let next_E = STANDARD.decode(b_parts[1])?;
    
           // println!("The intended recipient is {}", recipient);
    
            // create header
            let next_H = format!(
                "{}",
                STANDARD.encode(&next_E),
            );
    
            let next_message = format!(
                "{}||{}||\n",
                next_H,
                STANDARD.encode(&c),
            );
    
            return Ok((recipient, next_message));
        }
    
        let c_encrypted = parts[1]; // content
        let c = aes_gcm.decrypt(&layer_nonce, &*STANDARD.decode(c_encrypted)?)?;
    
        //println!("Decrypt content successfully!");
    
        // Process B and compute the hash
        let mut B = Vec::<_>::new();
        for i in 3..H_parts.len() {
            B.push(STANDARD.decode(H_parts[i]).expect("Decoding Bij failed!"));
        }
        // Decrypt all Bi
        for i in 0..B.len() {
            // println!("Received Bi: {}", STANDARD.encode(B[i].clone()));
            B[i] = aes_gcm.decrypt(&layer_nonce, B[i].as_slice())?;
        }
    
        let mut content_hasher = Sha256::new();
        for bij in B.iter() {
            content_hasher.update(bij);
        }
        content_hasher.update(c.clone());
        let ref_tag = content_hasher.finalize(); // compute the hash of content and blocks
    
        let t = STANDARD.decode(e1_parts[1])?; // read the tag
    
        //println!("The reference tag is: {}", STANDARD.encode(&ref_tag));
        //println!("Received tag: {}", STANDARD.encode(&t));
    
        if t != ref_tag.to_vec() { // hopefully to_vec keeps the hash the same
            //eprintln!("Some party sent the wrong content!");
        } else {
            //println!("The content is verified");
        }
    
    
        // Step 4: Peel every Bi and output the message to the next person
        // If the role is Mixer, currently we consider only honest Mixer and it just "peels" the sepal
    
        // read information from b1
        let b1_string = String::from_utf8_lossy(&B[0]).into_owned();
        let b1_parts = b1_string.split("||").collect::<Vec<_>>();
    
        let next_person = b1_parts[0].to_string();
        let next_E1 = STANDARD.decode(b1_parts[1])?;
        let next_E2 = STANDARD.decode(b1_parts[2])?;
        let next_vAi = b1_parts[3];
    
        // create header
        let next_H = format!(
            "{},,{},,{},,{}",
            STANDARD.encode(&next_E1),
            STANDARD.encode(&next_E2),
            next_vAi,
            B.iter().rev().take(B.len()-1).rev().map(|x| STANDARD.encode(x)).collect::<Vec<_>>().join(",,"),
        );
    
        if role == "Mixer" {
            if bruise { // bruising the sepal, removing index 0
                eprintln!("Mixer bruised onion!");
                S_nonce.remove(0);
                S_enc.remove(0);
            } else {
                S_nonce.pop();
                S_enc.pop();
            }
        }
    
        let next_message = format!(
            "{}||{}||{}||{}||\n",
            next_H,
            STANDARD.encode(&c),
            S_nonce.iter().map(|x| STANDARD.encode(&x)).collect::<Vec<_>>().join(",,"),
            S_enc.iter().map(|x| STANDARD.encode(&x)).collect::<Vec<_>>().join(",,"),
        );
    
    
        Ok((next_person, next_message))
    }
    
}