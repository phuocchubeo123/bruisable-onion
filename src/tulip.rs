// use std::{cmp::max, collections::HashMap};

// use crate::{globals, shared::IntermediaryNode}; // Import from shared.rs

// // Import IntermediaryNode
// use base64::{engine::general_purpose::STANDARD, Engine};
// use rand::{rngs::OsRng, RngCore};
// use aes_gcm::{
//     aead::{Aead, AeadCore, KeyInit},
//     Aes256Gcm, Key, Nonce,
// };
// use std::str;
// use sha2::{Sha256, Digest};




// // phuoc: tulip encryption
// // COMPILED BUT NOT TESTED
// pub fn tulip_encrypt(
//     message: &str,
//     recipient_pubkey: &RsaPublicKey,
//     recipient_id: &str,
//     mixers: &[(&str, &RsaPublicKey)],
//     gatekeepers: &[(&str, &RsaPublicKey)],
//     y: &[&[u8; 12]],
//     max_bruise: &usize
// ) -> Result<String, Box<dyn std::error::Error>> {
//     let mut rng = OsRng; 
//     let l1 = globals::MIXERS; // Number of Mixers
//     let l2 = globals::GATEKEEPERS; // Number of Gatekeepers
//     let l = l1 + l2 + 1;

//     // Step 1: Generating layer keys and master key
//     let k: Vec<_> = (0..l)  // layer keys
//         .map(|_| Aes256Gcm::generate_key(&mut rng))
//         .collect(); 

//     let master_key = Aes256Gcm::generate_key(&mut rng); // master key

//     // Step 2: Forming the first sepal S for the first mixer
//     let mut S_nonce = Vec::<_>::new();
//     let mut S_enc = Vec::<_>::new();

//     for _master_key_block in 0..max_bruise.clone() {
//         let mut enc_master_key = master_key.as_slice().to_vec(); // stupid workaround to copy the master key
//         let nonce = Aes256Gcm::generate_nonce(&mut rng); // Same nonce for every layer
//         for layer_key in k.iter().take(l-1).rev() { // iterate from near-last to first
//             let aes_gcm = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&layer_key));
//             // let new_enc_master_key = aes_gcm.encrypt(&nonce, enc_master_key.as_slice()).expect("Encryption Failed!");
//             enc_master_key = aes_gcm.encrypt(&nonce, enc_master_key.as_slice()).expect("Encryption Failed!");

//             // let dummy = aes_gcm.decrypt(&nonce, new_enc_master_key.as_slice()).expect("Can we decrypt back right away?");
//             // println!("Is this decryption correct? {}", dummy == enc_master_key);
//         }

//         S_nonce.push(nonce);
//         S_enc.push(enc_master_key.clone());

//     }

//     // I wonder if it is still okay to encrypt using l-1 keys instead of l1+1 keys
//     for _null_block in 0..(l1 - max_bruise + 1) {
//         let mut enc_null = vec![0u8; master_key.as_slice().to_vec().len()]; // more stupid workaround to have null string with the same length as master key
//         let nonce = Aes256Gcm::generate_nonce(&mut rng); // Currently, I use the same nonce for every layer, I hope that it is safe
//         for layer_key in k.iter().take(l-1).rev() { // iterate from first gatekeeper to first
//             let aes_gcm = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&layer_key));
//             enc_null = aes_gcm.encrypt(&nonce, enc_null.as_slice()).expect("Encrypt Null failed!");
//         }

//         S_nonce.push(nonce);
//         S_enc.push(enc_null);
//     }

//     let mut test_hasher = Sha256::new();
//     let test_layer_key = k[0];
//     let test_aes_gcm = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&test_layer_key));
//     for (s_nonce, s_enc) in S_nonce.iter().zip(S_enc.iter()) {
//         let dec_s_enc = test_aes_gcm.decrypt(&s_nonce, s_enc.as_slice()).expect("Cannot decrypt test sepal");
//         test_hasher.update(dec_s_enc.clone());
//     }
//     let test_sepal_hash = test_hasher.finalize().to_vec();
//     //println!("The test sepal hash for the first layer is: {}", STANDARD.encode(&test_sepal_hash));

//     // Creating the clasp

//     // Creating Tij
//     let mut T = Vec::<Vec<_>>::new(); // Tij is the sepal block S1j without the i-1 outermost encryption layers
//     T.push(S_enc.clone());

//     for (layer_id, layer_key) in (1..l).zip(k.iter().take(l-1)) { // each time peel one layer, left to right
//         let aes_gcm = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&layer_key));
//         let mut Ti = Vec::<_>::new();

//         for master_key_block in 0..max_bruise.clone() {
//             //println!("Decrypting sepal key {}", master_key_block);
//             let nonce = S_nonce[master_key_block].clone();
//             let enc_master_key = T[layer_id-1][master_key_block].clone();
//             let dec_master_key = aes_gcm.decrypt(&nonce, enc_master_key.as_slice()).expect("Cannot decrypt sepal block");
//             Ti.push(dec_master_key);
//         }

//         for null_block in (max_bruise.clone())..(l1+1) {
//             //println!("Decrypting sepal null {}", null_block);
//             let nonce = S_nonce[null_block].clone();
//             let enc_null = T[layer_id-1][null_block].clone();
//             let dec_null= aes_gcm.decrypt(&nonce, enc_null.as_slice()).expect("Cannot decrypt sepal block");
//             Ti.push(dec_null);
//         }

//         // let Ti: Vec<_> = (0..(l1+1))d
//         //     .map(|i| aes_gcm.decrypt(&S_nonce[i], T[layer_id-1][i].as_slice()).expect("Cannot decrypt the sepal layer"))
//         //     .collect();
//         T.push(Ti);
//     }

//     eprintln!("Done creating the sepal");

//     // The hash that contains the dummy sepal block would not matter!
//     for i in 0..l {  // Put a dummy sepal block T_{i, l1+2} in
//         let mut enc_rand = vec![0u8; master_key.as_slice().to_vec().len()]; // placeholder for random string with the same length as the master key
//         OsRng.fill_bytes(&mut enc_rand); // fill enc_rand with random bytes
//         let nonce = Nonce::from_slice(&[0; 12]); // Zero-nonce is okay since it's random anyway 
//         for layer_key in k.iter().take(l-1).rev() { // iterate from last gatekeeper to first
//             let aes_gcm = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&layer_key));
//             enc_rand = aes_gcm.encrypt(&nonce, enc_rand.as_slice()).expect("Creating Clasp: Encrypt rand failed!");
//         }
//         T[i].push(enc_rand);
//     }

//     eprintln!("Done creating the clasp.");

//     // Creating Aij, vAi

//     let mut vA = Vec::<String>::new(); // vA stores all the vAi

//     for i in 0..l {
//         // hash the ring
//         let ell = max(1, l1.saturating_add(2).saturating_sub(i));

//         //println!("Creating vAi for hop index {} with sepal length to hash equals to {}", i, ell);

//         let mut vAi = Vec::<_>::new();
//         for j in 0..(l1+1) {   // hash the ring
//             if i < j && j < l1 + 1 { continue;}
//             //println!("Start index for hash: {}", j);
//             let mut hasher = Sha256::new();
//             for jj in 0..ell {
//                 //print!("{} ", (j+jj) % (l1 + 2));
//                 hasher.update(T[i][(j + jj) % (l1 + 2)].clone());
//             }
//             //println!();
//             let Aij = hasher.finalize().to_vec();

//             //eprintln!("Hash: {}", STANDARD.encode(Aij.clone()));

//             vAi.push(Aij);
//         }

//         vAi.sort();

//         // I try to turn the hashes in vAi into strings and concatenate them here.
//         let vAi_string = vAi
//             .iter()
//             .map(|x| STANDARD.encode(x.as_slice())) // I think this encode should be correct, it should also decode into a slice
//             .collect::<Vec<_>>()
//             .join(",,");

//         let vAi_string_parts = vAi_string.split(",,").collect::<Vec<_>>();
//         //println!("The vAi for hop index {} has {} hashes.", i, vAi_string_parts.len());

//         vA.push(vAi_string);
//     }

//    //println!("Done creating the vA vectors");


//     // Step 2: Forming the header and content for the last onion layer a.k.a the receiver
//     // indexed l-1 on the path

//     // Create the unencrypted message 
//     let mut c = message.as_bytes().to_vec();

//     // Create header
//     // Global E is for the encrypted metadata
//     // Global H is for header
//     // We compute the tag first, which is just the hash of the unencrypted message

//     let mut hasher_last = Sha256::new();
//     hasher_last.update(c.clone());
//     let t_last = hasher_last.finalize(); // tag for the last layer
//     let e_last = format!(
//         "Recipient|{}|{}|{}", // role, tag, hop index, layer key
//         STANDARD.encode(&t_last),
//         l-1,
//         STANDARD.encode(&k[l-1]),
//     );
//     let mut E = recipient_pubkey.encrypt(&mut rng, Pkcs1v15Encrypt, &e_last.as_bytes())?;
//     let mut H = format!(  // H_l = E_l
//         "{}",
//         STANDARD.encode(&E) //lower case e decrypted/plaintext, E encrypted/ciphertext
//     ); 

//     // Create content 
//     // Global c is for the content

//     let aes_gcm_last = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&k[l-1]));
//     let nonce_last = Nonce::from_slice(&[0; 12]); // Zero-nonce for the recipient
//     c = aes_gcm_last.encrypt(nonce_last, c.as_slice())?;   // universal variable for content

//     //println!("Created content for the last layer.");


//     //println!("Created header for the last layer.");


//     // Step 3: Forming the header and content for the last gatekeeper
//     // indexed l2-1 in the gatekeepers list
//     // indexed l-2 in the nonce list
//     // indexed l-2 on the path

//     // Global B array for later use also
//     let mut B =  Vec::<_>::new();

//     let b = format!(   // b_{l-1, 1} = (recipient_id, E_l)
//         "{}||{}",
//         recipient_id,
//         STANDARD.encode(&E)
//     );
//     B.push(b.as_bytes().to_vec());
//     // Create tag
//     let mut hasher_gatekeeper_last = Sha256::new();
//     hasher_gatekeeper_last.update(B[0].clone());
//     hasher_gatekeeper_last.update(c.clone());
//     let t_gatekeeper_last = hasher_gatekeeper_last.finalize(); // tag for the last gatekeeper

//     //println!("The tag for last gatekeeper hop index {} is: {}", l-2, STANDARD.encode(&t_gatekeeper_last));


//     // Encrypt content and Bi, note that here we use the master key
//     let aes_gcm_gatekeeper_last = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&master_key));
//     let nonce_gatekeeper_last = Nonce::from_slice(y[l-2]); // last gatekeeper nonce for simplicity
//     c = aes_gcm_gatekeeper_last.encrypt(nonce_gatekeeper_last, c.as_slice())?; // content for the last gatekeeper is the encryption of c_last under master_key

//     //eprintln!("Created content for the last gatekeeper.");

//     for i in 0..B.len() {
//         B[i] = aes_gcm_gatekeeper_last.encrypt(nonce_gatekeeper_last, B[i].as_slice()).expect("Cannot encrypt new B");
//     }

//     // Create header

//     let e1_gatekeeper_last = format!(
//         "LastGatekeeper|{}|{}|{}", //role, tag, hop index, layer key
//         STANDARD.encode(&t_gatekeeper_last),
//         l-2,
//         STANDARD.encode(&k[l-2]),
//     );

//     let e2_gatekeeper_last = format!( //nonce, vector sorted hashes
//         "{}",
//         STANDARD.encode(y[l-2]),
//     );

//     let (id_gatekeeper_last, pubkey_gatekeeper_last) = gatekeepers[l2-1];
//     let mut E1 = pubkey_gatekeeper_last.encrypt(&mut rng, Pkcs1v15Encrypt, e1_gatekeeper_last.as_bytes())?; // E1 is encrypted with the pubkey of the last gatekeeper
//     let mut E2 = pubkey_gatekeeper_last.encrypt(&mut rng, Pkcs1v15Encrypt, e2_gatekeeper_last.as_bytes())?; // E1 is encrypted with the pubkey of the last gatekeeper

//     let mut current_vAi = vA[l-1].split(",,").collect::<Vec<_>>();

//     //println!("Created E for the last gatekeeper.");

//     H = format!(
//         "{},,{},,{},,{}",
//         STANDARD.encode(&E1),
//         STANDARD.encode(&E2),
//         current_vAi
//             .clone()
//             .into_iter()
//             .map(|x| pubkey_gatekeeper_last.encrypt(&mut rng, Pkcs1v15Encrypt, STANDARD.decode(x).expect("Cannot decode sepal hash last gatekeeper").as_slice()).expect("Cannot encrypt sepal hash last gatekeeper"))
//             .map(|x| STANDARD.encode(x))
//             .collect::<Vec<_>>()
//             .join(".."),
//         STANDARD.encode(&B[0])
//     );

//     //println!("Created header for the last gatekeeper with hop index {}", l-2);


//     // Step 4: Forming the outer gatekeepers layers
//     // indexed from l2-2 to 0 in the gatekeepers list
//     // indexed from l-3 to l-l2-1 = l1 in the nonce list
//     // indexed from l-3 to l-l2-1 = l1 on the path

//     for current_id in (0..(l2-1)).rev() { // current_id from l2-2 to 0
//         let hop_index = current_id + l1; 

//         let (next_gatekeeper_id, next_gatekeeper_pubkey) = gatekeepers[current_id+1];
//         let current_gatekeeper_pubkey = gatekeepers[current_id].1; // pk(P_i)
//         let current_layer_key = k[hop_index]; // k_i
//         let current_layer_nonce = y[hop_index]; // y_i

//         // Create Bi and the tag first
//         let b_gatekeeper = format!( // b_{i, 1} = (I_{i+1}, E_{i+1}})
//             "{}||{}||{}||{}",
//             next_gatekeeper_id,
//             STANDARD.encode(&E1),
//             STANDARD.encode(&E2),
//             current_vAi
//                 .clone()
//                 .into_iter()
//                 .map(|x| next_gatekeeper_pubkey.encrypt(&mut rng, Pkcs1v15Encrypt, STANDARD.decode(x).expect("Cannot decode sepal hash gatekeeper").as_slice()).expect("Cannot encrypt sepal hash mixer"))
//                 .map(|x| STANDARD.encode(x))
//                 .collect::<Vec<_>>()
//                 .join(".."),
//         );
//         B.push(b_gatekeeper.as_bytes().to_vec());
//         // Create tag t
//         let mut hasher_gatekeeper = Sha256::new();
//         for bij in B.iter().rev() {
//             hasher_gatekeeper.update(bij);
//         }
//         hasher_gatekeeper.update(c.clone());
//         let t_gatekeeper = hasher_gatekeeper.finalize(); // the tag

//         //println!("The tag for gatekeeper hop index {} is: {}", hop_index, STANDARD.encode(&t_gatekeeper));

//         // Now encrypt the content and Bi

//         let aes_gcm_gatekeeper = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&current_layer_key));
//         let nonce_gatekeeper = Nonce::from_slice(current_layer_nonce); // Constant nonce for simplicity
//         c = aes_gcm_gatekeeper.encrypt(nonce_gatekeeper, c.as_slice())?;  // content

//         //println!("Created content for the gatekeeper with hop index {}", hop_index);

//         for i in 0..B.len() {
//             B[i] = aes_gcm_gatekeeper.encrypt(nonce_gatekeeper, B[i].as_slice()).expect("Cannot encrypt new B");
//         }
//         //println!("Created B for the gatekeeper with hop index {} ", hop_index);

//         // Create E
//         let e1_gatekeeper = format!(
//             "GateKeeper|{}|{}|{}",
//             STANDARD.encode(&t_gatekeeper),
//             hop_index,
//             STANDARD.encode(&k[hop_index]),
//         );

//         let e2_gatekeeper = format!(
//             "{}",
//             STANDARD.encode(current_layer_nonce),
//         );

//         E1 = current_gatekeeper_pubkey.encrypt(&mut rng, Pkcs1v15Encrypt, e1_gatekeeper.as_bytes())?;
//         E2 = current_gatekeeper_pubkey.encrypt(&mut rng, Pkcs1v15Encrypt, e2_gatekeeper.as_bytes())?;

//         current_vAi = vA[hop_index+1].split(",,").collect::<Vec<_>>();

//         H = format!(
//             "{},,{},,{},,{}",
//             STANDARD.encode(&E1),
//             STANDARD.encode(&E2),
//             current_vAi
//                 .clone()
//                 .into_iter()
//                 .map(|x| current_gatekeeper_pubkey.encrypt(&mut rng, Pkcs1v15Encrypt, STANDARD.decode(x).expect("Cannot decode sepal hash gatekeeper").as_slice()).expect("Cannot encrypt sepal hash gatekeeper"))
//                 .map(|x| STANDARD.encode(x))
//                 .collect::<Vec<_>>()
//                 .join(".."),
//             B.iter().map(|x| STANDARD.encode(&x)).rev().collect::<Vec<_>>().join(",,"),
//         );

//         //println!("Created header for the gatekeeper with hop index {}", hop_index);
//     }

//     eprintln!("Done processing all gatekeepers");

//     // Step 5: Forming the outer mixers layers
//     // indexed from l1-1 to 0 in the mixers list
//     // indexed from l1-1 to 0 in the nonce list
//     // indexed from l1-1 to 0 on the path

//     for current_id in (0..(l1)).rev() { // current_id from l1-1 to 0
//         let hop_index = current_id;

//         let mut next_node_id = "Node 0"; // dummy for next_node_id
//         let mut next_node_pubkey = mixers[hop_index].1;
//         if current_id < l1-1 {
//             next_node_id = mixers[current_id+1].0;
//             next_node_pubkey = mixers[current_id+1].1;
//         } else {
//             next_node_id = gatekeepers[0].0;
//             next_node_pubkey = gatekeepers[0].1;
//         }
//         let current_mixer_pubkey = mixers[hop_index].1; // pk(P_i)
//         let current_layer_key = k[hop_index]; // k_i
//         let current_layer_nonce = y[hop_index]; // y_i

//         let current_node_id = mixers[current_id].0;
//         //println!("Creating tulip for mixer {}", current_node_id);

//         // Create b_{i, 1} and create the tag first, before encrypt every Bi
//         let b_mixer = format!( // b_{i, 1} = (I_{i+1}, E_{i+1}})
//             "{}||{}||{}||{}",
//             next_node_id,
//             STANDARD.encode(&E1),
//             STANDARD.encode(&E2),
//             current_vAi
//                 .clone()
//                 .into_iter()
//                 .map(|x| next_node_pubkey.encrypt(&mut rng, Pkcs1v15Encrypt, STANDARD.decode(x).expect("Cannot decode sepal hash mixer").as_slice()).expect("Cannot encrypt sepal hash mixer"))
//                 .map(|x| STANDARD.encode(x))
//                 .collect::<Vec<_>>()
//                 .join(".."),
//         );
//         B.push(b_mixer.as_bytes().to_vec());

//         // Create tag t
//         let mut hasher_mixer = Sha256::new();
//         for bij in B.iter().rev() {
//             hasher_mixer.update(bij);
//         }
//         hasher_mixer.update(c.clone());
//         let t_mixer = hasher_mixer.finalize(); // the tag

//         //println!("The tag for mixer hop index {} is: {}", hop_index, STANDARD.encode(&t_mixer));

//         // Start encrypting the content and Bi
//         let aes_gcm_mixer = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&current_layer_key));
//         let nonce_mixer = Nonce::from_slice(current_layer_nonce); // Constant nonce for simplicity

//         // Encrypting all Bi
//         for i in 0..B.len() {
//             B[i] = aes_gcm_mixer.encrypt(nonce_mixer, B[i].as_slice()).expect("Cannot encrypt new B");
//             // println!("Prepared Bi: {}", STANDARD.encode(B[i].clone()));
//         }

//         // Encrypting content
//         c = aes_gcm_mixer.encrypt(nonce_mixer, c.as_slice())?;  // content

//         //println!("Created content for the mixer with hop index {}", hop_index);


//         // Create E
//         let e1_mixer = format!(
//             "Mixer|{}|{}|{}",
//             STANDARD.encode(&t_mixer),
//             hop_index,
//             STANDARD.encode(&k[hop_index]),
//         );

//         let e2_mixer = format!(
//             "{}",
//             STANDARD.encode(current_layer_nonce),
//         );

//         E1 = current_mixer_pubkey.encrypt(&mut rng, Pkcs1v15Encrypt, e1_mixer.as_bytes())?;
//         E2 = current_mixer_pubkey.encrypt(&mut rng, Pkcs1v15Encrypt, e2_mixer.as_bytes())?;

//         current_vAi = vA[hop_index+1].split(",,").collect::<Vec<_>>();

//         H = format!(
//             "{},,{},,{},,{}",
//             STANDARD.encode(&E1),
//             STANDARD.encode(&E2),
//             current_vAi
//                 .clone()
//                 .into_iter()
//                 .map(|x| current_mixer_pubkey.encrypt(&mut rng, Pkcs1v15Encrypt, STANDARD.decode(x).expect("Cannot decode sepal hash mixer").as_slice()).expect("Cannot encrypt sepal hash mixer"))
//                 .map(|x| STANDARD.encode(x))
//                 .collect::<Vec<_>>()
//                 .join(".."),
//             B.iter().map(|x| STANDARD.encode(&x)).rev().collect::<Vec<_>>().join(",,"),
//         );

//         //println!("Created header for the mixer with hop index {}", hop_index);
//         // println!("The header is: {}", H);
//     }
//     eprintln!("Done processing all mixers");
//     let final_onion = format!(     // I will change the message format a bit. It will be: Header | Content | Sepal_nonce | Sepal_enc
//         "{}||{}||{}||{}||\n",
//         H,
//         STANDARD.encode(&c),
//         S_nonce.iter().map(|x| STANDARD.encode(&x)).collect::<Vec<_>>().join(",,"),
//         S_enc.iter().map(|x| STANDARD.encode(&x)).collect::<Vec<_>>().join(",,"),
//     );

//     // Log the size of the final tulip in bytes and KB before returning
//     let final_onion_size = final_onion.as_bytes().len(); // Size in bytes
//     let final_onion_size_kb = final_onion_size as f64 / 1024.0; // Size in KB
//     //println!("Tulip size before returning in tulip.rs: {:.2} KB", final_onion_size_kb);


//     Ok(final_onion)
// }

// pub fn tulip_receive(
//     tulip: &str,
//     node_seckey: &RsaPrivateKey,
// ) -> Result<String, Box<dyn std::error::Error>> {
//     let tulip_string = tulip.to_string(); // just a placeholder to translate any &str into string

//     let parts: Vec<&str> = tulip_string.split("||").collect();    

//     //println!("Number of tulip parts: {}", parts.len());

//     if parts.len() != 3 {
//         return Err("Invalid onion layer format".into());
//     }

//     // Step 1: Process header
//     let H = parts[0]; // Header

//     let E = STANDARD.decode(H)?;
//     let e = node_seckey.decrypt(Pkcs1v15Encrypt, &E)?;

//     //println!("Decrypted e!");

//     let e_string = str::from_utf8(e.as_slice()).unwrap().to_string();
//     let e_parts: Vec<&str> = e_string.split('|').collect();

//     //println!("Received e: {}", e_string);

//     // Get role
//     let role = e_parts[0].to_string(); // role
//     if role != "Recipient" {
//         eprintln!("Something's wrong! Cannot let the server know the message for recipient!");
//     }

//     //println!("Received the role: {}", role);

//     // Get hop_index
//     let hop_index_string = e_parts[2].to_string();
//     let hop_index = hop_index_string.parse::<usize>().unwrap(); // parse hop_index as usize

//     //println!("Received the hop index: {}", hop_index);

//     // Get layer key and nonce
//     let layer_key = STANDARD.decode(e_parts[3])?;
//     let aes_gcm = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&layer_key));
//     let layer_nonce = Nonce::from_slice(&[0; 12]); // Zero-nonce for the recipient

//     let c_encrypted = parts[1]; // content
//     let c = aes_gcm.decrypt(&layer_nonce, &*STANDARD.decode(c_encrypted)?)?;

//     //println!("Decrypt content successfully!");

//     let mut content_hasher = Sha256::new();
//     content_hasher.update(c.clone());
//     let ref_tag = content_hasher.finalize(); // compute the hash of content and blocks

//     let t = STANDARD.decode(e_parts[1])?; // read the tag

//    // println!("The reference tag is: {}", STANDARD.encode(&ref_tag));
//     //println!("Received tag: {}", STANDARD.encode(&t));

//     // if t != ref_tag.to_vec() { // hopefully to_vec keeps the hash the same
//     //     eprintln!("Some party sent the wrong content!");
//     // } else {
//     //     println!("The content is verified");
//     // }

//     let message = String::from_utf8_lossy(&c).to_string();
//     //println!("Decrypted message: {}", message);

//     Ok(message)
// }


// // change this function to implement modular approach. Send the current intermediary node the job to decrypt the tulip
// pub fn process_tulip(
//     tulip: &str,
//     first_node: &str,
//     node_registry: &HashMap<String, IntermediaryNode>,
// ) -> Result<(String, String), Box<dyn std::error::Error>> {
//     /*
//     This function is for the server, to loop through its nodes and process the tulip, 
//     then get the final recipient. It uses the node_registry to access nodes' secrets.
//     */

//     let mut current_node = first_node.to_string();
//     let mut current_tulip = tulip.to_string();

//     // Access the current node and its secret key from the registry
//     let mut current_node_obj = node_registry.get(&current_node)
//         .ok_or("Node ID not found in registry")?;

    
//     for hop_index in 0..(globals::MIXERS + globals::GATEKEEPERS) {
//         let bruise = hop_index == 0; // Use bruise = true for the first hop
//         let decrypt_result = current_node_obj.tulip_decrypt(&current_tulip, bruise);
//         assert!(decrypt_result.is_ok(), "tulip_decrypt failed: {:?}", decrypt_result);
//         let (next_node, next_tulip) = decrypt_result.unwrap();
        
//         current_node = next_node;
//         current_tulip = next_tulip;
    
//         if hop_index < (globals::MIXERS + globals::GATEKEEPERS - 1) {
//             // Get the next node from the registry
//             let next_node_obj = node_registry.get(&current_node)
//                 .ok_or("Next node ID not found in registry")?;
//             current_node_obj = next_node_obj;
//         }
//     }
        

//     Ok((current_node.to_string(), current_tulip.to_string()))
// }