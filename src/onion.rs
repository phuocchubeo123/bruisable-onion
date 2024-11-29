// eileen function to decrypt the onion received from client
fn onion_decrypt(
    onion: &str,
    node_secrets: &HashMap<String, RsaPrivateKey>, // Maps node IDs to their private keys
) -> Result<String, Box<dyn std::error::Error>> {
    let mut current_layer = onion.to_string();
    
    // loop to decrypt each of the 3 layers, from outermost to innermost
    for _ in 0..3 { // We know there are 3 nodes, so we decrypt 3 layers
        // Split the current layer into three parts: node_id, encrypted symmetric key, and encrypted layer
        let parts: Vec<&str> = current_layer.split('|').collect();
        if parts.len() != 3 {
            return Err("Invalid onion layer format".into());
        }

        let node_id = parts[0];          // Current node's ID
        let enc_sym_key = parts[1];      // Encrypted symmetric key for the current layer
        let encrypted_layer = parts[2];  // The encrypted layer content

        // get the private key for the current node
        let node_seckey = node_secrets.get(node_id).ok_or("Node ID not found")?;

        // Decrypt the symmetric key for the current layer using the current node's private key
        let enc_sym_key_bytes = STANDARD.decode(enc_sym_key)?;
        let sym_key_bytes = node_seckey.decrypt(Pkcs1v15Encrypt, &enc_sym_key_bytes)?;

        // decrypt the layer content using the symmetric key for the current layer
        let aes_gcm = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&sym_key_bytes));
        let nonce = Nonce::from_slice(&[0; 12]); // Use a constant nonce

        let decrypted_layer = aes_gcm.decrypt(nonce, &*STANDARD.decode(encrypted_layer)?)?;

        // Convert the decrypted layer back to a string for the next iteration
        current_layer = String::from_utf8_lossy(&decrypted_layer).into_owned();

        //println!("Current layer after decryption: {}", current_layer); //debugging
    }

    // ater decrypting all layers, we expect the final layer to contain:
    // 1. The recipient ID
    // 2. The encrypted symmetric key for the recipient
    // 3. The encrypted message

    let parts: Vec<&str> = current_layer.split('|').collect();
    if parts.len() != 3 {
        return Err("Final layer format invalid".into());
    }

    let recipient_id = parts[0];   // Recipient's ID
    let enc_sym_key = parts[1];    // Encrypted symmetric key for the recipient
    let encrypted_message = parts[2]; // The encrypted message

    // format the final result into a single string compatible with client's parsing
    let result = format!("{}|{}|{}", recipient_id, enc_sym_key, encrypted_message);

    Ok(result) // Return the formatted string to the client
}

// eileen: basic onion encryption function
// next steps include adding more information in the public key enryption part. 
// right now we only include the symmetric key, next we need to include the index, current recipient, nonce, and verification hashes
fn onion_encrypt(
    message: &str,
    recipient_pubkey: &RsaPublicKey,
    recipient_id: &str,
    server_nodes: &[(&str, &RsaPublicKey)]
) -> Result<String, Box<dyn std::error::Error>> {
    let mut rng = OsRng;

    // STEP 1: Start with the innermost encryption layer for the recipient
    // generate symmetric key for the recipient's layer (sym_K4)
    let sym_key4 = Aes256Gcm::generate_key(&mut rng);
    let aes_gcm4 = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&sym_key4));
    let nonce4 = Nonce::from_slice(&[0; 12]); // Constant nonce for simplicity

    // encrypt message with sym_K4
    let encrypted_message = aes_gcm4.encrypt(nonce4, message.as_bytes())?;

    // Encrypt sym_K4 with the recipient's public key
    let enc_sym_key4 = recipient_pubkey.encrypt(&mut rng, Pkcs1v15Encrypt, &sym_key4)?; //this is where in future edits we need to add R, A, i, y

    // Combine the innermost layer: Recipient_ID, Enc_R_PK(sym_K4), Enc_symK4(message)
    let mut layer = format!(
        "{}|{}|{}",
        recipient_id,
        STANDARD.encode(&enc_sym_key4),
        STANDARD.encode(&encrypted_message)
    );

    //println!("Initial encrypted layer for recipient: {}", layer);
    println!("Done with encrypted layer for recipient");

    // STEP 2: wrap each subsequent layer in reverse order (starting from Node 3)
    for (node_id, node_pubkey) in server_nodes.iter().rev() {
        // Generate symmetric key for the current layer
        let sym_key = Aes256Gcm::generate_key(&mut rng);
        let aes_gcm = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&sym_key));
        let nonce = Nonce::from_slice(&[0; 12]); // Constant nonce for simplicity

        // encrypt the current layer with the symmetric key
        let encrypted_layer = aes_gcm.encrypt(&nonce, layer.as_bytes())?;

        // encrypt the symmetric key with the node's public key
        let enc_sym_key = node_pubkey.encrypt(&mut rng, Pkcs1v15Encrypt, &sym_key)?;

        // combine the current layer format:
        // node ID, Enc_PK_N(sym_K), Enc_symK(layer)
        layer = format!(
            "{}|{}|{}",
            node_id,
            STANDARD.encode(&enc_sym_key),
            STANDARD.encode(&encrypted_layer)
        );
        //println!("Layer after wrapping with node {}: {}", node_id, layer);
        println!("Done wrapping with node : {}", node_id);
    }


    // FINAL layer - Add a newline here to mark the end of the onion message
    let final_onion = format!("{}\n", layer);  // Adding the newline at the very end

    // after completing all layers, `layer` now represents the fully encrypted onion
    Ok(final_onion)
}

fn onion_receive(
    onion: &str,
    node_seckey: &RsaPrivateKey,
) -> Result<String, Box<dyn std::error::Error>> {
    let parts: Vec<&str> = received_message.split('|').collect();
                        
    if parts.len() != 3 { // Most likely does not happen
        eprintln!("Message received does not have 3 parts!");
    }

    let recipient_id = parts[0];
    let enc_sym_key4 = parts[1];
    let encrypted_message = parts[2];

    //println!("Received: recipient_id = {}, enc_sym_key4 = {}, encrypted_message = {}", recipient_id, enc_sym_key4, encrypted_message); //debug

    // check if this message is for this client (by comparing recipient_id to username)
    if recipient_id != username.trim() { // Hopefully does not happen
        eprintln!("Someone else not recorded is sending this message.")
    }

    // step 3: decode and decrypt symmetric key with the private key
    match STANDARD.decode(enc_sym_key4) {
        Ok(enc_sym_key_bytes) => {
            //println!("Decoded symmetric key bytes: {:?}", enc_sym_key_bytes);
            println!("Decoded symmetric key bytes");
            match personal_seckey.decrypt(Pkcs1v15Encrypt, &enc_sym_key_bytes) {
                Ok(sym_key4) => {
                    //println!("Decrypted symmetric key: {:?}", sym_key4);
                    println!("Decrypted symmetric key");
                    // step 4: use the symmetric key to decrypt the message
                    let aes_gcm4 = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&sym_key4));
                    let nonce4 = Nonce::from_slice(&[0; 12]); // Same nonce as used in encryption

                    // decode encrypted message and do error checking
                    match STANDARD.decode(encrypted_message) {
                        Ok(encrypted_message_bytes) => {
                            //println!("Decoded encrypted message: {:?}", encrypted_message_bytes);
                            println!("Decoded encrypted message");
                            match aes_gcm4.decrypt(nonce4, encrypted_message_bytes.as_ref()) {
                                Ok(decrypted_message) => {
                                    // convert decrypted message to string and print
                                    let message_text = String::from_utf8_lossy(&decrypted_message);
                                    println!("Decrypted message: {}", message_text);
                                },
                                Err(e) => eprintln!("Failed to decrypt message: {}", e),
                            }
                        },
                        Err(e) => eprintln!("Failed to decode encrypted message: {}", e),
                    }
                },
                Err(e) => eprintln!("Failed to decrypt symmetric key: {}", e),
            }
        },
        Err(e) => eprintln!("Failed to decode encrypted symmetric key: {}", e),
    }
}