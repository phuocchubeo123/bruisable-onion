extern crate rsa;
use rsa::{RsaPrivateKey, RsaPublicKey, pkcs1::EncodeRsaPublicKey};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use rand::rngs::OsRng;

pub struct IntermediaryNode {
    id: String, 
    pub_key: RsaPublicKey,
    sec_key: RsaPrivateKey
}

impl IntermediaryNode {
    // creates new intermediary node with unique ID and generates its key pair
    pub fn new(id: &str) -> Self {
        let mut rng = OsRng;
        let sec_key = RsaPrivateKey::new(&mut rng, 2048).expect("Failed to generate private key");
        let pub_key = sec_key.to_public_key();

        IntermediaryNode {
            id: id.to_string(),
            pub_key,
            sec_key,
        }
    }


    // decrypts message using the node's private key
    pub fn decrypt_message(&self, encrypted_message: &[u8]) -> Result<Vec<u8>, rsa::errors::Error> {
        self.sec_key.decrypt(rsa::Pkcs1v15Encrypt, encrypted_message)
    }

    // returns node's public key as a PEM string
    pub fn public_key_pem(&self) -> String {
        self.pub_key.to_pkcs1_pem().expect("Failed to encode public key to PEM")
    }
}

pub struct NodeRegistry {
    nodes: Arc<Mutex<HashMap<String, IntermediaryNode>>>
}


impl NodeRegistry {
    // create a new registry for managing intermediary nodes (needed for server)
    pub fn new() -> Self {
        NodeRegistry {
            nodes: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    // register new intermediary node and return its ID
    pub fn create_node(&self, id: &str) {
        let mut nodes = self.nodes.lock().unwrap();
        nodes.insert(id.to_string(), IntermeidaryNode::new(id));
    }

    // retrieve node by its ID
    pub fn get_node(&self, id: &str) -> Option<IntermediaryNode> {
        let nodes = self.nodes.lock().unwrap();
        nodes.get(id).clones()
    }
}
