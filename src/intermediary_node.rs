extern crate rsa;
extern crate sha2;

use std::{cmp::max, str};
use std::collections::HashMap;

use rsa::{
    pkcs1::{
        DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPrivateKey, EncodeRsaPublicKey, LineEnding,
    },
    sha2::Sha256, Oaep, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey,
};
use rsa::pkcs8::{EncodePrivateKey, DecodePrivateKey};
use base64::{engine::general_purpose::STANDARD, Engine};
use rand::{rngs::OsRng, RngCore};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use sha2::Digest;

// Import the IntermediaryNode struct and its implementation
use crate::shared::IntermediaryNode; // Import from shared.rs



pub fn register_node(
    nodes: &mut HashMap<String, IntermediaryNode>,
    id: &str,
    public_key: RsaPublicKey,
    private_key: RsaPrivateKey,
) {
    let node = IntermediaryNode::new(id, public_key, private_key);
    nodes.insert(id.to_string(), node);
}