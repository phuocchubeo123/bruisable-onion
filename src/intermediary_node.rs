// extern crate rsa;
// extern crate sha2;

// use std::str;
// use std::collections::HashMap;

// use rsa::{
//     RsaPrivateKey, RsaPublicKey,
// };

// // Import the IntermediaryNode struct and its implementation from shared.rs (due to dependency issues before...)
// use crate::shared::IntermediaryNode; 


// // registers node
// pub fn register_node(
//     nodes: &mut HashMap<String, IntermediaryNode>,
//     id: &str,
//     public_key: RsaPublicKey,
//     private_key: RsaPrivateKey,
// ) {
//     let node = IntermediaryNode::new(id, public_key, private_key);
//     nodes.insert(id.to_string(), node);
// }