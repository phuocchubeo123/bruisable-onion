use rsa::{RsaPublicKey, RsaPrivateKey};

// shared.rs
pub struct IntermediaryNode {
    pub id: String,
    pub public_key: RsaPublicKey,
    pub private_key: RsaPrivateKey,
}

impl IntermediaryNode {
    // Constructor method to create a new IntermediaryNode
    pub fn new(id: &str, public_key: RsaPublicKey, private_key: RsaPrivateKey) -> Self {
        IntermediaryNode {
            id: id.to_string(),
            public_key,
            private_key,
        }
    }
}