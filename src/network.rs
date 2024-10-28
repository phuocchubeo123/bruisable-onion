extern crate rsa;
extern crate rand;

use rsa::{RsaPrivateKey, RsaPublicKey, Pkcs1v15Encrypt};
use rand::{rngs::OsRng, Rng};
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead, Write};


pub struct Node {
    pub id: String,              // Node ID as a String
    pub pubkey: RsaPublicKey,    // Public key
    seckey: RsaPrivateKey,       // Secret key
    pub messages: Vec<String>,   // Messages to send
}

impl Node {
    pub fn new(id: String) -> Node {
        let mut rng = OsRng;
        let bits = 2048;
        let private_key = RsaPrivateKey::new(&mut rng, bits)
            .expect(&format!("Node {}: failed to generate a private key", id));
        let public_key = RsaPublicKey::from(&private_key);

        println!("Node {} created with public key", id);

        Node {
            id,
            pubkey: public_key,
            seckey: private_key,
            messages: Vec::new(),
        }
    }
}

pub struct Network {
    nodes: HashMap<String, Node>,
    edges: HashMap<String, Vec<String>>, // adjacency list
}

impl Network {
    pub fn new() -> Network {
        Network {
            nodes: HashMap::new(),
            edges: HashMap::new(),
        }
    }

    pub fn add_node(&mut self, id: String) {
        let node = Node::new(id.clone());
        self.nodes.insert(id.clone(), node);
        self.edges.insert(id, Vec::new());
    }

    pub fn connect(&mut self, node1: &String, node2: &String) {
        if !self.nodes.contains_key(node2) {
            println!("Node {} does not exist in the network", node2);
            return;
        }

        if let Some(neighbors) = self.edges.get_mut(node1) {
            if !neighbors.contains(node2) {
                neighbors.push(node2.clone());
            } else {
                println!("Nodes {} and {} are already connected", node1, node2);
            }
        } else {
            println!("Node {} does not exist in the network", node1);
        }

        if let Some(neighbors) = self.edges.get_mut(node2) {
            if !neighbors.contains(node1) {
                neighbors.push(node1.clone());
            } else {
                println!("Nodes {} and {} are already connected", node1, node2);
            }
        } else {
            println!("Node {} does not exist in the network", node1);
        }
    }

    pub fn display_nodes(&self) {
        for (id, node) in &self.nodes {
            println!("Node ID: {}", id);
            println!("Public Key: {:?}", node.pubkey);
            println!("Messages: {:?}", node.messages);

            // Display edges
            if let Some(neighbors) = self.edges.get(id) {
                println!("Connected to: {:?}", neighbors);
            } else {
                println!("No connections");
            }

            println!("-------------------------");
        }
    }

    pub fn random_graph(&mut self, num_nodes: usize, num_edges: usize) {
        let mut rng = rand::thread_rng();

        // Add nodes
        for i in 0..num_nodes {
            let node_id = format!("Node{}", i);
            self.add_node(node_id);
        }

        // Add random edges
        for _ in 0..num_edges {
            let node1 = format!("Node{}", rng.gen_range(0..num_nodes));
            let node2 = format!("Node{}", rng.gen_range(0..num_nodes));
            self.connect(&node1, &node2);
        }
    }

    pub fn barabasi_albert(&mut self, num_nodes: usize) {
        let mut rng = rand::thread_rng();
        let mut preferences = Vec::<String>::new(); // This preferences vector helps sampling nodes according to their preferences
        
        self.add_node("Node 1".to_string());
        self.add_node("Node 2".to_string());
        self.connect(&"Node 1".to_string(), &"Node 2".to_string());
        preferences.push("Node 1".to_string());
        preferences.push("Node 2".to_string());

        for i in 3..num_nodes {
            let current_node = format!("Node {}", i);
            self.add_node(current_node.clone());
            let connect_node = preferences[rng.gen_range(0..(2*(i-2)))].clone();
            self.connect(&current_node, &connect_node);
            preferences.push(current_node);
            preferences.push(connect_node);
        }
    }

    // Save the network to a file
    pub fn write_to_file(&self, filename: &str) -> io::Result<()> {
        let mut file = File::create(filename)?;
        for (id, neighbors) in &self.edges {
            writeln!(file, "{}: {:?}", id, neighbors)?;
        }
        Ok(())
    }

    // Load a network from a file
    pub fn read_from_file(&mut self, filename: &str) -> io::Result<()> {
        let file = File::open(filename)?;
        let reader = io::BufReader::new(file);

        self.nodes.clear();
        self.edges.clear();

        for line in reader.lines() {
            let line = line?;
            let parts: Vec<_> = line.split(": ").collect();
            if parts.len() == 2 {
                let node_id = parts[0].to_string();
                let neighbors: Vec<String> = parts[1]
                    .trim_matches(|c| c == '[' || c == ']')
                    .split(", ")
                    .map(|s| s.to_string())
                    .collect();
                self.add_node(node_id.clone()); // Add node to network
                self.edges.insert(node_id, neighbors);
            }
        }
        Ok(())
    }
}