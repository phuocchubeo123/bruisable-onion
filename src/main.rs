mod network;

use network::Network;

fn main() {
    let mut net = Network::new();

    net.barabasi_albert(10);
    
    // Display nodes and their connections
    net.display_nodes();

    // Write network to file
    if let Err(e) = net.write_to_file("network.txt") {
        println!("Failed to write network: {}", e);
    }

    // Read network from file
    let mut new_net = Network::new();
    if let Err(e) = new_net.read_from_file("network.txt") {
        println!("Failed to read network: {}", e);
    }

    new_net.display_nodes();
}