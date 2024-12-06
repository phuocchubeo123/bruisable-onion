**Bruisable Onion**

Implementation for Brown's CSCI 2390 Final Project, based on the following paper: [https://eprint.iacr.org/2024/885].

Dependencies:
Only Rust, other dependencies are readily handled by Cargo.

Steps to use:
1. Build the project
> cargo build
2. Generate intermediate keys
> cargo run --bin server_key_gen

We recommend generating around 20 keys to play around first. Further experiment with a large number of intermediate nodes is also possible.

3. Run the server
> cargo run --bin server
4. Open other terminals, connect to as many clients as you like, and test it out!
> cargo run --bin client
