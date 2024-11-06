Oct 26 Edit: (client - server socket and messaging between several clients)

To run server type in terminal:
cargo run --bin server

To run serveral clients open up new terminals and type:
cargo run --bin client


Nov 5 - Eileen Changes:
part 1
- add in message functionality (clients choose recipient and message goes to them)
- add existing_users hashmap in client.rs
- parse received messages to determine if server broadcasted a new clients PK and if so, add new users' broadcasted PK to the existing_users hashmap in form <username, usernamePK>

part 2
- added symmetric encryption in client.rs
- implemented client functionality to sample a random path of intermediary nodes
- client will onion encrypt with their chosen path
- client sends path and onion encrypted message to the server
- also included recipient in onion encryption so intermediary nodes know who is next
- fix lock/mutex bugs

part 3
- going to hardcode the list of intermediary nodes that the client chooses to onion encrytp
- use only three for now
- fix server.rs code and client.rs code



NEXT STEPS:

1. fix bugs in server/client.rs code (hardcode to three intermediary nodes)
2. bruisable onion encryption scheme
    - add metadata (role, y, index?) into onion ciphertext
    - add sepal layers to the onion
    - add roles (and define their functionality: gatekeepers vs mixers)
    - peel and bruise onion functionality
4. add the hashes of the sepal layers (tricky) use SHA256
5. tagged encryption to only allow nodes to decrypt if correct sepal layers exist
6. Undo hardcoded sections and implement loops and randomized paths
7. Add checkpoint onions & move Onion into a seperate class
8. Think about the network

