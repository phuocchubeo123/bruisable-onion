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