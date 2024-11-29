Oct 26 Edit: (client - server socket and messaging between several clients)

To run server type in terminal:
cargo run --bin server

To run serveral clients open up new terminals and type:
cargo run --bin client


Nov 5/6/7 - Eileen Changes:
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

part 4
- fixed issues and errors
current implementation works as follows:

    1. client wants to send a message: so enters in recipient and message in command line

    2. in client.rs, client first chooses symmetric key, encrypts symmetric key with the recipients public key, then encrypts the message with the symmetric key. Then client chooses three random intermediary nodes. It goes in reverse order (for onion encryption), and starts with the last node. Now it chooses another symmetric key, encrypts the symmetric key with the last nodes public key, and then encrypts the previous layer with the new symmetric key. Goes until last intermediary node.
    Last layer looks like this:
    // in string format: first intermediary node ID | encrypted symmetric key | encrypted layer content \n

    3. Server gets layer and extracts the first intermediary node ID, fetches the corresponding SK, and then decrypts layer to find next node to find SK and decrypt. Final layer will be:
    // in string format: recipient ID, encrypted symmetric key | encryped layer content
    server sends this final encrypted layer to the recipient

    4. recipient uses their own SK to decrypt the final part of the message and decryped message is sent to client. 

    Still is a lot of debugging code printing to command line...

    sample outputs:

    SERVER OUTPUT:
    Enter the number of intermediate clients: 
    4
    Created keys for id 1
    Created keys for id 2
    Created keys for id 3
    Created keys for id 4
    Successfully written pseudo keys to PKKeys.txt!
    Loaded server public keys and private keys.
    Reset the list in UserKeys.txt!
    Server listening on port 7878
    Raw received data: "eileen\n-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEAoRkimaBr1fOr2ZWP1/4QEwUEkjgPd51ouImhKzbDt/bC6ocDxoGy\n7MUcq+cdn5w6+XOa2xkdGdhX8LKLka1A4283N84zBty9StXE3h2QqO/RSnBF5r0p\nYaOUiv5q0FS6uxyN+tRR3LagkuIFAB+mN9NLhNwkgvlHfVEqorVmi9+bVc3Kivxl\nYsZKOXqnbMFK0KJ5vJzpIIQn1D5tS6jRglqORRBtS6Osq2g7OSexiUmyCycFZjPS\nRyLFKis7F96/yKXT80bwrDxz4/llzih97UaARGvnm67Y60odwtcaaAK5BIPMeD0c\nJb/5WFU33LdRqQfBlx/Y7/btvjxysyuaUQIDAQAB\n-----END RSA PUBLIC KEY-----"
    Parsed Username: "eileen"
    Parsed PEM Key Contents:
    -----BEGIN RSA PUBLIC KEY-----
    MIIBCgKCAQEAoRkimaBr1fOr2ZWP1/4QEwUEkjgPd51ouImhKzbDt/bC6ocDxoGy
    7MUcq+cdn5w6+XOa2xkdGdhX8LKLka1A4283N84zBty9StXE3h2QqO/RSnBF5r0p
    YaOUiv5q0FS6uxyN+tRR3LagkuIFAB+mN9NLhNwkgvlHfVEqorVmi9+bVc3Kivxl
    YsZKOXqnbMFK0KJ5vJzpIIQn1D5tS6jRglqORRBtS6Osq2g7OSexiUmyCycFZjPS
    RyLFKis7F96/yKXT80bwrDxz4/llzih97UaARGvnm67Y60odwtcaaAK5BIPMeD0c
    Jb/5WFU33LdRqQfBlx/Y7/btvjxysyuaUQIDAQAB
    -----END RSA PUBLIC KEY-----
    User 'eileen' connected with valid PEM key.
    Added user to list of existing users!
    Current users: ["eileen"]
    Raw received data: "phuoc\n-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEA9E6hR5dI3pcUdj/UiCRdxPdxf09+86FHgBooN2hZxya/QAgZK6LW\nm1nBoayrrb1CYNJOWQwd9lYvIq22fQ+ruRm57gOjIjGKakuZGh5gHP2ssl51G3Xe\n84Vt30UDLAKYSlqwsFDjyEWbUQAW3739Rn7r58Fv6YbcHKqPUO+x8yov2qX4pDeM\nrB2P1JHfyzUBaVLFVj4H19LjMncHTS2ntLza/rFYNI/sUyokZgDDYR0Re9ZYMQuP\noQO7Yl7kQ6SmWnTe8Dwa6U6YW9Ls02J3OVPPDh3Sct+oJYOSiIQVslevjYAkI+Kb\nRIvbkKIZzv7BtStsI+/G8xKzzLHs0szEmQIDAQAB\n-----END RSA PUBLIC KEY-----"
    Parsed Username: "phuoc"
    Parsed PEM Key Contents:
    -----BEGIN RSA PUBLIC KEY-----
    MIIBCgKCAQEA9E6hR5dI3pcUdj/UiCRdxPdxf09+86FHgBooN2hZxya/QAgZK6LW
    m1nBoayrrb1CYNJOWQwd9lYvIq22fQ+ruRm57gOjIjGKakuZGh5gHP2ssl51G3Xe
    84Vt30UDLAKYSlqwsFDjyEWbUQAW3739Rn7r58Fv6YbcHKqPUO+x8yov2qX4pDeM
    rB2P1JHfyzUBaVLFVj4H19LjMncHTS2ntLza/rFYNI/sUyokZgDDYR0Re9ZYMQuP
    oQO7Yl7kQ6SmWnTe8Dwa6U6YW9Ls02J3OVPPDh3Sct+oJYOSiIQVslevjYAkI+Kb
    RIvbkKIZzv7BtStsI+/G8xKzzLHs0szEmQIDAQAB
    -----END RSA PUBLIC KEY-----
    User 'phuoc' connected with valid PEM key.
    Added user to list of existing users!
    Broadcasting new key to eileen
    Current users: ["eileen", "phuoc"]
    Received message: "Node 4|OZG/+vWHyKrJNrW8j40FqxLi/W9dX6Z8r9UasLD6WjqxvEsS4tYE0Lx07fV1vhob2qSwpPRLsUwF6Pyq31TswfF6wFZrc7HNkMVu8Q/hwPabwEHjjXlQZiIxTJk7NjwKTTgcy/QtamJbwtl/iBNXKeA1R6BjnF08sA6r2yemyfh4+ZHX6Zi+2XJh3ZnIiIq0liLVGwqlNv8RhNrZkLodu6uhZv+MNeyYDM0L2jMTxHbwl3Bnp+Jxrut3Pw0Yuy0rEcliR4TTYtvO8GsxNf2z9mICVRHd2pB3J0LWWDZ3c2Som5xBkxIltqItPVEf5BSuTXVdstIzu3vw34hTf4gDRA==|zKQCkqfaPxYREaiE4vMed4I0IyBE/ZUqlwZ8MeYjRBWZ0blamjW3dv7A9Yr/imQC33bGbYuOQYEyw1xjqxEAJOKekQUT9B0UR24rMoW2993YTJwbAqvfiYhDlh9kzqo4fsy8MHmRrkBzLorvigoaQh4jdmWJXd+oeJWbllWh72Q81nQJ+1epL8r6e7g6DzV7H/RzCD8rmu77+pcYfim8G/ofUXu+8zOxVCHMsLttfi4U+ePx4Cy5x4YcMDCtncQMDKXv7/H/qH5GlEtYlZPiv6oOSRTusbDjevDhRMCvrGItf7K/duJfqzOQnOn8yitKPcxTzVGbSRnummNsD2elId7jIPA6juwb+Z3gYapMuusn2pUwqWeQRNzqeTipO5L9sU2vSK/pAjzZ18ZaUzm47HQGaj4PqIPAVynyxPC9fjMJ8ag0HoyHWnq7f1e1o+c1fbuZPt4aSHj9gHgPinsu2WkHUmbkssGwDGm3NiB1D+DJOl7LY3mAKpkZgzh2UjH59W/8P5JPlSY+KsUkFIMgTp4x5klThS+Dn43afKH0PZXcTN8xTieekF89WqKlH+KNfczMdVF8OhTOdSx0BG5stoNX/hWAxrL2dX6LpYYIbwMFHF143ZTfVVUTQjyxy8kUuLKYTSNrjrdhEQg5NIFYa8LF3QMBYgmAC0BUBeBE504Fuzu9WDX201Mswhhn20pO7ItI3tJyGI02KeE9/z15Dx4yZxPXm6IixI9Ydhrv7/e5Zbato3dPHXfWhFJYGxI6Kxcc483CS9knEznbGnyazXYC85PSa88VLqNc9/Mg2s5KUT+S1RV58kmryVfejccGJoa3lX4n2Vh+UfGakhAOYdPXb2xlOJK0pWApc3r148ipAGfbHOvkDz449c+FEu1zUpB83BDtUsW3qEEEzOV+KMV8NGTQyEd9di2JRZEpzMWvPB53Hc1sDMoUdxWp5FALv4fxRrSp3jih/5rbrm6bh7pwU/9HQ9b1NV1DqBWHA0rnql2fV5VobiGsPDH0Bwag5ELU4oNz9QMC3t8On65WVpNh7dgLXqx2VcF/I8NMjBFNd5ycNOjU+tLJamJaN7oCLJzkt8m+IerPIvgbFqedQJfJN2e+ePJV6lAtGpTcj32pbDnC4fljEG1RInDvYiRPRDItOTxbRwd7HfRipKVpzfTjGfdf6efpNqB9uiNoinsQPBzEV8Dzh9mArOCiEnXx0j3IFXsD2qjhRFKxGkK0yNW+FldftvkyFuBtiki4XEmoG0Vlr7UZTxrzzw578SyfYvGhznm2n49tClzQt2WjmKSs2HPY0PSYloEEQaeEluABq+6fJH1a3c/68gIYwkvZ2zAS6UeAXga5bfj5ySvbJV4OkWj84Ahdoo2WkZTY4btY4BodSy8DIHayjTRQtB3jWbg8+CpIxfjfEXdfthwoxtPt9MtUQxlAXTEXN606w3U4NcR4reNJL6EhB4HxkA1e8MTDiDYjlZCnbKFKq/VLUmpLPTz+vs3fM46btyvjdrQvKL5zXf/P0FdmpWnNpFNe9rn2G7NPt+k1CytAI9YU+4d0hEcVIAytsx5jumIYjrNPit3rI93deGBlUL69gLcEPrLEPqVBSBG4LAzF+xHDpABwz/ZXw0xPW/AgI40zCpflMYC4vL0sIsOZyJ1nLLJx/yaeIFcsH29AKVg1XHHM2TmBghc2ZvB2v4HQaw34K4wKyqgL0t5e78A2UuG2kIXdN4yu0zirBQ0ozCprYgDnyTxzxv/0Ojk7DhIuPu9NqestZBTd4f1d9DFpmFDAlHhcPOuih9J9QV0V40aKwR7rr6+hO+9lFFDxkZeWQW5B88W8GVb8uhCDu5D6uF6hF5zEem2IwraVX8DQNO8kYt+HWJ3wtE3zWjl+/jiEaeFMRnBtVKfEJdsbL+TBbv8y/XEsbeq9Qkam+Y1cgqnd/iSmcZeHPAiWB7bM1RxplEEB3/YsKw7eu+aEmOHMA1ysCaHVccouMsqdids5D7hqcGSpplKWng8gR9sWIOfgizxg+u+9Gt8IjIK3inKdDfC//ZLmF5YQbcmRrq18+4Y8XXYogndUbBsF3Kv4bTzDmYWLeHxAfT9m6GFhwbW4z4Uk8vGkS9aIyAjTiMtWLkTC3skovSsg6X2bFx092mKBHEJRo7w="
    Parsed parts: ["Node 4", "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"]


    client eileen output:
    Successfully connected to server on port 7878
    Enter your username:
    eileen
    Loaded server public keys from PKKeys.txt
    Loaded existing user public keys from UserKeys.txt
    Enter recipient:
    Added new user phuoc with public key
    Raw received message: eileen|DMJfmDnJKWK+pqJ5zGP7eCETujnkmc0Xug987+xoJFnSbsyotBMvbUtAar5mA41kC87refOmjjdpwDuq/hQ+sEv7Pfi6FbkeyMyuhP69ysCNn1+vx8vSkMZaQDjAY1ytwthzElVUcuJAhjNStvOPdz3/ifL0o1wDC9+wV2d4EHI91tXegrwhScqSDpR1DBqiSxeO2XB4/rp8xkXVspJUtdqqzPsc25+Fwi52PUeOhp7BPc614hK0zE7cAwLe/RJ1GcVmCwQioussb7x0woQbY8PL8hMkfE8HT0MK3xIre3GmL5/wG5ZBhOH4oPLSPZ31UWEB1cxPzuGqq1NxsxNh7Q==|CfN2vTqT9ECGEXAZRSaiypanDylJ5pCBkDn7snFcG/tozgd0x1HXTA==
    Decoded symmetric key bytes
    Decrypted symmetric key
    Decoded encrypted message
    Decrypted message: hey eileen this is phuoc


    client phuoc code:
    Successfully connected to server on port 7878
    Enter your username:
    phuoc
    Loaded server public keys from PKKeys.txt
    Loaded existing user public keys from UserKeys.txt
    Enter recipient:
    eileen
    Enter your message:
    hey eileen this is phuoc
    Choosing 3 random intermediary nodes.
    Done with encrypted layer for recipient
    Done wrapping with node : Node 2
    Done wrapping with node : Node 1
    Done wrapping with node : Node 4
    Message sent successfully.
    Enter recipient:





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



Meet with Kinan Check-In Next Steps:
1. need to implement bruisable onion and test it
2. Run tests:
    1. test on end to end delivery (between Alice to Bob times) and compare between basic onion scheme and bruisable onion scheme
    2. mini-benchmark tests (like on just how long it takes Alice to encrypt or how long it takes intermediary nodes to decrypt)
    3. Graphs to show how message length affects timing, and how number of intermediary nodes affects timing.

Update 28 Nov 2024:
1. Debugged for every intermediate node (DONE)
2. Write code for receiver (NOT DONE)
3. Make things modular (NOT DONE)