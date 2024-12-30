# Message Format

## Overview of Application
The secure client, VPN, secure server, and certificate authority all take command line arguments, and the client message is constructed through a series of inputs prompted by questions about an ice cream order. A TLS Handshake is used to generate a symmetric key, and using this symmetric key, the client and server securely exchange a message. This message is constructed through a series of inputs constructed through a series of inputs prompted by questions about an ice cream order. The secure client sends the symmetric key encrypted order message to the VPN server, which the VPN then forwards to the secure server, and waits for a response. The secure server decrypts this message and constructs a response, then encrypting it using the symmetric key, and sends the encrypted response to the VPN server, which the VPN server forwards back to the client, which is then decrypted one last time by the client.

## Format of an unsigned certificate
The format of the unsigned certificate consists of three parts: the server's public key, the server's IP address, and the server's PORT number. The three elements are separated by a colon in parsing. Example: (18606, 56533):127.0.0.1:65432

## Example output
### Client Output
Connecting to the certificate authority at IP 127.0.0.1 and port 55553
Connection established, requesting public key
Received public key (55580, 56533) from the certificate authority for verifying certificates
Welcome to Tomoko's Really Pretty Cool (RPC) Ice Cream Stand!

Customer identified! - Connecting you to cashier 127.0.0.1 and port... 55554
Would you like a scoop, milkshake, or chipwich?
scoop
Specify the cup size: small, medium, large: 
small
Specify a flavor: strawberry, chocolate, vanilla: 
vanilla
Choose a syrup: no syrup, chocolate syrup, or cherry syrup: 
no syrup
Client starting - connecting to VPN at IP 127.0.0.1 and port 55554
Requesting a TLS handshake from the server.
Recieved a signed certificate: D_(953, 56533)[(18606, 56533):127.0.0.1:65432] from the server
Verifying the certificate with the certificate authority's public key.
Verification successful, return unsigned certificate: (18606, 56533):127.0.0.1:65432
Extracted server public key: (18606, 56533), extracted server IP address: 127.0.0.1, extracted server PORT: 65432
Indicating successful retrieval of public key, ip, and port from signed certificate.
Extracted real server IP: 127.0.0.1 and real server PORT 65432.
The server IP and PORT extracted from the certificate were verified successfully.
Generating a symmetric key to send to the server: 59140
Encrypting symmetric key using server's public key extracted from certificate: E_(18606, 56533)[59140]
Sending encrypted symmetric key to the server.
TLS handshake complete: sent symmetric key '59140', waiting for acknowledgement
Received acknowledgement 'Symmetric key '59140' received', preparing to send message
Sending message 'HMAC_38826[symmetric_59140[scoop,small,vanilla,no syrup]]' to the server
Message sent, waiting for reply
Received raw response: 'b'HMAC_48052[symmetric_59140[Here is your small vanilla scoop with no syrup!]]'' [76 bytes]
Decoded message 'Here is your small vanilla scoop with no syrup!' from server
client is done!

### VPN Output
VPN starting - listening for connections at IP 127.0.0.1 and port 55554
Connected established with ('127.0.0.1', 53756)
Received client message: 'b'127.0.0.1~IP~65432~port~TLS_HANDSHAKE_REQUEST'' [45 bytes]
connecting to server at IP 127.0.0.1 and port 65432
server connection established, sending message 'TLS_HANDSHAKE_REQUEST'
message sent to server, waiting for reply
Received server response: 'b'D_(953, 56533)[(18606, 56533):127.0.0.1:65432]'' [46 bytes], forwarding to client
Received client message: 'b'127.0.0.1~IP~65432~port~SUCCESS'' [31 bytes], forwarding to server
Received server response: 'b'127.0.0.1:65432'' [15 bytes], forwarding to client
Received client message: 'b'E_(18606, 56533)[59140]'' [23 bytes], forwarding to server
Received server response: 'b"symmetric_59140[Symmetric key '59140' received]"' [47 bytes], forwarding to client
Received client message: 'b'HMAC_38826[symmetric_59140[scoop,small,vanilla,no syrup]]'' [57 bytes], forwarding to server
Received server response: 'b'HMAC_48052[symmetric_59140[Here is your small vanilla scoop with no syrup!]]'' [76 bytes], forwarding to client
VPN is done!

### Server Output
Generated public key '(18606, 56533)' and private key '37927'
Connecting to the certificate authority at IP 127.0.0.1 and port 55553
Prepared the formatted unsigned certificate '(18606, 56533):127.0.0.1:65432'
Connection established, sending certificate '(18606, 56533):127.0.0.1:65432' to the certificate authority to be signed
Received signed certificate 'D_(953, 56533)[(18606, 56533):127.0.0.1:65432]' from the certificate authority
server starting - listening for connections at IP 127.0.0.1 and port 65432
Connected established with ('127.0.0.1', 53757)
Waiting for TLS handshake request from the client.
Received TLS handshake request: TLS_HANDSHAKE_REQUEST
Proceeding with TLS handshake.
Sending signed certificate: D_(953, 56533)[(18606, 56533):127.0.0.1:65432] to client for asymmetric encryption process.
Waiting for indication of successful retrieval of public key, ip, and port from signed certificate.
Received indication of success: 127.0.0.1~IP~65432~port~SUCCESS
Proceeding with TLS handshake (2).
Sending real Server IP ad PORT for verification: 127.0.0.1:65432
Received encrypted symmetric key: E_(18606, 56533)[59140]
Symmetric key decrypted successfully: 59140
TLS handshake complete: established symmetric key '59140', acknowledging to client
Received client message: 'b'HMAC_38826[symmetric_59140[scoop,small,vanilla,no syrup]]'' [57 bytes]
Decoded message 'scoop,small,vanilla,no syrup' from client
Order recieved: scoop,small,vanilla,no syrup
Responding 'Here is your small vanilla scoop with no syrup!' to the client
Sending encoded response 'HMAC_48052[symmetric_59140[Here is your small vanilla scoop with no syrup!]]' back to the client
server is done!

### Client Authority Output
Certificate Authority started using public key '(55580, 56533)' and private key '953'
Certificate authority starting - listening for connections at IP 127.0.0.1 and port 55553
Connected established with ('127.0.0.1', 53752)
Received client message: 'b'$(18606, 56533):127.0.0.1:65432'' [31 bytes]
Signing '(18606, 56533):127.0.0.1:65432' and returning it to the client.
Received client message: 'b'done'' [4 bytes]
('127.0.0.1', 53752) has closed the remote connection - listening 
Connected established with ('127.0.0.1', 53753)
Received client message: 'b'key'' [3 bytes]
Sending the certificate authority's public key (55580, 56533) to the client
Received client message: 'b'done'' [4 bytes]
('127.0.0.1', 53753) has closed the remote connection - listening 

## TLS Handshake Walkthrough 
The secure server first gneerates a public/private key pair, creates a certificate that contains its public key, IP address, and PORT number, and sends the certificate to the certificate authority for verification. The certificate authority signs the certificate, sends the signed certificate back to the secure server, and the secure server promptly closes the connection with the certificate authority. After fetching the certificate authority's public key, the secure client sends a request for a TLS handshake with the secure server through the VPN, and the secure server waits to receive a request for the TLS handshake from the secure client through the VPN. Upon receiving the request for a TLS handshake, the secure server sends the signed certificate contianing the the public key, server IP, and PORT number to the secure client through the VPN. The secure client receives this signed certificate and decrypts it, then verifying it by matching the extracted public key with the certificate authority's public key. If it matches, it then verifies that the IP address and PORT number in the signed certificate corresponds to the IP and PORT the secure client believes it is intending communication with. Upon verification, the secure client generates a symmetric key and encrypts it using the secure server's public key, and sends the encrypted symmetric key to the secure server through the VPN. The secure server waits to receive an encrypted symmetric key from the client, and decrypts it using its private key, and successfully extracts the symmetric key, sending back an encrypted acknowledgement back to the client. With this the TLS Handshake exchange is concluded, the symmetric key between the secure client and secure server has been established, and this symmetric key is used for symmetric encryption for the user-input constructed message to be processed by the server. 


## Limitations
One of the ways our simulation fails to achieve real security is in how the secure client fetches and uses the certificate authority's public key. This is especially vulnerable to a Man-In-The-Middle (MITM) attack, as the client requests a public key directly from the certificate authority if it is not provided in the command line. As the key request is made using an unencrypted socket connection, it is easy for a potential attacker to intercept and send a compromised CA key that the client would then use to verify the server certificate. If this were to be improved, the communication with the certificate authority would be done over a secure channel such as HTTPS to prevent any potential interference.

A second way our simlation fails to achieve real security is in the lack of verification algorithms in ensuring that the encrypted message has not been tampered with, and tha the encrypted message itself is from the correct source. As the program is right now, the there is a lack of integrity and authentication. An Hash-based Message Authentication Code (HMAC) would improve this vulnerability by ensuring that the message, encrypted or not, has not been altered at any point during transmission between the secure client and server. An HMAC would also assist in the client and server both in verifying that the message came from the respective server/client, as HMACs can only be generated by someone with the symmetric key that the client and server share.


## Acknowledgements
I did not collaborate with anyone on this assignment, but used online sources to review python syntax and specifically stack overflow to debug.

## Client>Server/Server>Client Application Layer Message Format (incomplete)

If the order type is a scoop:
"Here is your {size} {flavor} {order_type} with {syrup}!"

If the order type is a milkshake:
"Here is your {flavor} {order_type} with {milk} and {syrup}!"
If the order type is a chipwich:
"Here is your {flavor} chipwich with {cookie} cookies!"

Otherwise:
"You did not specify an order type! Please try ordering again."