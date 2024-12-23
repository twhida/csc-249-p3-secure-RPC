A **text** (.txt or .md) document with a written description of your client-VPN message format (that is, a description of all implemented client and VPN messages, and how the various components of each message are represented). Your goal in writing this document should be to convey enough information in enough detail to allow a competent programmer **without access to your source code** to write either a new secure client that communicates properly with your secure server, or a new secure server that communicates properly with your client. This document should include at least **six** sections:
1. Overview of Application
2. Format of an unsigned certificate
3. Example output
4. **A walkthorough of the steps of a TLS handshake, and what each step accomplishes**
    * For example, one step will be: "The client encrypts the generated symmetric key before sending it to the server. If it doesn't, the VPN will be able to read the symmetric key in transit and use it to decrypt further secure communications between the client and server encrypted and HMAC'd with that key."
5. A description of two ways in which our simulation fails to achieve real security, and how these failures might be exploited by a malicious party. This is one place you can earn extra credit by discussing some less-obvious exploits. Some options for discussion are:
    * The asymmetric key generation scheme
    * The encryption/decryption/HMAC/verification algorithms
    * The certificate authority's public key distribution system
    * The use of python's "eval()" function
6. Acknowledgements
7. (Optional) Client->Server and Server->Client application layer message format if you decide to change "process_message()" in "secure_server.py". This can be another source of extra credit if you're creative with your application.