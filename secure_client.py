#!/usr/bin/env python3

import socket
import arguments
import argparse
import cryptgraphy_simulator

# Run 'python3 secure_client.py --help' to see what these lines do
parser = argparse.ArgumentParser('Send a message to a server at the given address and print the response')
parser.add_argument('--server_IP', help='IP address at which the server is hosted', **arguments.ip_addr_arg)
parser.add_argument('--server_port', help='Port number at which the server is hosted', **arguments.server_port_arg)
parser.add_argument('--VPN_IP', help='IP address at which the VPN is hosted', **arguments.ip_addr_arg)
parser.add_argument('--VPN_port', help='Port number at which the VPN is hosted', **arguments.vpn_port_arg)
parser.add_argument('--CA_IP', help='IP address at which the certificate authority is hosted', **arguments.ip_addr_arg)
parser.add_argument('--CA_port', help='Port number at which the certificate authority is hosted', **arguments.CA_port_arg)
parser.add_argument('--CA_public_key', default=None, type=arguments._public_key, help='Public key for the certificate authority as a tuple')
parser.add_argument('--message', default=['Hello, world'], nargs='+', help='The message to send to the server', metavar='MESSAGE')
args = parser.parse_args()

SERVER_IP = args.server_IP  # The server's IP address
SERVER_PORT = args.server_port  # The port used by the server
VPN_IP = args.VPN_IP  # The VPN's IP address
VPN_PORT = args.VPN_port  # The port used by the VPN
CA_IP = args.CA_IP # the IP address used by the certificate authority
CA_PORT = args.CA_port # the port used by the certificate authority
MSG = ' '.join(args.message) # The message to send to the server

if not args.CA_public_key:
    # If the certificate authority's public key isn't provided on the command line,
    # fetch it from the certificate authority directly
    # This is bad practice on the internet. Can you see why?
    print(f"Connecting to the certificate authority at IP {CA_IP} and port {CA_PORT}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((CA_IP, CA_PORT))
        print("Connection established, requesting public key")
        s.sendall(bytes('key', 'utf-8'))
        CA_public_key = s.recv(1024).decode('utf-8')
        # close the connection with the certificate authority
        s.sendall(bytes('done', 'utf-8'))
    print(f"Received public key {CA_public_key} from the certificate authority for verifying certificates")
    CA_public_key = eval(CA_public_key)
else:
    CA_public_key = eval(args.CA_public_key)

## --------------------------------- from the project 1 ----------------------------
#introduction, connection confirmation
print("Welcome to Tomoko's Really Pretty Cool (RPC) Ice Cream Stand!\n")
print("Customer identified! - Connecting you to cashier", VPN_IP, "and port...", VPN_PORT)

#initalizing arguments/parameters for operations
#these arguments will be updated with user input
order_type = ""
size = ""
flavor = ""
syrup = ""
milk = ""
cookie = ""

#order type is updated first, and handles misspelling or empty inputs
while order_type not in ["scoop", "milkshake", "chipwich"]:
    order_type = input("Would you like a scoop, milkshake, or chipwich?\n")   
    if order_type not in ["scoop", "milkshake", "chipwich"]:
        print("I didn't quite catch that! Please choose either scoop, milkshake, or chipwich: ")

    #arguments for scoop order type are updated and include size, flavor, and choice of syrup
    #error handling implemented with if statements!
    if order_type == "scoop":
        while size not in ["small", "medium", "large"]:
            size = input("Specify the cup size: small, medium, large: \n")
            if size not in ["small", "medium", "large"]:
                print("I didn't quite catch that! Please choose either small, medium, or large: \n" )
        
        while flavor not in ["strawberry", "chocolate", "vanilla"]:
            flavor = input("Specify a flavor: strawberry, chocolate, vanilla: \n")
            if flavor not in ["strawberry", "chocolate", "vanilla"]:
                print("I didn't quite catch that! Please choose either strawberry, chocolate, vanilla: \n")

        while syrup not in ["no syrup", "chocolate syrup", "cherry syrup"]:
            syrup = input("Choose a syrup: no syrup, chocolate syrup, or cherry syrup: \n")
            if syrup not in ["no syrup", "chocolate syrup", "cherry syrup"]:
                print("I didn't quite catch that! Please choose either no syrup, chocolate syrup, or cherry syrup: \n")

    #arguments for milkshake order type are updated and include flavor, milk type, and choice of syrup
    #error handling implemented with if statements!
    elif order_type == "milkshake":
        while flavor not in ["strawberry", "chocolate", "vanilla"]:
            flavor = input("Specify a flavor: strawberry, chocolate, vanilla: \n")
            if flavor not in ["strawberry", "chocolate", "vanilla"]:
                print("I didn't quite catch that! Please choose either strawberry, chocolate, vanilla: \n")
        
        while milk not in ["dairy milk", "oat milk", "almond milk", "soy milk"]:
            milk = input("Choose your milk or alternative: dairy milk, oat milk, almond milk, or soy milk: \n")
            if milk not in ["dairy milk", "oat milk", "almond milk", "soy milk"]:
                print("I didn't quite catch that! Please choose either dairy milk, oat milk, almond milk, or soy milk: \n")
        
        while syrup not in ["no syrup", "chocolate syrup", "cherry syrup"]:
            syrup = input("Choose a syrup: no syrup, chocolate syrup, or cherry syrup: \n")
            if syrup not in ["no syrup", "chocolate syrup", "cherry syrup"]:
                print("I didn't quite catch that! Please choose either no syrup, chocolate syrup, or cherry syrup: \n")

    #arguments for chipwich order type are updated and include flavor and choice of cookie
    #error handling implemented with if statements!
    elif order_type == "chipwich":
        while flavor not in ["strawberry", "chocolate", "vanilla"]:
            flavor = input("Specify a flavor: strawberry, chocolate, vanilla: \n")
            if flavor not in ["strawberry", "chocolate", "vanilla"]:
                print("I didn't quite catch that! Please choose either strawberry, chocolate, vanilla: \n")
        
        while cookie not in ["chocolate chip", "oatmeal raisin", "ginger bread"]:
            cookie = input("Choose the cookies for your ice cream sandwich: chocolate chip, oatmeal raisin, ginger bread: \n")
            if cookie not in ["chocolate chip", "oatmeal raisin", "ginger bread"]:
                print("I didn't quite catch that! Please choose either chocolate chip, oatmeal raisin, or ginger bread: \n")

#order_message created based on order type
if order_type == "scoop":
    order_message = f"{order_type},{size},{flavor},{syrup}"
elif order_type == "milkshake":
    order_message = f"{order_type},{flavor},{milk},{syrup}"
elif order_type == "chipwich":
    order_message = f"{order_type},{flavor},{cookie}"

## -------------------------------- from project 1 -------------------------------------

# Add an application-layer header to the message that the VPN can use to forward it
def encode_message(message):
    message = str(SERVER_IP) + '~IP~' +str(SERVER_PORT) + '~port~' + message
    return message

def TLS_handshake_client(connection, server_ip=SERVER_IP, server_port=SERVER_PORT):
    ## Instructions ##
    # Fill this function in with the TLS handshake:
    #  * Request a TLS handshake from the server
    print("Requesting a TLS handshake from the server.")
    connection.sendall(bytes("TLS_HANDSHAKE_REQUEST", 'utf-8'))

    #  * Receive a signed certificate from the server
    signed_certificate = connection.recv(1024).decode('utf-8')
    if not signed_certificate:
        print("Error: Received an empty signed certificate.")
    # Handle this error case appropriately
    print(f"Recieved a signed certificate: {signed_certificate} from the server")

    #  * Verify the certificate with the certificate authority's public key
    #    * Use cryptgraphy_simulator.verify_certificate()
    # if verification is successful, returns the unsigned certificate
    # if verification is unsuccessful, throws an AssertionError exception (catch it with a try/except!)
    try:
        print("Verifying the certificate with the certificate authority's public key.")
        unsigned_certificate = cryptgraphy_simulator.verify_certificate(CA_public_key, signed_certificate)
        print(f"Verification successful, return unsigned certificate: {unsigned_certificate}")
    except Exception as e:
        print(f"Error verifying certificate: {e}")
        return None
    
    #  * Extract the server's public key, IP address, and port from the certificate
    try:
        cert_public_key, cert_SERVER_IP, cert_SERVER_PORT = unsigned_certificate.split(':')
        server_public_key = eval(cert_public_key)
        cert_SERVER_PORT = int(cert_SERVER_PORT)
        print(f"Extracted server public key: {server_public_key}, extracted server IP address: {cert_SERVER_IP}, extracted server PORT: {cert_SERVER_PORT}")
    except Exception as e:
        print(f"Error extracting details from certificate {e}")
        return None
    
    #  * Verify that you're communicating with the port and IP specified in the certificate
    real_SERVER_IP, real_SERVER_PORT = connection.getpeername()
    if cert_SERVER_IP != real_SERVER_IP or cert_SERVER_PORT != real_SERVER_PORT:
        print(f"The server IP and PORT extracted from the certificate {cert_SERVER_IP}, {cert_SERVER_PORT} do not match the actual connection: {real_SERVER_IP},{real_SERVER_PORT}.")
        return None
    print("The server IP and PORT extracted from the certificate were verified successfully.")
    
    #  * Generate a symmetric key to send to the server
    #    * Use cryptography_simulator.generate_symmetric_key()
    symmetric_key = cryptgraphy_simulator.generate_symmetric_key()
    if symmetric_key is None:
        print("Failed to generate symmetric key.")
        return None
    print(f"Generating a symmetric key to send to the server: {symmetric_key}")

    #  * Use the server's public key to encrypt the symmetric key
    #    * Use cryptography_simulator.public_key_encrypt()
    encrypted_symmetric_key = cryptgraphy_simulator.public_key_encrypt(server_public_key, symmetric_key)
    print(f"Encrypting symmetric key using server's public key extracted from certificate: {encrypted_symmetric_key}")
    
    #  * Send the encrypted symmetric key to the server
    connection.sendall(encrypted_symmetric_key.encode('utf-8'))
    print("Sending encrypted symmetric key to the server.")

    #  * Return the symmetric key for use in further communications with the server
    return symmetric_key
    # Make sure to use encode_message() on the first message so the VPN knows which 
    # server to connect with

print("Client starting - connecting to VPN at IP", VPN_IP, "and port", VPN_PORT)
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((VPN_IP, VPN_PORT))
    symmetric_key = TLS_handshake_client(s)
    print(f"TLS handshake complete: sent symmetric key '{symmetric_key}', waiting for acknowledgement")
    data = s.recv(1024).decode('utf-8')
    print(f"Received acknowledgement '{cryptgraphy_simulator.symmetric_decrypt(symmetric_key, data)}', preparing to send message")
    MSG = cryptgraphy_simulator.tls_encode(symmetric_key,MSG)
    print(f"Sending message '{MSG}' to the server")
    s.sendall(bytes(MSG, 'utf-8'))
    print("Message sent, waiting for reply")
    data = s.recv(1024)

print(f"Received raw response: '{data}' [{len(data)} bytes]")
print(f"Decoded message '{cryptgraphy_simulator.tls_decode(symmetric_key, data.decode('utf-8'))}' from server")
print("client is done!")
