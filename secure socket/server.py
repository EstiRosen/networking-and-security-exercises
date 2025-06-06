"""Encrypted socket server implementation
 Author: Esti Rosen
   Date: 26/12/24
"""

import socket
import protocol

SERVER_RSA_P = 269
SERVER_RSA_Q = 251


def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("0.0.0.0", protocol.PORT))
    server_socket.listen()
    print("Server is up and running")
    (client_socket, client_address) = server_socket.accept()
    print("Client connected")

    # Diffie Hellman
    private_key_dh = protocol.diffie_hellman_choose_private_key()  # 1 - choose private key
    public_key_dh = protocol.diffie_hellman_calc_public_key(private_key_dh)  # 2 - calc public key

    # 3 - interact with client and calc shared secret
    msg = protocol.create_msg(str(public_key_dh))
    client_socket.send(msg)

    valid_msg, other_public_key_dh = protocol.get_msg(client_socket)
    if not valid_msg:
        print("Something went wrong with the length field")
        print("Closing\n")
        client_socket.close()
        server_socket.close()
        return
    shared_secret = protocol.diffie_hellman_calc_shared_secret(other_public_key_dh, private_key_dh)

    # RSA
    n = SERVER_RSA_P * SERVER_RSA_Q
    totient = (SERVER_RSA_P - 1) * (SERVER_RSA_Q - 1)
    public_key_rsa = protocol.get_RSA_public_key(totient)  # Pick public key
    private_key_rsa = protocol.get_RSA_private_key(totient, public_key_rsa)  # Calculate matching private key

    # Exchange RSA public keys with client
    msg = protocol.create_msg(f"{public_key_rsa},{n}")
    client_socket.send(msg)
    valid_msg, other_public_key_rsa = protocol.get_msg(client_socket)
    if not valid_msg:
        print("Something went wrong with the length field")
        print("Closing\n")
        client_socket.close()
        server_socket.close()
        return
    other_public_key_rsa = other_public_key_rsa.decode()
    client_public_key, client_n = str(other_public_key_rsa).split(',')

    while True:
        try:
            # Receive client's message
            valid_msg, message = protocol.get_msg(client_socket)
            if not valid_msg:
                print("Something went wrong with the length field")
                break

            # Check if client's message is authentic
            # 1 - separate the message and the MAC
            MAC = message[-3:]
            message = message[:-3]

            # 2 - calc hash of message
            hashed_received_msg = protocol.calc_hash(message)

            # 3 - use client's public RSA key to decrypt the MAC and get the hash
            decrypted_mac = protocol.verify_signature(MAC, client_public_key, client_n)

            # 4 - check if both calculations end up with the same result
            if hashed_received_msg != decrypted_mac:
                print("Warning: Client authentication failed!")
                break
            else:
                # decrypt the client's message and print it
                decrypted_msg = protocol.symmetric_encryption(message, shared_secret, False).decode()
                print(f"Client sent: {decrypted_msg}")

            # Create response. The response would be the echo of the client's message
            response = f"you sent {decrypted_msg}"

            # Encrypt - apply symmetric encryption to the server's message
            encrypted_msg = protocol.symmetric_encryption(response.encode('utf-8'), shared_secret)
            hashed_msg = protocol.calc_hash(encrypted_msg)
            signature = protocol.calc_signature(hashed_msg, private_key_rsa, n)

            # Combine encrypted user's message to MAC, send to client
            msg = protocol.create_msg(encrypted_msg + signature)
            client_socket.send(msg)
        except (ConnectionAbortedError, ConnectionResetError):
            print("Client disconnected")
            break

    print("Closing\n")
    client_socket.close()
    server_socket.close()


if __name__ == "__main__":
    main()
