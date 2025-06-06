"""Encrypted socket client implementation
   Author: Esti Rosen
   Date: 26/12/24
"""

import socket
import protocol

CLIENT_RSA_P = 257
CLIENT_RSA_Q = 263


def main():
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    my_socket.connect(("127.0.0.1", protocol.PORT))

    # Diffie Hellman
    private_key_dh = protocol.diffie_hellman_choose_private_key()  # 1 - choose private key
    public_key_dh = protocol.diffie_hellman_calc_public_key(private_key_dh)  # 2 - calc public key

    # 3 - interact with server and calc shared secret
    msg = protocol.create_msg(str(public_key_dh))
    my_socket.send(msg)

    valid_msg, other_public_key_dh = protocol.get_msg(my_socket)
    if not valid_msg:
        print("Something went wrong with the length field")
        print("Closing\n")
        my_socket.close()
        return
    shared_secret = protocol.diffie_hellman_calc_shared_secret(other_public_key_dh, private_key_dh)

    # RSA
    n = CLIENT_RSA_P * CLIENT_RSA_Q
    totient = (CLIENT_RSA_P - 1) * (CLIENT_RSA_Q - 1)
    public_key_rsa = protocol.get_RSA_public_key(totient)  # Pick public key
    private_key_rsa = protocol.get_RSA_private_key(totient, public_key_rsa)  # Calculate matching private key

    # Exchange RSA public keys with server
    msg = protocol.create_msg(f"{public_key_rsa},{n}")
    my_socket.send(msg)

    valid_msg, other_public_key_rsa = protocol.get_msg(my_socket)
    if not valid_msg:
        print("Something went wrong with the length field")
        print("Closing\n")
        my_socket.close()
        return

    server_public_key, server_n = str(other_public_key_rsa.decode()).split(',')

    while True:
        user_input = input("Enter command\n")

        if user_input == 'EXIT':
            break

        # Encrypt - apply symmetric encryption to the user's input
        encrypted_msg = protocol.symmetric_encryption(user_input.encode('utf-8'), shared_secret)

        # Add MAC (signature)
        hashed_msg = protocol.calc_hash(encrypted_msg)  # 1 - calc hash of user input
        signature = protocol.calc_signature(hashed_msg, private_key_rsa, n)  # 2 - calc the signature

        # Simulate a tampered MAC for testing
        # tampered_signature = bytearray(signature)
        # tampered_signature[0] = (tampered_signature[0] + 1) % 256  # Modify the first byte of the MAC

        # Send to server - Combine encrypted user's message to MAC, send to server
        msg = protocol.create_msg(encrypted_msg + signature)
        my_socket.send(msg)

        # Receive server's message
        valid_msg, message = protocol.get_msg(my_socket)
        if not valid_msg:
            print("Server disconnected")
            break

        # Check if server's message is authentic
        # 1 - separate the message and the MAC
        MAC = message[-3:]
        message = message[:-3]
        # 2 - calc hash of message
        hashed_received_msg = protocol.calc_hash(message)
        #  3 - use server's public RSA key to decrypt the MAC and get the hash
        decrypted_mac = protocol.verify_signature(MAC, server_public_key, server_n)

        # 4 - check if both calculations end up with the same result
        if hashed_received_msg != decrypted_mac:
            print("Warning: Server authentication failed!")
            break
        else:
            # decrypt server's message and print it
            decrypted_msg = protocol.symmetric_encryption(message, shared_secret, False).decode()
            print(f"Server sent: {decrypted_msg}")

    print("Closing\n")
    my_socket.close()


if __name__ == "__main__":
    main()
