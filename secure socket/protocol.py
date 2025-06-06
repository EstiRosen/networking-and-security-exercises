"""Encrypted sockets protocol implementation
   Author: Esti Rosen
   Date: 26/12/24
"""

import secrets
from sympy import isprime, mod_inverse
import random

LENGTH_FIELD_SIZE = 2
PORT = 8820

DIFFIE_HELLMAN_P = 65437
DIFFIE_HELLMAN_G = 5

LOOKUP_TABLE = [34, 200, 166, 249, 104, 128, 80, 146, 179, 22, 3, 229, 136, 252, 76, 236, 74, 103, 178, 32, 143, 246, 0, 237, 151, 58, 172, 208, 72, 106, 216, 66, 202, 244, 156, 65, 50, 211, 36, 95, 170, 167, 83, 133, 57, 5, 10, 147, 163, 222, 73, 53, 169, 195, 180, 152, 149, 234, 197, 140, 69, 125, 29, 168, 8, 243, 175, 81, 102, 225, 9, 96, 92, 6, 231, 111, 241, 14, 215, 219, 226, 230, 117, 162, 13, 182, 126, 127, 71, 121, 148, 188, 120, 38, 210, 205, 248, 77, 204, 177, 223, 12, 56, 123, 160, 49, 233, 176, 101, 67, 218, 99, 37, 174, 122, 154, 35, 157, 114, 84, 93, 19, 183, 108, 142, 31, 98, 171, 44, 18, 192, 130, 153, 173, 199, 187, 227, 112, 214, 194, 33, 201, 87, 28, 54, 245, 212, 206, 20, 184, 94, 198, 47, 186, 209, 119, 181, 70, 158, 42, 240, 86, 150, 7, 141, 132, 64, 235, 79, 115, 91, 116, 193, 11, 238, 4, 239, 40, 24, 242, 217, 109, 45, 75, 46, 144, 105, 247, 135, 62, 207, 221, 124, 251, 137, 30, 213, 191, 139, 78, 41, 90, 39, 25, 1, 250, 60, 224, 118, 110, 138, 185, 190, 63, 52, 55, 107, 155, 189, 100, 89, 21, 196, 17, 129, 228, 131, 15, 165, 159, 134, 85, 253, 203, 27, 82, 51, 43, 26, 164, 232, 23, 88, 68, 16, 48, 254, 145, 113, 255, 97, 161, 2, 220, 59, 61]
INVERSE_LOOKUP_TABLE = [22, 204, 252, 10, 175, 45, 73, 163, 64, 70, 46, 173, 101, 84, 77, 227, 244, 223, 129, 121, 148, 221, 9, 241, 178, 203, 238, 234, 143, 62, 195, 125, 19, 140, 0, 116, 38, 112, 93, 202, 177, 200, 159, 237, 128, 182, 184, 152, 245, 105, 36, 236, 214, 51, 144, 215, 102, 44, 25, 254, 206, 255, 189, 213, 166, 35, 31, 109, 243, 60, 157, 88, 28, 50, 16, 183, 14, 97, 199, 168, 6, 67, 235, 42, 119, 231, 161, 142, 242, 220, 201, 170, 72, 120, 150, 39, 71, 250, 126, 111, 219, 108, 68, 17, 4, 186, 29, 216, 123, 181, 209, 75, 137, 248, 118, 169, 171, 82, 208, 155, 92, 89, 114, 103, 192, 61, 86, 87, 5, 224, 131, 226, 165, 43, 230, 188, 12, 194, 210, 198, 59, 164, 124, 20, 185, 247, 7, 47, 90, 56, 162, 24, 55, 132, 115, 217, 34, 117, 158, 229, 104, 251, 83, 48, 239, 228, 2, 41, 63, 52, 40, 127, 26, 133, 113, 66, 107, 99, 18, 8, 54, 156, 85, 122, 149, 211, 153, 135, 91, 218, 212, 197, 130, 172, 139, 53, 222, 58, 151, 134, 1, 141, 32, 233, 98, 95, 147, 190, 27, 154, 94, 37, 146, 196, 138, 78, 30, 180, 110, 79, 253, 191, 49, 100, 207, 69, 80, 136, 225, 11, 81, 74, 240, 106, 57, 167, 15, 23, 174, 176, 160, 76, 179, 65, 33, 145, 21, 187, 96, 3, 205, 193, 13, 232, 246, 249]


# Return the encrypted / decrypted data according to value of encrypt parameter
def symmetric_encryption(input_data, key, encrypt=True):

    # Ensure the key is 16 bits
    key = key & 0xFFFF

    # Extract the 2 bytes of the key
    key_bytes = [(key >> 8) & 0xFF, key & 0xFF]

    # Pad input data to make its length a multiple of 4 bytes
    padding_length = (4 - len(input_data) % 4) % 4
    padded_data = input_data + b'\x00' * padding_length

    # Initialize output data as a bytearray
    output_data = bytearray()

    # Process the data in 4-byte blocks
    for i in range(0, len(padded_data), 4):
        # Extract the current 4-byte block
        block = padded_data[i:i + 4]

        # XOR the block with the key bytes cyclically
        block = bytes(b ^ key_bytes[j % 2] for j, b in enumerate(block))

        if encrypt:
            # Apply the lookup table for encryption
            block = bytes([LOOKUP_TABLE[b] for b in block])
            # Perform circular shift (0 -> 1, 1 -> 2, 2 -> 3, 3 -> 0)
            block = block[1:] + block[:1]
        else:
            # Perform reverse circular shift (3 -> 0, 0 -> 1, 1 -> 2, 2 -> 3)
            block = block[-1:] + block[:-1]
            # Reverse the lookup table for decryption
            block = bytes([INVERSE_LOOKUP_TABLE[b] for b in block])

        # XOR the block again with the key bytes cyclically
        block = bytes(b ^ key_bytes[j % 2] for j, b in enumerate(block))

        # Append the processed block to the output
        output_data.extend(block)

    # Remove padding during decryption
    if not encrypt:
        output_data = output_data[:len(input_data)]

    return bytes(output_data)


# Choose a 16 bit size private key
def diffie_hellman_choose_private_key():
    # The private key is a 16-bit integer in the range [2, 65535].
    return secrets.randbelow(65534) + 2


# Calculate diffie hellman public key
def diffie_hellman_calc_public_key(private_key):
    return pow(DIFFIE_HELLMAN_G, private_key, DIFFIE_HELLMAN_P)


# Calculate diffie hellman shared secret given private key and other side's public key
def diffie_hellman_calc_shared_secret(other_side_public, my_private):
    return pow(int(other_side_public), my_private, DIFFIE_HELLMAN_P)


# Create a 16-bit hash from the message.
def calc_hash(message):

    hash_value = 0xAAAA  # Initialize a 16-bit hash value, Some arbitrary starting value

    message = str(message)

    for i, char in enumerate(message):
        # XOR the character with the current hash value
        char_value = ord(char)  # Get the ASCII value of the character
        hash_value ^= char_value  # XOR with the current hash value

        # Mix the bits: rotate hash_value left and add the index
        hash_value = ((hash_value << 3) | (hash_value >> 13)) & 0xFFFF  # Rotate left by 3 bits (16-bit max)
        hash_value += i  # Add the character's position for uniqueness
        hash_value &= 0xFFFF  # Ensure it remains 16 bits

    return hash_value


# Calculate the signature, using RSA alogorithm
def calc_signature(hash, RSA_private_key, n):
    # Calculate the RSA signature
    result = pow(hash, RSA_private_key, n)

    # Determine the fixed byte size (n requires up to 17 bits, which is 3 bytes)
    byte_size = 3  # Fixed size in bytes for a 5-digit n (17 bits -> 3 bytes)

    # Convert the result to bytes and pad with leading zeros to ensure fixed size
    result_bytes = result.to_bytes(byte_size, byteorder='big')

    return result_bytes


# Verify the signature to recover the original hash.
def verify_signature(signature, RSA_public_key, n):

    # Convert the signature from bytes back to an integer
    signature_int = int.from_bytes(signature, byteorder='big')

    # Decrypt the signature to find the original hash
    original_hash = pow(signature_int, int(RSA_public_key), int(n))
    return original_hash


# Create a valid protocol message, with length field.
def create_msg(data):

    # If data is not bytes, ensure it's converted to bytes
    if not isinstance(data, bytes):
        data = str(data).encode()  # Convert non-bytes data to bytes

    # Calculate the length of the data
    length = len(data)

    # Ensure the length field has proper size
    length_field = str(length).zfill(LENGTH_FIELD_SIZE).encode()

    # Concatenate length field with data
    return length_field + data


# Extract message from protocol, without the length field
def get_msg(my_socket):

    # Receive the length field
    length_field = my_socket.recv(LENGTH_FIELD_SIZE)
    if not length_field:
        return False, "Error: No data received for length field"

    # Decode and convert length field to an integer
    try:
        length = int(length_field.decode())
    except ValueError:
        return False, "Error: Invalid length field"

    msg = my_socket.recv(length)
    return True, msg


# Choose RSA public key that satisfies the conditions
def get_RSA_public_key(totient):

    # Find all valid keys
    valid_keys = [key for key in range(2, totient) if isprime(key) and totient % key != 0]

    if not valid_keys:
        raise ValueError("No valid public key found.")

    # Choose a random key from the list of valid keys
    return random.choice(valid_keys)


# Calculate the pair of the RSA public key
def get_RSA_private_key(totient, public_key):
    private_key = mod_inverse(public_key, totient)
    if not private_key:
        raise ValueError("No valid private key found.")
    return private_key

