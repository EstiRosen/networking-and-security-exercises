# Ex 4.4 - HTTP Server Shell
# Author: Barak Gonen
# Purpose: Provide a basis for Ex. 4.4
# Note: The code is written in a simple way, without classes, log files or other utilities, for educational purpose
# Usage: Fill the missing functions and constants

import socket
import os

IP = '0.0.0.0'
PORT = 80
SOCKET_TIMEOUT = 2
DOCUMENT_ROOT = "webroot"
REDIRECTION_DICTIONARY = {"uploads/index.html": "index.html"}  # Programmer should pick the old and new resources


# Get data from file.
def get_file_data(filename):
    try:
        with open(filename, 'rb') as file:
            return file.read()
    except FileNotFoundError:
        print(f"File not found: {filename}")
    except Exception as e:
        print(f"Error reading file {filename}: {e}")


# Returns the appropriate Content-Type based on the file extension.
def get_content_type(extension):
    content_types = {
        "html": "text/html",
        "jpg": "image/jpeg",
        "jpeg": "image/jpeg",
        "png": "image/png",
        "css": "text/css",
        "js": "application/javascript",
        "json": "application/json",
        "txt": "text/plain",
        "default": "application/octet-stream"
    }
    return content_types.get(extension, content_types["default"])


# Checks the required resource, generates a proper HTTP response, and sends it to the client.
def handle_client_request(resource, socket):
    # Handle default case: serve index.html for an empty resource
    if resource == '':
        resource = "index.html"

    # Check for redirection
    if resource in REDIRECTION_DICTIONARY:
        new_location = REDIRECTION_DICTIONARY[resource]
        response = f"HTTP/1.1 302 Found\r\nLocation: /{new_location}\r\n\r\n"
        socket.send(response.encode())
        print(f"Redirecting to {new_location}")
        return

    # Split resource into path and query string
    if '?' in resource:
        path, query_string = resource.split('?', 1)
    else:
        path, query_string = resource, ""

    # Parse query parameters into a dictionary
    query = {}
    if query_string:
        for param in query_string.split('&'):
            key, _, value = param.partition('=')
            query[key] = value

    # Handle dynamic requests based on path
    if path == "calculate-area":
        # Ensure required parameters are present and valid
        try:
            # Retrieve parameters
            height = int(query.get('height', [0]))
            width = int(query.get('width', [0]))

            if height > 0 and width > 0:  # Calculate the area only if both parameters are valid and positive
                area = height * width * 0.5
                response_body = f"<h1>Area Calculation</h1><p> Height: {height} Width: {width} Area: {area}</p>"
                response = (
                        "HTTP/1.1 200 OK\r\n"
                        f"Content-Length: {len(response_body)}\r\n"
                        "Content-Type: text/html\r\n\r\n"
                        + response_body
                )
            else:
                # Invalid parameters (non-positive values)
                raise ValueError("Parameters must be positive integers.")

        except (ValueError, KeyError):
            # Handle missing or invalid parameters
            response_body = "<h1>400 Bad Request</h1><p>Invalid parameters provided.</p>"
            response = (
                    "HTTP/1.1 400 Bad Request\r\n"
                    f"Content-Length: {len(response_body)}\r\n"
                    "Content-Type: text/html\r\n\r\n"
                    + response_body
            )

        # Send the response
        socket.send(response.encode())
        print(f"Handled dynamic request: {resource}")
        return

    # Prepend document root to the resource path
    resource_path = os.path.join(DOCUMENT_ROOT, path)

    # Extract file type from resource
    file_extension = os.path.splitext(path)[1][1:]  # Get extension without the dot
    content_type = get_content_type(file_extension)

    # Retrieve file data using get_file_data
    data = get_file_data(resource_path)
    if not data:
        # File not found or error reading it; send 404 response
        response = "HTTP/1.1 404 Not Found\r\n\r\n<h1>404 Not Found</h1>"
        socket.send(response.encode())
        print(f"Resource not found: {resource}")
        return

    # Generate the HTTP response for a successful file retrieval
    response_header = (
        "HTTP/1.1 200 OK\r\n"
        f"Content-Length: {len(data)}\r\n"
        f"Content-Type: {content_type}\r\n\r\n"
    )
    socket.send(response_header.encode() + data)
    print(f"Served resource: {resource}")


# Check if the request is a valid HTTP request and return (True/False, resource).
def validate_HTTP_request(request):
    try:
        # Check that the request ends with the correct delimiter
        if "\r\n\r\n" not in request:
            return False, None

        # Split headers from the body (if any)
        header_section, _, _ = request.partition("\r\n\r\n")

        # Split header section into lines
        lines = header_section.split("\r\n")
        if len(lines) < 2:  # At least Request Line + Host header
            return False, None

        # Extract and validate the request line
        request_line = lines[0]
        parts = request_line.split()
        if len(parts) != 3 or parts[0] != "GET" or not parts[1].startswith("/") or parts[2] != "HTTP/1.1":
            return False, None

        # Validate headers
        headers = lines[1:]
        host_header_present = False

        for header in headers:
            if not header.strip():  # Skip empty lines
                continue

            if ":" not in header:
                return False, None  # Invalid header format, missing colon

            # Split header into name and value
            name, value = header.split(":", 1)
            if not name.strip() or not value.strip():
                return False, None  # Header name or value is empty

            # Check for Host header
            if name.strip().lower() == "host":
                host_header_present = True

        # Ensure Host header is present
        if not host_header_present:
            return False, None

        # Extract resource (remove leading '/')
        resource = parts[1][1:] if len(parts[1]) > 1 else ""
        return True, resource

    except Exception as e:
        print(f"Error validating HTTP request: {e}")
        return False, None


# Handles client requests: verifies client's requests are legal HTTP, calls function to handle the requests.
def handle_client(socket):
    print('Client connected')

    while True:
        try:
            # Receive client request
            client_request = socket.recv(1024).decode()
            if not client_request:
                print('Empty request received. Closing connection.')
                break

            # Validate HTTP request
            valid_http, resource = validate_HTTP_request(client_request)
            if valid_http:
                print('Got HTTP request')
                handle_client_request(resource, socket)
            else:
                print('Error: invalid HTTP request')
                response = "HTTP/1.1 400 Bad Request\r\n\r\n<h1>400 Bad Request</h1>"
                socket.send(response.encode())
            break  # Break after processing one request
        except Exception as e:
            print(f'Error during client handling: {e}')
            break

    print('Closing connection')
    socket.close()


def main():
    # Open a socket and loop forever while waiting for clients
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((IP, PORT))
    server_socket.listen()
    print("Listening for connections on port {}".format(PORT))

    while True:
        client_socket, client_address = server_socket.accept()
        print('New connection received')
        client_socket.settimeout(SOCKET_TIMEOUT)
        handle_client(client_socket)


if __name__ == "__main__":
    # Call the main handler function
    main()
