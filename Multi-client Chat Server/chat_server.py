import socket
import select
import protocol
SERVER_IP = "0.0.0.0"


def handle_client_request(current_socket, clients_names, data, blocked_users):
    messages_to_add = []
    current_name = next((name for name, sckt in clients_names.items() if sckt == current_socket), None)
    words = str(data).split()
    dest_socket = current_socket  # Default assignment

    # Assign a name to the client, ensuring no duplicates or reserved names
    if words[0] == "NAME":
        if len(words) < 2:
            reply = "Missing name parameter"
        else:
            name = words[1]
            if current_name:
                reply = f"You already have a name, your name is: {current_name}"
            elif not name.isalpha():
                reply = "Name must be one word containing english letters only"
            elif name in clients_names.keys() or name == "BROADCAST":
                reply = "Requested name is not available"
            else:
                reply = f"Hello {name}"
                clients_names[name] = current_socket

    # Return a space-separated string of all client names
    elif words[0] == "GET_NAMES":
        reply = ' '.join(clients_names.keys())

    # Send a message to a specific user or broadcast to all
    elif words[0] == "MSG":
        if len(words) < 3:
            reply = "Missing parameters"
        else:
            name = words[1]
            msg = ' '.join(words[2:])
            if name == "BROADCAST":  # Broadcast the message to all users except the sender
                if len(clients_names) <= 1:
                    messages_to_add.append((current_socket, "No other users connected"))
                else:
                    for client_name, client_socket in clients_names.items():
                        # Check if the recipient has blocked the sender
                        if client_name in blocked_users and current_name in blocked_users[client_name]:
                            messages_to_add.append((current_socket, f"{client_name} blocked you"))
                        elif client_socket != current_socket:
                            messages_to_add.append((client_socket, f"{current_name} sent {msg}"))
            else:  # Direct message to a specific user
                if name in clients_names:
                    # Check if the recipient has blocked the sender
                    if name in blocked_users and current_name in blocked_users[name]:
                        dest_socket = current_socket
                        reply = f"{name} blocked you"
                    else:
                        dest_socket = clients_names[name]
                        reply = f"{current_name} sent {msg}"
                else:
                    reply = f"No user with the name: \t {name}"
                    dest_socket = current_socket

    # Block a specific user to prevent them from sending messages
    elif words[0] == "BLOCK":
        if len(words) < 2:
            reply = "Missing name parameter"
        else:
            name = words[1]
            if name not in clients_names:
                reply = f"{name} is not a user"
            else:
                if current_name not in blocked_users:
                    blocked_users[current_name] = []
                blocked_users[current_name].append(name)
                reply = f"{name} was successfully blocked"

    else:  # Default case for invalid commands
        reply = "Please enter valid command"

    # Queue message for non-broadcast commands
    if not messages_to_add:
        messages_to_add.append((dest_socket, reply))

    return messages_to_add


# Cleans up resources when a client disconnects.
def close_client(clients_names, current_socket, client_sockets):
    print("Connection closed by client\n")
    # Find and remove the disconnected client from all relevant lists
    client_to_close = next((name for name, sckt in clients_names.items() if sckt == current_socket), None)
    if client_to_close:
        clients_names.pop(client_to_close)
    if current_socket in client_sockets:
        client_sockets.remove(current_socket)
    current_socket.close()


def print_client_sockets(client_sockets):
    for c in client_sockets:
        print("\t", c.getpeername())


def main():
    print("Setting up server")
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_IP, protocol.PORT))
    print("Listening for clients")
    server_socket.listen()

    client_sockets = []
    messages_to_send = []
    clients_names = {}
    blocked_users = {}

    while True:
        read_list = client_sockets + [server_socket]
        # Monitor sockets for activity: readable sockets, writable sockets, and errors
        ready_to_read, ready_to_write, in_error = select.select(read_list, client_sockets, [])
        for current_socket in ready_to_read:
            if current_socket is server_socket:  # New client is connecting
                client_socket, client_address = server_socket.accept()  # Accept the connection
                print("Client joined!\n", client_address)
                client_sockets.append(client_socket)  # Add the new client socket to the list
                print_client_sockets(client_sockets)  # Show all connected clients
            else:
                try:
                    # Attempt to receive a message from the client using the protocol
                    data = protocol.get_message(current_socket)
                    print("Data from client: ")
                    # If an empty string is received, treat it as a disconnection
                    if data == "":
                        close_client(clients_names, current_socket, client_sockets)
                        continue
                except (ConnectionResetError, BrokenPipeError, ValueError):
                    # Handle cases where the client is no longer connected
                    close_client(clients_names, current_socket, client_sockets)
                    continue  # Skip further processing for this client

                # Handle the client's request and queue new messages for sending
                print(data)
                new_messages = handle_client_request(current_socket, clients_names, data, blocked_users)
                messages_to_send += new_messages

        # write to everyone (note: only ones which are free to read...)
        for message in messages_to_send:
            current_socket, data = message
            if current_socket in ready_to_write:
                response = protocol.create_msg(data)
                try:
                    # Attempt to send the response to the client
                    current_socket.send(response)
                except (ConnectionResetError, BrokenPipeError, EOFError):
                    # Handle cases where the client is no longer connected
                    close_client(clients_names, current_socket, client_sockets)
                # Remove the processed message from the queue
                messages_to_send.remove(message)


if __name__ == '__main__':
    main()
