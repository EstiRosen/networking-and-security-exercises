import socket
import select
import msvcrt
import protocol

# NAME <name> will set name. Server will reply error if duplicate
# GET_NAMES will get all names
# MSG <NAME> <message> will send message to client name or to broadcast
# BLOCK <name> will block a user from sending messages to the client who sent the block command
# EXIT will close client


my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
my_socket.connect(("127.0.0.1", protocol.PORT))
try:
    print("Enter commands\n")
    msg = ""
    while msg != "EXIT":
        # Check if the server sent any messages
        rlist, wlist, xlist = select.select([my_socket], [], [], 0.2)
        if rlist:
            print("\r" + " " * (len(msg) + 10) + "\r", end="")  # Clear the current line
            print(f"\nServer sent: {protocol.get_message(rlist[0])}")
            print(msg, end="", flush=True)  # Re-display the user's input

        # Check if the user pressed any key
        if msvcrt.kbhit():
            char = msvcrt.getch().decode("utf-8")  # Read the key pressed
            if char == '\r':  # Enter key pressed
                if msg:
                    data = protocol.create_msg(msg)
                    my_socket.send(data)
                    msg = ""  # Clear the message after sending
                    print("\n")
            elif char == '\b':  # Backspace key pressed
                if msg:  # Only process if there are characters to delete
                    msg = msg[:-1]  # Remove the last character
                    # Update the input display to reflect the change
                    print("\r" + " " * (len(msg) + 1) + "\r" + msg, end="", flush=True)
            else:
                msg += char  # Append the current character to the message
                print(char, end="", flush=True)  # Display the typed character

except KeyboardInterrupt:
    print("\nProgram interrupted by user.")
finally:
    # This block always executes, whether the user presses Ctrl+C (KeyboardInterrupt)
    # or exits the loop by typing "EXIT". It ensures the program cleans up properly.
    data = protocol.create_msg("")
    my_socket.send(data)
    my_socket.close()
