# CS425: Computer Networks

## Group Members:
- *Abhiraj Singh* (210033)
- *Hemant Kumar* (210433)
- *Pawan Kumar* (210713)

# Multi-threaded Chat Server

## Overview

This chat server is a multi-threaded TCP server that supports:
- *User authentication*: Users must log in using a username and password (as defined in users.txt).
- *Private messaging*: Send a private message with /msg <username> <message>.
- *Broadcast messaging*: Broadcast a message to all users with /broadcast <message>.
- *Group management*: 
  - Create a group using /create group <group_name>.
  - Join a group using /join group <group_name>.
  - Send a message to a group using /group msg <group_name> <message>.
  - Leave a group using /leave group <group_name>.

## Files

- *server_grp.cpp*: Source code for the server.
- *client_grp.cpp*: (Provided separately) Client code for connecting to the server.
- *users.txt*: Contains valid usernames and passwords.
- *Makefile*: Already configured to compile both server and client.
- *README.md*: This file.

## How the Code Works

1. *User Authentication*:
   - When a client connects, the server sends prompts for the username and password.
   - The server reads users.txt at startup to populate a map of valid users.
   - If authentication fails, the client is disconnected.

2. *Client Management*:
   - Each new client connection is handled in a separate thread.
   - The server maintains a thread-safe global map (clients) to track online clients.

3. *Messaging*:
   - *Broadcast*: The /broadcast command sends a message to all connected clients except the sender.
   - *Private Message*: The /msg command sends a message only to the specified user.
   - *Group Messaging and Management*:
     - /create group <group_name> creates a new group.
     - /join group <group_name> adds the user to a group.
     - /group msg <group_name> <message> sends a message to all members of a group (except the sender).
     - /leave group <group_name> removes the user from the specified group.
   - All shared resources (the clients and groups maps) are protected by mutexes to ensure thread safety.

4. *Connection Handling*:
   - If a client disconnects (or sends /exit), the server cleans up by removing the user from the online clients list and from any groups the user was a member of.
   - Other clients are optionally notified when someone joins or leaves.

## How to Compile and Run
1. *Compile*:  
   Open a terminal in the project directory and run:
   ```bash make

   This will compile both the server and client executables (server_grp and client_grp).

2. *Run the Server*:
   In one terminal window, run:
   ./server_grp

   The server will start listening on port 12345.

3. *Run the Client*:
   In another terminal window, run:
   ./client_grp

   Follow the prompts to log in and start chatting.

Additional Notes
	•	The code uses standard C++20 libraries along with POSIX socket functions.
	•	Mutexes (via std::lock_guard<std::mutex>) are used to protect shared resources from concurrent access.
	•	The server handles each client in its own detached thread, allowing multiple clients to communicate concurrently.

Enjoy your chat server!

### Final Notes

• Make sure that your *users.txt* and *server_grp.cpp* files are in the same folder as the Makefile so that the code runs as expected.  
• You may adjust or expand the functionality as needed. This solution meets the assignment’s requirements for authentication, broadcasting, private messaging, and group management.
