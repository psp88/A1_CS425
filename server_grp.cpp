// Group Members for Assignment_1:
// 1. Abhiraj Singh (210033)
// 2. Hemant Kumar (210433)
// 3. Pawan Kumar (210713)

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <cstring>
#include <unordered_map>
#include <unordered_set>
#include <thread>
#include <mutex>
#include <algorithm>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#define PORT 12345
#define BUFFER_SIZE 1024

// data structures used
// clients: mapping client socket -> username 
// users: mapping username -> password 
// groups: mapping group name -> set of client sockets
std::unordered_map<int, std::string> clients;
std::unordered_map<std::string, std::string> users;
std::unordered_map<std::string, std::unordered_set<int>> groups;

std::mutex clients_mutex;
std::mutex groups_mutex;

// send a message to a client socket.
void send_message(int client_socket, const std::string &message)
{
    send(client_socket, message.c_str(), message.size(), 0);
}

// Load allowed users 
void load_users(const std::string &filename)
{
    std::ifstream infile(filename);
    if (!infile.is_open())
    {
        std::cerr << "Error opening " << filename << std::endl;
        return;
    }
    std::string line;
    while (std::getline(infile, line))
    {
        if (line.empty())
            continue;
        size_t delim_pos = line.find(':');
        if (delim_pos != std::string::npos)
        {
            std::string username = line.substr(0, delim_pos);
            std::string password = line.substr(delim_pos + 1);
            users[username] = password;
        }
    }
    infile.close();
}

// Broadcast a message to all connected clients (except the sender)
void broadcast_message(int sender_socket, const std::string &message)
{
    std::lock_guard<std::mutex> lock(clients_mutex);
    for (const auto &pair : clients)
    {
        int client_socket = pair.first;
        if (client_socket != sender_socket)
        {
            send_message(client_socket, message);
        }
    }
}

// Send a private message to a particular user 
void private_message(int sender_socket, const std::string &target_username, const std::string &message)
{
    int target_socket = -1;
    {
        std::lock_guard<std::mutex> lock(clients_mutex);
        for (const auto &pair : clients)
        {
            if (pair.second == target_username)
            {
                target_socket = pair.first;
                break;
            }
        }
    }
    if (target_socket != -1)
    {
        send_message(target_socket, message);
    }
    else
    {
        send_message(sender_socket, "User not found or not online.\n");
    }
}

// Send a message to all members of a group (except the sender)
void group_message(int sender_socket, const std::string &group_name, const std::string &message)
{
    std::lock_guard<std::mutex> lock(groups_mutex);
    if (groups.find(group_name) != groups.end())
    {
        for (int sock : groups[group_name])
        {
            if (sock != sender_socket)
            {
                send_message(sock, message);
            }
        }
    }
    else
    {
        send_message(sender_socket, "Group not found.\n");
    }
}

// Remove a client socket from all groups
void remove_client_from_groups(int client_socket)
{
    std::lock_guard<std::mutex> lock(groups_mutex);
    for (auto &pair : groups)
    {
        pair.second.erase(client_socket);
    }
}

// function that handles each connected client.
void handle_client(int client_socket)
{
    char buffer[BUFFER_SIZE];

    // 1. Authentication
    std::string username, password;

    // Ask for username
    send_message(client_socket, "Enter username: ");
    memset(buffer, 0, BUFFER_SIZE);
    int bytes_received = recv(client_socket, buffer, BUFFER_SIZE, 0);
    if (bytes_received <= 0)
    {
        close(client_socket);
        return;
    }
    username = std::string(buffer);

    username.erase(std::remove(username.begin(), username.end(), '\n'), username.end());
    username.erase(std::remove(username.begin(), username.end(), '\r'), username.end());

    // Ask for password
    send_message(client_socket, "Enter password: ");
    memset(buffer, 0, BUFFER_SIZE);
    bytes_received = recv(client_socket, buffer, BUFFER_SIZE, 0);
    if (bytes_received <= 0)
    {
        close(client_socket);
        return;
    }
    password = std::string(buffer);
    password.erase(std::remove(password.begin(), password.end(), '\n'), password.end());
    password.erase(std::remove(password.begin(), password.end(), '\r'), password.end());

    if (users.find(username) == users.end() || users[username] != password)
    {
        send_message(client_socket, "Authentication failed.\n");
        close(client_socket);
        return;
    }

    {
        std::lock_guard<std::mutex> lock(clients_mutex);
        clients[client_socket] = username;
    }
    send_message(client_socket, "Welcome to the server!\n");

    std::string joinNotice = username + " has joined the chat.\n";
    broadcast_message(client_socket, joinNotice);

    // 2. Main loop: Process commands and messages
    while (true)
    {
        memset(buffer, 0, BUFFER_SIZE);
        bytes_received = recv(client_socket, buffer, BUFFER_SIZE, 0);
        if (bytes_received <= 0)
            break; // Client disconnected

        std::string input(buffer);

        input.erase(std::remove(input.begin(), input.end(), '\n'), input.end());
        input.erase(std::remove(input.begin(), input.end(), '\r'), input.end());
        if (input.empty())
            continue;

        // If client wishes to exit.
        if (input == "/exit")
        {
            break;
        }

        std::istringstream iss(input);
        std::string command;
        iss >> command;

        if (command == "/broadcast")
        {
            std::string msg;
            std::getline(iss, msg);
            if (!msg.empty() && msg[0] == ' ')
                msg.erase(0, 1);
            std::string fullMsg = username + " (broadcast): " + msg + "\n";
            broadcast_message(client_socket, fullMsg);
        }
        else if (command == "/msg")
        {
            std::string target_username;
            iss >> target_username;
            std::string msg;
            std::getline(iss, msg);
            if (!msg.empty() && msg[0] == ' ')
                msg.erase(0, 1);
            std::string fullMsg = username + " (private): " + msg + "\n";
            private_message(client_socket, target_username, fullMsg);
        }
        else if (command == "/create_group")
        {
            std::string group_name;
            iss >> group_name;
            if (group_name.empty())
            {
                send_message(client_socket, "Usage: /create group <group_name>\n");
            }
            else
            {
                std::lock_guard<std::mutex> lock(groups_mutex);
                if (groups.find(group_name) == groups.end())
                {
                    groups[group_name] = std::unordered_set<int>();
                    groups[group_name].insert(client_socket);
                    send_message(client_socket, "Group " + group_name + " created.\n");
                }
                else
                {
                    send_message(client_socket, "Group " + group_name + " already exists.\n");
                }
            }
        }
        else if (command == "/join_group")
        {
            std::string group_name;
            iss >> group_name;
            if (group_name.empty())
            {
                send_message(client_socket, "Usage: /join group <group_name>\n");
            }
            else
            {
                std::lock_guard<std::mutex> lock(groups_mutex);
                if (groups.find(group_name) != groups.end())
                {
                    groups[group_name].insert(client_socket);
                    send_message(client_socket, "Joined group " + group_name + ".\n");
                }
                else
                {
                    send_message(client_socket, "Group " + group_name + " does not exist. Create it first using /create group <group_name>.\n");
                }
            }
        }
        else if (command == "/leave_group")
        {
            std::string group_name;
            iss >> group_name;
            if (group_name.empty())
            {
                send_message(client_socket, "Usage: /leave group <group_name>\n");
            }
            else
            {
                std::lock_guard<std::mutex> lock(groups_mutex);
                if (groups.find(group_name) != groups.end() &&
                    groups[group_name].count(client_socket))
                {
                    groups[group_name].erase(client_socket);
                    send_message(client_socket, "Left group " + group_name + ".\n");
                }
                else
                {
                    send_message(client_socket, "You are not in group " + group_name + ".\n");
                }
            }
        }
        else if (command == "/group_msg")
        {

            std::string group_name;
            iss >> group_name;
            std::string msg;
            std::getline(iss, msg);
            if (!msg.empty() && msg[0] == ' ')
                msg.erase(0, 1);
            if (group_name.empty() || msg.empty())
            {
                send_message(client_socket, "Usage: /group msg <group_name> <message>\n");
            }
            else
            {
                std::string fullMsg = username + " (" + group_name + "): " + msg + "\n";
                group_message(client_socket, group_name, fullMsg);
            }
        }
        else
        {
            send_message(client_socket, "Unknown command.\n");
        }
    }

    // 3. Clean-up on disconnect
    {
        std::lock_guard<std::mutex> lock(clients_mutex);
        clients.erase(client_socket);
    }
    remove_client_from_groups(client_socket);
    std::string leaveNotice = username + " has left the chat.\n";
    broadcast_message(client_socket, leaveNotice);
    close(client_socket);
}

int main()
{
    // Load the users
    load_users("users.txt");

    // Create a TCP socket
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0)
    {
        std::cerr << "Error creating socket.\n";
        return 1;
    }

    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
    {
        std::cerr << "setsockopt failed\n";
        return 1;
    }

    sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(PORT);
    server_address.sin_addr.s_addr = INADDR_ANY;
    if (bind(server_socket, (sockaddr *)&server_address, sizeof(server_address)) < 0)
    {
        std::cerr << "Bind failed.\n";
        return 1;
    }

    if (listen(server_socket, 5) < 0)
    {
        std::cerr << "Listen failed.\n";
        return 1;
    }
    std::cout << "Server listening on port " << PORT << std::endl;

    while (true)
    {
        sockaddr_in client_address;
        socklen_t client_len = sizeof(client_address);
        int client_socket = accept(server_socket, (sockaddr *)&client_address, &client_len);
        if (client_socket < 0)
        {
            std::cerr << "Error accepting connection.\n";
            continue;
        }
        std::thread t(handle_client, client_socket);
        t.detach();
    }

    close(server_socket);
    return 0;
}
