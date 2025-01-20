#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

class TCPClient {
private:
    std::string server_ip;
    int server_port;
    int sock;

public:
    TCPClient(const std::string& ip, int port) : server_ip(ip), server_port(port), sock(-1) {}

    bool connect_to_server() {
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == -1) {
            std::cerr << "Socket creation failed\n";
            return false;
        }

        sockaddr_in server_address{};
        server_address.sin_family = AF_INET;
        server_address.sin_port = htons(server_port);
        if (inet_pton(AF_INET, server_ip.c_str(), &server_address.sin_addr) <= 0) {
            std::cerr << "Invalid server address\n";
            return false;
        }

        if (connect(sock, (struct sockaddr*)&server_address, sizeof(server_address)) < 0) {
            std::cerr << "Connection to server failed\n";
            return false;
        }
        return true;
    }

    void send_id(const std::string& id) {
        if (send(sock, id.c_str(), id.size(), 0) < 0) {
            std::cerr << "Failed to send ID\n";
            return;
        }

        char buffer[1024] = {0};
        int bytes_received = recv(sock, buffer, sizeof(buffer), 0);
        if (bytes_received < 0) {
            std::cerr << "Error receiving response\n";
        } else {
            std::string response(buffer, bytes_received);
            std::cout << "Server response: " << response << std::endl;
        }
    }

    void close_connection() {
        if (sock != -1) {
            close(sock);
        }
    }
};

int main() {
    std::string id;
    std::cout << "Enter your ID: ";
    std::cin >> id;

    TCPClient client("127.0.0.1", 8888);
    if (client.connect_to_server()) {
        client.send_id(id);
        client.close_connection();
    }

    return 0;
}
