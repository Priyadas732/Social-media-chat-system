#include <iostream>
#include <string>
#include <thread>
#include <mutex>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdarg.h>

#define BUF_SIZE 1024
#define SERVER_PORT 5208
#define SERVER_IP "127.0.0.1"

class ChatClient {
private:
    int socketFd; // Socket descriptor
    std::string name; // Client name
    std::string messageBuffer; // Message buffer

public:
    ChatClient(const std::string& clientName);
    ~ChatClient();
    void start(); // Start the chat client

private:
    void sendMessage(); // Thread function to send messages
    void receiveMessage(); // Thread function to receive messages

public:
    static int output(const char *arg, ...);
    static int error_output(const char *arg, ...);
    static void error_handling(const std::string &message);
};

ChatClient::ChatClient(const std::string& clientName) : name(clientName) {
    socketFd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socketFd == -1) {
        error_handling("socket() failed!");
    }

    sockaddr_in serv_addr{};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(SERVER_IP);
    serv_addr.sin_port = htons(SERVER_PORT);

    if (connect(socketFd, (sockaddr*)&serv_addr, sizeof(serv_addr)) == -1) {
        error_handling("connect() failed!");
    }

    std::string initMsg = "#new client:" + clientName;
    send(socketFd, initMsg.c_str(), initMsg.length() + 1, 0);
}

ChatClient::~ChatClient() {
    close(socketFd);
}

void ChatClient::start() {
    std::thread snd(&ChatClient::sendMessage, this);
    std::thread rcv(&ChatClient::receiveMessage, this);
    snd.join();
    rcv.join();
}

void ChatClient::sendMessage() {
    while (true) {
        std::getline(std::cin, messageBuffer);
        if (messageBuffer == "Quit" || messageBuffer == "quit") {
            close(socketFd);
            exit(0);
        }

        std::string formattedMsg;

        // Check if it's a private message
        if (messageBuffer.rfind("#sendto:", 0) == 0) {
            formattedMsg = messageBuffer; // Already in the format: #sendto:User:Message
        } else {
            formattedMsg = messageBuffer; // Normal public message
        }

        send(socketFd, formattedMsg.c_str(), formattedMsg.length() + 1, 0);
    }
}

void ChatClient::receiveMessage() {
    char buffer[BUF_SIZE + 100];
    while (true) {
        memset(buffer, 0, sizeof(buffer));
        int str_len = recv(socketFd, buffer, sizeof(buffer), 0);
        if (str_len <= 0) {
            std::cerr << "Disconnected from server or error occurred." << std::endl;
            exit(-1);
        }

        std::string received(buffer);
        
        // Example format expected: "Alice: Hello everyone"
        size_t delimiterPos = received.find(":");
        if (delimiterPos != std::string::npos) {
            std::string sender = received.substr(0, delimiterPos);
            std::string message = received.substr(delimiterPos + 1);
            std::cout << "\n📩 From " << sender << ": " << message << std::endl;
        } else {
            // fallback in case message doesn't follow format
            std::cout << received << std::endl;
        }
    }
}


int ChatClient::output(const char *arg, ...) {
    int res;
    va_list ap;
    va_start(ap, arg);
    res = vfprintf(stdout, arg, ap);
    va_end(ap);
    return res;
}

int ChatClient::error_output(const char *arg, ...) {
    int res;
    va_list ap;
    va_start(ap, arg);
    res = vfprintf(stderr, arg, ap);
    va_end(ap);
    return res;
}

void ChatClient::error_handling(const std::string &message) {
    std::cerr << message << std::endl;
    exit(1);
}

int main(int argc, const char** argv) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <Name>" << std::endl;
        exit(1);
    }

    ChatClient client(argv[1]);
    client.start();
    return 0;
}
