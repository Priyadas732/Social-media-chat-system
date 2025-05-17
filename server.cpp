#include <iostream>
#include <thread>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdarg.h>
#include <vector>
#include <sstream>
#include <fstream>
#include <ctime>
#include <mysql_driver.h>
#include <mysql_connection.h>
#include <cppconn/prepared_statement.h>
#include <cppconn/exception.h>

#define SERVER_PORT 5208
#define BUF_SIZE 1024
#define MAX_CLNT 256

class ChatServer {
private:
    int serverSocket;
    std::mutex mtx; 
    std::unordered_map<std::string, int> clientSockets;
    std::unordered_map<int, std::string> socketToClient;
    std::unordered_map<std::string, std::unordered_set<std::string>> groups;
    int clientCount = 0;
    sql::mysql::MySQL_Driver* driver;
    std::unique_ptr<sql::Connection> conn;
    std::unique_ptr<sql::PreparedStatement> pstmt;

public:
    ChatServer();
    ~ChatServer();
    void start();

private:
    void handleClient(int clientSocket);
    void sendMessage(const std::string& msg);
    void sendGroupMessage(const std::string& group, const std::string& sender, const std::string& content);
    void removeClient(int clientSocket);
    void logChat(const std::string& sender, const std::string& receiver, const std::string& msg);
    static int output(const char *arg, ...);
    static int error_output(const char *arg, ...);
    static void error_handling(const std::string &message);
};

ChatServer::ChatServer() {
    serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (serverSocket == -1) {
        error_handling("socket() failed!");
    }

    sockaddr_in serv_addr{};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(SERVER_PORT);

    if (bind(serverSocket, (sockaddr*)&serv_addr, sizeof(serv_addr)) == -1) {
        error_handling("bind() failed!");
    }

    if (listen(serverSocket, MAX_CLNT) == -1) {
        error_handling("listen() error!");
    }

    try {
        driver = sql::mysql::get_mysql_driver_instance();
        conn.reset(driver->connect("tcp://127.0.0.1:3306", "root", "12345"));
        conn->setSchema("chatdb");
        pstmt.reset(conn->prepareStatement("INSERT INTO chat_logs(sender, receiver, message) VALUES (?, ?, ?)"));
    } catch (sql::SQLException &e) {
        error_handling("MySQL Connection failed: " + std::string(e.what()));
    }

    output("The server is running on port %d\n", SERVER_PORT);
}

ChatServer::~ChatServer() {
    close(serverSocket);
}

void ChatServer::start() {
    while (true) {
        sockaddr_in clnt_addr{};
        socklen_t clnt_addr_size = sizeof(clnt_addr);
        int clnt_sock = accept(serverSocket, (sockaddr*)&clnt_addr, &clnt_addr_size);
        if (clnt_sock == -1) {
            error_handling("accept() failed!");
        }

        {
            std::lock_guard<std::mutex> lock(mtx);
            clientCount++;
        }

        std::thread(&ChatServer::handleClient, this, clnt_sock).detach();
        output("Connected client IP: %s\n", inet_ntoa(clnt_addr.sin_addr));
    }
} 

void ChatServer::handleClient(int clientSocket) {
    char msg[BUF_SIZE];
    int flag = 0;
    const std::string tell_name = "#new client:";

    while (recv(clientSocket, msg, sizeof(msg), 0) > 0) {
        std::string message(msg);

        if (message.substr(0, tell_name.size()) == tell_name) {
            std::string name = message.substr(tell_name.size());
            std::lock_guard<std::mutex> lock(mtx);
            if (clientSockets.find(name) == clientSockets.end()) {
                clientSockets[name] = clientSocket;
                socketToClient[clientSocket] = name;
                output("the name of socket %d: %s\n", clientSocket, name.c_str());
            } else {
                std::string error_msg = name + " exists already. Please quit and enter with another name!";
                send(clientSocket, error_msg.c_str(), error_msg.length() + 1, 0);
                clientCount--;
                flag = 1;
                break;
            }
        } else if (message.substr(0, 6) == "#group") {
            std::istringstream iss(message);
            std::string cmd, groupName, member;
            iss >> cmd >> groupName;
            std::unordered_set<std::string> members;
            while (iss >> member) {
                members.insert(member);
            }
            std::lock_guard<std::mutex> lock(mtx);
            groups[groupName] = members;
        } else if (message.substr(0, 6) == "#sendg") {
            size_t sep = message.find(":");
            if (sep == std::string::npos) continue;

            std::string groupInfo = message.substr(6, sep - 6);
            std::string content = message.substr(sep + 1);

            std::string sender;
            {
                std::lock_guard<std::mutex> lock(mtx);
                sender = socketToClient[clientSocket];
            }

            sendGroupMessage(groupInfo, sender, content);
        } else if (message.substr(0, 8) == "#sendto:") {
            size_t sep = message.find(":", 8);
            if (sep == std::string::npos) continue;

            std::string receiver = message.substr(8, sep - 8);
            std::string content = message.substr(sep + 1);

            std::string sender;
            {
                std::lock_guard<std::mutex> lock(mtx);
                sender = socketToClient[clientSocket];
            }

            std::string formatted = "[Private] " + sender + " to " + receiver + ": " + content;

            {
                std::lock_guard<std::mutex> lock(mtx);
                if (clientSockets.find(receiver) != clientSockets.end()) {
                    send(clientSockets[receiver], formatted.c_str(), formatted.length() + 1, 0);
                    send(clientSocket, formatted.c_str(), formatted.length() + 1, 0);
                    logChat(sender, receiver, content);
                } else {
                    std::string err = "User " + receiver + " not found.";
                    send(clientSocket, err.c_str(), err.length() + 1, 0);
                }
            }
        } else {
            std::string sender, receiver = "all";
            {
                std::lock_guard<std::mutex> lock(mtx);
                sender = socketToClient[clientSocket];
            }

            std::string formattedMsg = sender + ": " + message;

            logChat(sender, receiver, message);
            sendMessage(formattedMsg);
        }
    }

    if (flag == 0) {
        removeClient(clientSocket);
    }
    close(clientSocket);
}

void ChatServer::removeClient(int clientSocket) {
    std::lock_guard<std::mutex> lock(mtx);
    std::string name = socketToClient[clientSocket];
    clientSockets.erase(name);
    socketToClient.erase(clientSocket);
    clientCount--;

    std::string leave_msg = "client " + name + " leaves the chat room";
    sendMessage(leave_msg);
    output("client %s leaves the chat room\n", name.c_str());
}

void ChatServer::sendGroupMessage(const std::string& group, const std::string& sender, const std::string& content) {
    std::lock_guard<std::mutex> lock(mtx);
    if (groups.find(group) == groups.end()) return;

    std::string fullMsg = "[Group: " + group + "] " + sender + ": " + content;
    for (const auto& member : groups[group]) {
        if (clientSockets.find(member) != clientSockets.end()) {
            send(clientSockets[member], fullMsg.c_str(), fullMsg.length() + 1, 0);
            logChat(sender, member, content);
        }
    }
}

void ChatServer::sendMessage(const std::string& msg) {
    std::lock_guard<std::mutex> lock(mtx);
    for (auto& it : clientSockets) {
        send(it.second, msg.c_str(), msg.length() + 1, 0);
    }
}

void ChatServer::logChat(const std::string& sender, const std::string& receiver, const std::string& msg) {
    try {
        std::lock_guard<std::mutex> lock(mtx);
        pstmt->setString(1, sender);
        pstmt->setString(2, receiver);
        pstmt->setString(3, msg);
        pstmt->execute();
    } catch (sql::SQLException &e) {
        error_output("Failed to log message: %s\n", e.what());
    }
}

int ChatServer::output(const char *arg, ...) {
    int res;
    va_list ap;
    va_start(ap, arg);
    res = vfprintf(stdout, arg, ap);
    va_end(ap);
    return res;
}

int ChatServer::error_output(const char *arg, ...) {
    int res;
    va_list ap;
    va_start(ap, arg);
    res = vfprintf(stderr, arg, ap);
    va_end(ap);
    return res;
}

void ChatServer::error_handling(const std::string &message) {
    std::cerr << message << std::endl;
    exit(1);
}

int main() {
    ChatServer server;
    server.start();
    return 0;
}