#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>

#define BUFFERSIZE 200

int decode_message(SOCKET mainSocket, char messageBuffer[BUFFERSIZE], char returnBuffer[BUFFERSIZE], int messageLength) {
    // Telnet protocol characters 
    char IAC  = '\xff';   // "Interpret As Command"
    char DONT = '\xfe';
    char DO   = '\xfd';
    char WONT = '\xfc';
    char WILL = '\xfb';
    char theNULL = '\x00';
    char ECHO = '\x01';
    
    // special buffer to hold telnet commands received from server
    char commandBuffer[3];
    int commandBufferLocation = 0;

    // save location in return buffer
    int returnLocation = 0;

    for (int i = 0; i < messageLength; i++) {
        // read byte from buffer
        char c = messageBuffer[i];

        if (commandBufferLocation == 0) {
            if (c == theNULL) {
                // If null symbol, then do nothing
                continue;
            }
            else if (c != IAC) {
                // If it is no command, then add it to returnBuffer
                returnBuffer[returnLocation] = c;
                returnLocation++;
            }
            else {
                // If it is command start, then add it to buffer
                commandBuffer[commandBufferLocation] = c;
                commandBufferLocation++;
            }
        }
        else if (commandBufferLocation == 1) {
            // If there is second negotiation command
            if (c == DO || c == DONT || c == WILL || c == WONT) {
                // Add command to message buffer
                commandBuffer[commandBufferLocation] = c;
                commandBufferLocation++;
            }
            else {
                // Reset bufferLocation
                commandBufferLocation = 0;
            }
        }
        else if (commandBufferLocation == 2) {
            // response for DO and DONT
            if (commandBuffer[1] == DO || commandBuffer[1] == DONT) {
                // dont accept this command
                commandBuffer[1] = WONT;
                commandBuffer[2] = c;
                send(mainSocket, commandBuffer, 3, 0);
            }
            else if (commandBuffer[1] == WILL || commandBuffer[1] == WONT) {
                // dont accept this command
                commandBuffer[1] = DONT;
                commandBuffer[2] = c;
                send(mainSocket, commandBuffer, 3, 0);
            }

            // set bufferLocation to start
            commandBufferLocation = 0;
        }
    }

    // return message
    return returnLocation;
}

int main(int argc, char* argv[]) {
    // Arguments
    char IpAddress[15] = "172.0.0.1";    // longest possible IPv4 address have only 15 characters
    unsigned short portNumber = 23;    // port number
    int recvTimeout = 500;  // how long client wait for server response
    int echoVerification = 1;   // echo verification on client side

    // Use Ip provided by user
    if (argc > 1) {
        if (strlen(argv[1]) > 15) {
            printf("Wrong IP address format \n");
            return 0;
        }
        else {
            strcpy(IpAddress, argv[1]);
        }
    }

    // check port number
    if (argc > 2) {
        portNumber = (unsigned short)atoi(argv[2]);
        if (portNumber == 0 || portNumber > 65535) {
            printf("Port number out of range. Use a number between 0 and 65535\n");
            return 1;
        }
    }

    // check recv timeout
    if (argc > 3) {
        recvTimeout = atoi(argv[3]);
        if (recvTimeout < 0 || recvTimeout > 600000) {
            printf("Recv timeout out of range. Use a number between 0 and 600000\n");
            return 1;
        }
    }

    // check echo verification
    if (argc > 4) {
        int temp = atoi(argv[4]);
        if (temp == 1) {
            echoVerification = 1;
        }
        else if (temp == 0) {
            echoVerification = 0;
        }
        else {
            printf("Out of range, use only 0 - inactive and 1 - active\n");
            return 1;
        }
    }

    // Initialize variables
    WSADATA wsaData;
    WORD LibVersion = MAKEWORD(2, 2);
    int comm_status = WSAStartup(LibVersion, &wsaData);

    if (comm_status == 0) {
        printf("Connection OK\n");
    }
    else {
        printf("ERROR\n");
        return 0;
    }

    // Create a socket
    SOCKET mainSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (mainSocket == INVALID_SOCKET) {
        printf("Error creating socket: %ld\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    // Connect to a server
    struct sockaddr_in clientService;
    clientService.sin_family = AF_INET;
    clientService.sin_addr.s_addr = inet_addr(IpAddress);  // Replace with the server's IP address
    clientService.sin_port = htons(portNumber);  // Use the same port as the server

    // Set recv timeout
    comm_status = setsockopt(mainSocket, SOL_SOCKET, SO_RCVTIMEO, (char *)&recvTimeout, sizeof(int));
    if (comm_status == SOCKET_ERROR) {
        printf("setsockopt for SO_RCVTIMEO failed with error: %u\n", WSAGetLastError());
    } else {
        printf("Set SO_RCVTIMEO: ON\n");
    }

    // Use the connect function
    if (connect(mainSocket, (struct sockaddr *)&clientService, sizeof(clientService)) == SOCKET_ERROR) {
        printf("Failed to connect: \n");
        WSACleanup();
        return 0;
    } else {
        printf("Client connected \n");
    }

    // communication buffers
    char receiveBuffer[BUFFERSIZE];
    int receiveBufferLen = 0;
    char senderBuffer[BUFFERSIZE];
    int senderBufferLen = 0;
    int echoFlag = 0;   // 1 when message is echo

    // Handle server connection
    while (1) {
        // empty the receiveBuffer
        memset(receiveBuffer, '\0', sizeof(receiveBuffer));

        // Read server message
        receiveBufferLen = recv(mainSocket, receiveBuffer, BUFFERSIZE, 0);

        // make sure that echo flag is 0
        echoFlag = 0;

        // Make sure, there is no echo. Some servers sends echo even if it is disable, so this is to make sure that there is no echo
        if (senderBufferLen > 1 && echoVerification) {
            if (strncmp(receiveBuffer, senderBuffer, senderBufferLen - 1) == 0) {
                echoFlag = 1;
            }
        }

        // empty the senderBuffer
        memset(senderBuffer, '\0', sizeof(senderBuffer));

        // If there are some bytes in buffer, then decode message
        if (receiveBufferLen > 0) {
            // Read server message
            senderBufferLen = decode_message(mainSocket, receiveBuffer, senderBuffer, receiveBufferLen);
            
            // Display server message
            if (echoFlag == 0) {
                printf("%s", senderBuffer);
            }
        }
        else {
            // Display start writing mark
            printf(": ");

            // Read user input
            fgets(senderBuffer, BUFFERSIZE, stdin);

            // check if termination command was send by user
            if (strcmp(senderBuffer, "exit\n") == 0) {
                break;
            }

            // Send message to a server
            senderBufferLen = send(mainSocket, senderBuffer, strlen(senderBuffer), 0);

            // Handle error
            if (senderBufferLen == SOCKET_ERROR) {
                printf("Server error: \n");
                break;
            }
        }
    }

    // Shutdown the connection
    shutdown(mainSocket, SD_SEND); // Shutdown the sending side

    // Close the socket
    closesocket(mainSocket);

    // Cleanup Winsock
    WSACleanup();

    printf("END \n");
    return 0;
}
