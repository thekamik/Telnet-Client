/*
 * Simple, non-secure Telnet client for Linux.
 * Copyright (C) 2024 Kamil Kuczera
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#define _GNU_SOURCE     // ppoll, SOCK_NONBLOCK

#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>

#define BUFFERSIZE 1024         // one read from server
#define INPUTSIZE 512           // one read from user
#define OUTBUFFERSIZE 4096      // data waiting to be sent to server
#define SUBBUFFERSIZE 64        // longest accepted subnegotiation
#define MAXREPLY 64             // longest reply a single received byte can cause
#define MAXTERMNAME 40          // longest terminal name sent to server
#define ESCAPECHAR 0x1d         // Ctrl+], closes the connection

// ---------------------------------------------------------------------------
// Telnet protocol (RFC 854)
// ---------------------------------------------------------------------------

enum telnet_command {
    TELNET_SE   = 240,  // end of subnegotiation
    TELNET_NOP  = 241,
    TELNET_DM   = 242,  // data mark
    TELNET_BRK  = 243,
    TELNET_IP   = 244,  // interrupt process
    TELNET_AO   = 245,  // abort output
    TELNET_AYT  = 246,  // are you there
    TELNET_EC   = 247,  // erase character
    TELNET_EL   = 248,  // erase line
    TELNET_GA   = 249,  // go ahead
    TELNET_SB   = 250,  // start of subnegotiation
    TELNET_WILL = 251,
    TELNET_WONT = 252,
    TELNET_DO   = 253,
    TELNET_DONT = 254,
    TELNET_IAC  = 255   // "Interpret As Command"
};

enum telnet_option_code {
    OPTION_ECHO  = 1,   // RFC 857
    OPTION_SGA   = 3,   // RFC 858, suppress go ahead
    OPTION_TTYPE = 24,  // RFC 1091, terminal type
    OPTION_NAWS  = 31   // RFC 1073, window size
};

enum parser_state {
    STATE_DATA,         // normal data
    STATE_IAC,          // IAC received, waiting for command
    STATE_NEGOTIATION,  // WILL/WONT/DO/DONT received, waiting for option code
    STATE_SUB,          // inside subnegotiation
    STATE_SUB_IAC       // IAC received inside subnegotiation
};

struct telnet_session {
    int socket;
    bool debug;

    // parser
    enum parser_state state;
    unsigned char negotiationCommand;
    unsigned char subBuffer[SUBBUFFERSIZE];
    size_t subLength;
    bool subOverflow;

    // state of options, indexed by option code
    bool localEnabled[256];     // option active on our side (we sent WILL)
    bool remoteEnabled[256];    // option active on server side (we sent DO)

    // bytes received from server, not parsed yet
    unsigned char inBuffer[BUFFERSIZE];
    size_t inLength;
    size_t inPosition;

    // decoded server data waiting to be displayed
    unsigned char displayBuffer[BUFFERSIZE];
    size_t displayLength;

    // data waiting to be sent to server
    unsigned char outBuffer[OUTBUFFERSIZE];
    size_t outLength;

    // user input
    bool isTerminal;        // stdin is a terminal
    bool characterMode;     // every key is sent at once, server makes echo
    bool previousInputCR;   // last user byte was CR
};

// To support a new option, add its code to telnet_option_code and one row to optionTable
struct telnet_option {
    unsigned char code;
    const char *name;
    bool allowLocal;    // we agree to enable it on our side (DO is answered with WILL)
    bool allowRemote;   // we agree that server enables it (WILL is answered with DO)
    void (*on_change)(struct telnet_session *session);      // called after option is switched on or off
    void (*on_subnegotiation)(struct telnet_session *session, const unsigned char *data, size_t length);
};

static void update_terminal_mode(struct telnet_session *session);
static void naws_changed(struct telnet_session *session);
static void ttype_subnegotiation(struct telnet_session *session, const unsigned char *data, size_t length);

// Every option which is not listed here is refused
static const struct telnet_option optionTable[] = {
    // code         name                  local  remote on_change             on_subnegotiation
    { OPTION_ECHO,  "ECHO",               false, true,  update_terminal_mode, NULL },
    { OPTION_SGA,   "SUPPRESS-GO-AHEAD",  true,  true,  update_terminal_mode, NULL },
    { OPTION_TTYPE, "TERMINAL-TYPE",      true,  false, NULL,                 ttype_subnegotiation },
    { OPTION_NAWS,  "WINDOW-SIZE",        true,  false, naws_changed,         NULL },
};

static const struct telnet_option *find_option(unsigned char code) {
    for (size_t i = 0; i < sizeof(optionTable) / sizeof(optionTable[0]); i++) {
        if (optionTable[i].code == code) {
            return &optionTable[i];
        }
    }
    return NULL;
}

// ---------------------------------------------------------------------------
// Signals and terminal
// ---------------------------------------------------------------------------

static volatile sig_atomic_t quitRequested = 0;
static volatile sig_atomic_t windowChanged = 0;

static struct termios originalTerminal;
static bool terminalSaved = false;

static void handle_signal(int signalNumber) {
    if (signalNumber == SIGWINCH) {
        windowChanged = 1;
    }
    else {
        quitRequested = 1;
    }
}

static void restore_terminal(void) {
    if (terminalSaved) {
        tcsetattr(STDIN_FILENO, TCSADRAIN, &originalTerminal);
    }
}

// Line mode with local echo by default. When server makes echo: line mode without echo
// (passwords), or character mode if server also suppresses go ahead (remote shell).
static void update_terminal_mode(struct telnet_session *session) {
    if (!terminalSaved) {
        return;
    }

    struct termios terminal = originalTerminal;
    session->characterMode = false;

    if (session->remoteEnabled[OPTION_ECHO] && session->remoteEnabled[OPTION_SGA]) {
        terminal.c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON);
        terminal.c_lflag &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
        terminal.c_cc[VMIN] = 1;
        terminal.c_cc[VTIME] = 0;
        session->characterMode = true;
    }
    else if (session->remoteEnabled[OPTION_ECHO]) {
        terminal.c_lflag &= ~ECHO;
    }

    tcsetattr(STDIN_FILENO, TCSADRAIN, &terminal);
}

// ---------------------------------------------------------------------------
// Sending
// ---------------------------------------------------------------------------

static void debug_log(const struct telnet_session *session, const char *format, ...) {
    if (!session->debug) {
        return;
    }

    va_list arguments;
    va_start(arguments, format);
    vfprintf(stderr, format, arguments);
    va_end(arguments);
    fputc('\n', stderr);
}

static const char *command_name(unsigned char command) {
    switch (command) {
        case TELNET_WILL: return "WILL";
        case TELNET_WONT: return "WONT";
        case TELNET_DO:   return "DO";
        case TELNET_DONT: return "DONT";
        default:          return "?";
    }
}

static void debug_negotiation(const struct telnet_session *session, const char *direction, unsigned char command, unsigned char code) {
    const struct telnet_option *option = find_option(code);

    if (option != NULL) {
        debug_log(session, "%s %s %s", direction, command_name(command), option->name);
    }
    else {
        debug_log(session, "%s %s %d", direction, command_name(command), code);
    }
}

// Add bytes to the buffer which is sent to server
static bool queue_bytes(struct telnet_session *session, const unsigned char *data, size_t length) {
    if (length > OUTBUFFERSIZE - session->outLength) {
        return false;
    }

    memcpy(session->outBuffer + session->outLength, data, length);
    session->outLength += length;
    return true;
}

static void send_negotiation(struct telnet_session *session, unsigned char command, unsigned char code) {
    unsigned char message[3] = { TELNET_IAC, command, code };

    if (queue_bytes(session, message, sizeof(message))) {
        debug_negotiation(session, "SENT", command, code);
    }
}

static void send_window_size(struct telnet_session *session) {
    struct winsize window;
    unsigned short columns = 0;     // 0 means unknown size
    unsigned short rows = 0;

    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &window) == 0) {
        columns = window.ws_col;
        rows = window.ws_row;
    }

    unsigned char values[4] = { columns >> 8, columns & 0xff, rows >> 8, rows & 0xff };
    unsigned char message[13];
    size_t length = 0;

    message[length++] = TELNET_IAC;
    message[length++] = TELNET_SB;
    message[length++] = OPTION_NAWS;
    for (size_t i = 0; i < sizeof(values); i++) {
        message[length++] = values[i];
        if (values[i] == TELNET_IAC) {
            // value 255 has to be doubled
            message[length++] = TELNET_IAC;
        }
    }
    message[length++] = TELNET_IAC;
    message[length++] = TELNET_SE;

    if (queue_bytes(session, message, length)) {
        debug_log(session, "SENT WINDOW-SIZE %d x %d", columns, rows);
    }
}

static void naws_changed(struct telnet_session *session) {
    if (session->localEnabled[OPTION_NAWS]) {
        send_window_size(session);
    }
}

// Server asks for terminal type: IAC SB TERMINAL-TYPE SEND IAC SE
static void ttype_subnegotiation(struct telnet_session *session, const unsigned char *data, size_t length) {
    const unsigned char IS = 0;
    const unsigned char SEND = 1;

    if (!session->localEnabled[OPTION_TTYPE] || length != 1 || data[0] != SEND) {
        return;
    }

    // TERM is the only thing we tell about our environment, and only safe characters of it
    const char *name = getenv("TERM");
    char safeName[MAXTERMNAME + 1];
    size_t nameLength = 0;

    for (; name != NULL && name[nameLength] != '\0' && nameLength < MAXTERMNAME; nameLength++) {
        char c = name[nameLength];
        bool allowed = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
                       || c == '-' || c == '_' || c == '.' || c == '+';
        if (!allowed) {
            nameLength = 0;
            break;
        }
        safeName[nameLength] = c;
    }
    if (nameLength == 0) {
        strcpy(safeName, "unknown");
        nameLength = strlen(safeName);
    }
    safeName[nameLength] = '\0';

    unsigned char message[MAXTERMNAME + 6];
    size_t messageLength = 0;

    message[messageLength++] = TELNET_IAC;
    message[messageLength++] = TELNET_SB;
    message[messageLength++] = OPTION_TTYPE;
    message[messageLength++] = IS;
    memcpy(message + messageLength, safeName, nameLength);
    messageLength += nameLength;
    message[messageLength++] = TELNET_IAC;
    message[messageLength++] = TELNET_SE;

    if (queue_bytes(session, message, messageLength)) {
        debug_log(session, "SENT TERMINAL-TYPE IS %s", safeName);
    }
}

// Translate user input to telnet format and add it to the buffer which is sent to server.
// Returns false when user typed the escape character.
static bool send_user_data(struct telnet_session *session, const unsigned char *data, size_t length) {
    unsigned char message[2 * INPUTSIZE];
    size_t messageLength = 0;

    for (size_t i = 0; i < length; i++) {
        unsigned char c = data[i];
        bool afterCR = session->previousInputCR;
        session->previousInputCR = (c == '\r');

        if (session->isTerminal && c == ESCAPECHAR) {
            return false;
        }
        else if (c == TELNET_IAC) {
            // byte 255 in data has to be doubled
            message[messageLength++] = TELNET_IAC;
            message[messageLength++] = TELNET_IAC;
        }
        else if (session->characterMode) {
            message[messageLength++] = c;
            if (c == '\r') {
                // CR alone is sent as CR NUL
                message[messageLength++] = '\0';
            }
        }
        else if (c == '\r' || (c == '\n' && !afterCR)) {
            // end of line is always sent as CR LF
            message[messageLength++] = '\r';
            message[messageLength++] = '\n';
        }
        else if (c != '\n') {
            message[messageLength++] = c;
        }
    }

    queue_bytes(session, message, messageLength);
    return true;
}

// ---------------------------------------------------------------------------
// Receiving
// ---------------------------------------------------------------------------

// Answer for WILL/WONT/DO/DONT. Request for a state which is already active is not answered,
// otherwise two sides could acknowledge each other forever.
static void handle_negotiation(struct telnet_session *session, unsigned char command, unsigned char code) {
    const struct telnet_option *option = find_option(code);
    bool changed = false;

    debug_negotiation(session, "RCVD", command, code);

    switch (command) {
        case TELNET_WILL:
            if (session->remoteEnabled[code]) {
                break;
            }
            if (option != NULL && option->allowRemote) {
                session->remoteEnabled[code] = true;
                send_negotiation(session, TELNET_DO, code);
                changed = true;
            }
            else {
                send_negotiation(session, TELNET_DONT, code);
            }
            break;

        case TELNET_WONT:
            if (session->remoteEnabled[code]) {
                session->remoteEnabled[code] = false;
                send_negotiation(session, TELNET_DONT, code);
                changed = true;
            }
            break;

        case TELNET_DO:
            if (session->localEnabled[code]) {
                break;
            }
            if (option != NULL && option->allowLocal) {
                session->localEnabled[code] = true;
                send_negotiation(session, TELNET_WILL, code);
                changed = true;
            }
            else {
                send_negotiation(session, TELNET_WONT, code);
            }
            break;

        case TELNET_DONT:
            if (session->localEnabled[code]) {
                session->localEnabled[code] = false;
                send_negotiation(session, TELNET_WONT, code);
                changed = true;
            }
            break;
    }

    if (changed && option->on_change != NULL) {
        option->on_change(session);
    }
}

static void handle_subnegotiation(struct telnet_session *session) {
    if (session->subOverflow || session->subLength == 0) {
        debug_log(session, "RCVD subnegotiation ignored");
        return;
    }

    const struct telnet_option *option = find_option(session->subBuffer[0]);

    debug_log(session, "RCVD subnegotiation for option %d, %zu bytes", session->subBuffer[0], session->subLength - 1);
    if (option != NULL && option->on_subnegotiation != NULL) {
        option->on_subnegotiation(session, session->subBuffer + 1, session->subLength - 1);
    }
}

// Decode one byte received from server
static void receive_byte(struct telnet_session *session, unsigned char c) {
    switch (session->state) {
        case STATE_DATA:
            if (c == TELNET_IAC) {
                session->state = STATE_IAC;
            }
            else if (c != '\0') {
                // NUL is a no-operation, everything else is data
                session->displayBuffer[session->displayLength++] = c;
            }
            break;

        case STATE_IAC:
            session->state = STATE_DATA;
            if (c == TELNET_IAC) {
                // doubled IAC is data byte 255
                session->displayBuffer[session->displayLength++] = c;
            }
            else if (c == TELNET_WILL || c == TELNET_WONT || c == TELNET_DO || c == TELNET_DONT) {
                session->negotiationCommand = c;
                session->state = STATE_NEGOTIATION;
            }
            else if (c == TELNET_SB) {
                session->subLength = 0;
                session->subOverflow = false;
                session->state = STATE_SUB;
            }
            else {
                // NOP, GA, DM and other commands need no action on client side
                debug_log(session, "RCVD command %d", c);
            }
            break;

        case STATE_NEGOTIATION:
            session->state = STATE_DATA;
            handle_negotiation(session, session->negotiationCommand, c);
            break;

        case STATE_SUB:
            if (c == TELNET_IAC) {
                session->state = STATE_SUB_IAC;
            }
            else if (session->subLength < SUBBUFFERSIZE) {
                session->subBuffer[session->subLength++] = c;
            }
            else {
                session->subOverflow = true;
            }
            break;

        case STATE_SUB_IAC:
            if (c == TELNET_SE) {
                session->state = STATE_DATA;
                handle_subnegotiation(session);
            }
            else if (c == TELNET_IAC) {
                // doubled IAC is byte 255 of subnegotiation
                session->state = STATE_SUB;
                if (session->subLength < SUBBUFFERSIZE) {
                    session->subBuffer[session->subLength++] = c;
                }
                else {
                    session->subOverflow = true;
                }
            }
            else {
                // broken subnegotiation, drop it and treat this byte as a normal command
                session->state = STATE_IAC;
                receive_byte(session, c);
            }
            break;
    }
}

static bool write_all(int fd, const unsigned char *data, size_t length) {
    while (length > 0) {
        ssize_t written = write(fd, data, length);

        if (written >= 0) {
            data += written;
            length -= written;
        }
        else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            struct pollfd waiting = { fd, POLLOUT, 0 };
            poll(&waiting, 1, -1);
        }
        else if (errno != EINTR) {
            return false;
        }
    }
    return true;
}

// Decode received bytes and display the data. Decoding stops when there is no place for
// a reply, so server which does not read our replies cannot make us buffer them forever.
static bool process_received(struct telnet_session *session) {
    while (session->inPosition < session->inLength && OUTBUFFERSIZE - session->outLength >= MAXREPLY) {
        receive_byte(session, session->inBuffer[session->inPosition++]);
    }

    bool displayed = write_all(STDOUT_FILENO, session->displayBuffer, session->displayLength);
    session->displayLength = 0;
    return displayed;
}

// ---------------------------------------------------------------------------
// Connection
// ---------------------------------------------------------------------------

static int connect_to_server(const char *host, const char *port, int timeoutSeconds) {
    struct addrinfo hints;
    struct addrinfo *result;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;        // IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM;

    int comm_status = getaddrinfo(host, port, &hints, &result);
    if (comm_status != 0) {
        fprintf(stderr, "Cannot resolve %s port %s: %s\n", host, port, gai_strerror(comm_status));
        return -1;
    }

    // Try every returned address until one of them connects
    int mainSocket = -1;
    int lastError = 0;
    for (struct addrinfo *address = result; address != NULL; address = address->ai_next) {
        mainSocket = socket(address->ai_family, address->ai_socktype | SOCK_NONBLOCK | SOCK_CLOEXEC, address->ai_protocol);
        if (mainSocket == -1) {
            lastError = errno;
            continue;
        }

        // Socket is non-blocking, so connect returns at once and we wait for the result
        comm_status = connect(mainSocket, address->ai_addr, address->ai_addrlen);
        if (comm_status == -1 && errno == EINPROGRESS) {
            struct pollfd waiting = { mainSocket, POLLOUT, 0 };
            int ready;
            do {
                ready = poll(&waiting, 1, timeoutSeconds * 1000);
            } while (ready == -1 && errno == EINTR);

            socklen_t errorLength = sizeof(lastError);
            if (ready == 0) {
                lastError = ETIMEDOUT;
            }
            else if (ready == -1) {
                lastError = errno;
            }
            else if (getsockopt(mainSocket, SOL_SOCKET, SO_ERROR, &lastError, &errorLength) == -1) {
                lastError = errno;
            }
        }
        else {
            lastError = (comm_status == -1) ? errno : 0;
        }

        if (lastError == 0) {
            break;
        }

        close(mainSocket);
        mainSocket = -1;
    }

    freeaddrinfo(result);

    if (mainSocket == -1) {
        fprintf(stderr, "Failed to connect to %s port %s: %s\n", host, port, strerror(lastError));
        return -1;
    }

    // Keys should not wait for a full packet, and dead server should be noticed
    int enabled = 1;
    setsockopt(mainSocket, IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof(enabled));
    setsockopt(mainSocket, SOL_SOCKET, SO_KEEPALIVE, &enabled, sizeof(enabled));

    return mainSocket;
}

// Send as much of waiting data as server accepts now
static bool flush_output(struct telnet_session *session) {
    ssize_t sent = send(session->socket, session->outBuffer, session->outLength, MSG_NOSIGNAL);

    if (sent < 0) {
        return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR;
    }

    memmove(session->outBuffer, session->outBuffer + sent, session->outLength - sent);
    session->outLength -= sent;
    return true;
}

// Handle server connection until one of sides closes it. Returns false on error.
static bool run_session(struct telnet_session *session, const sigset_t *signalMask) {
    bool inputClosed = false;       // nothing more to read from user
    bool sendingClosed = false;     // sending side of the socket is shut down

    while (!quitRequested) {
        // Tell server about new window size
        if (windowChanged && OUTBUFFERSIZE - session->outLength >= MAXREPLY) {
            windowChanged = 0;
            naws_changed(session);
        }

        if (!process_received(session)) {
            perror("Cannot write to output");
            return false;
        }

        // User finished and everything was sent: tell server that there is no more data
        if (inputClosed && !sendingClosed && session->outLength == 0) {
            shutdown(session->socket, SHUT_WR);
            sendingClosed = true;
        }

        // Nothing can be sent after that, so replies for server are dropped
        if (sendingClosed) {
            session->outLength = 0;
        }

        // Read only when there is place for the result, so buffers never overflow
        bool readServer = session->inPosition == session->inLength;
        bool readUser = !inputClosed && OUTBUFFERSIZE - session->outLength >= 2 * INPUTSIZE + MAXREPLY;

        struct pollfd descriptors[2];
        descriptors[0].fd = session->socket;
        descriptors[0].events = (readServer ? POLLIN : 0) | (session->outLength > 0 ? POLLOUT : 0);
        descriptors[0].revents = 0;
        descriptors[1].fd = readUser ? STDIN_FILENO : -1;
        descriptors[1].events = POLLIN;
        descriptors[1].revents = 0;

        // Signals are delivered only here, so none of them can be missed
        if (ppoll(descriptors, 2, NULL, signalMask) == -1) {
            if (errno == EINTR) {
                continue;
            }
            perror("poll failed");
            return false;
        }

        if (session->outLength > 0 && (descriptors[0].revents & (POLLOUT | POLLERR | POLLHUP))) {
            if (!flush_output(session)) {
                perror("Cannot send to server");
                return false;
            }
        }

        if (readServer && (descriptors[0].revents & (POLLIN | POLLERR | POLLHUP))) {
            ssize_t received = recv(session->socket, session->inBuffer, BUFFERSIZE, 0);

            if (received == 0) {
                return true;
            }
            else if (received > 0) {
                session->inLength = received;
                session->inPosition = 0;
            }
            else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                perror("Cannot receive from server");
                return false;
            }
        }

        if (descriptors[1].revents & (POLLIN | POLLERR | POLLHUP | POLLNVAL)) {
            unsigned char input[INPUTSIZE];
            ssize_t inputLength = read(STDIN_FILENO, input, sizeof(input));

            if (inputLength > 0) {
                if (!send_user_data(session, input, inputLength)) {
                    return true;
                }
            }
            else if (inputLength == 0 || (errno != EAGAIN && errno != EINTR)) {
                inputClosed = true;
            }
        }
    }

    return true;
}

// ---------------------------------------------------------------------------
// Program
// ---------------------------------------------------------------------------

// Convert text to number, returns false if it is not a number in given range
static bool parse_number(const char *text, long minimum, long maximum, long *value) {
    char *end;

    errno = 0;
    *value = strtol(text, &end, 10);
    return errno == 0 && end != text && *end == '\0' && *value >= minimum && *value <= maximum;
}

static void print_usage(const char *programName) {
    fprintf(stderr, "Usage: %s [-d] [-t seconds] [host] [port]\n"
                    "  -d          show option negotiation\n"
                    "  -t seconds  connection timeout, 1 - 600 (default 10)\n"
                    "  host        server address or host name (default 127.0.0.1)\n"
                    "  port        port number or service name (default 23)\n", programName);
}

int main(int argc, char* argv[]) {
    // Arguments
    const char* host = "127.0.0.1";    // server address or host name
    const char* port = "23";           // port number or service name
    long connectTimeout = 10;          // how long client wait for connection [s]
    bool debug = false;                // show option negotiation

    int argument;
    while ((argument = getopt(argc, argv, "dht:")) != -1) {
        switch (argument) {
            case 'd':
                debug = true;
                break;
            case 't':
                if (!parse_number(optarg, 1, 600, &connectTimeout)) {
                    fprintf(stderr, "Timeout out of range. Use a number between 1 and 600\n");
                    return 1;
                }
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    if (argc - optind > 2) {
        print_usage(argv[0]);
        return 1;
    }

    // Use host provided by user
    if (optind < argc) {
        host = argv[optind];
    }

    // check port number, anything which is not a number is treated as service name
    if (optind + 1 < argc) {
        long portNumber;
        port = argv[optind + 1];
        if (strspn(port, "0123456789") == strlen(port) && !parse_number(port, 1, 65535, &portNumber)) {
            fprintf(stderr, "Port number out of range. Use a number between 1 and 65535\n");
            return 1;
        }
    }

    // Connect to a server
    static struct telnet_session session;
    session.debug = debug;
    session.state = STATE_DATA;
    session.socket = connect_to_server(host, port, (int)connectTimeout);
    if (session.socket == -1) {
        return 1;
    }
    fprintf(stderr, "Connected to %s.\n", host);

    // Remember terminal settings, they are restored on every way out
    session.isTerminal = isatty(STDIN_FILENO);
    if (session.isTerminal && tcgetattr(STDIN_FILENO, &originalTerminal) == 0) {
        terminalSaved = true;
        atexit(restore_terminal);
        fprintf(stderr, "Escape character is '^]'.\n");
    }

    // Signals only set a flag, and they are blocked everywhere except waiting in ppoll
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = handle_signal;
    sigemptyset(&action.sa_mask);
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGHUP, &action, NULL);
    sigaction(SIGWINCH, &action, NULL);
    signal(SIGPIPE, SIG_IGN);

    sigset_t blockedSignals;
    sigset_t originalSignals;
    sigemptyset(&blockedSignals);
    sigaddset(&blockedSignals, SIGINT);
    sigaddset(&blockedSignals, SIGTERM);
    sigaddset(&blockedSignals, SIGHUP);
    sigaddset(&blockedSignals, SIGWINCH);
    sigprocmask(SIG_BLOCK, &blockedSignals, &originalSignals);

    bool success = run_session(&session, &originalSignals);

    restore_terminal();

    // Close the socket
    close(session.socket);

    fprintf(stderr, "\nConnection closed.\n");
    return success ? 0 : 1;
}
