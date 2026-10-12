# Telnet-Client

This project was created to demonstrate basic socket client functionality on Linux. It provides a simple, non-secure Telnet client implemented in C using POSIX sockets, in a single source file without external libraries.

## Features

- IPv4, IPv6 and host names, connection timeout
- One event loop (`poll`) for keyboard and server, so nothing blocks: server data is displayed at once, and a closed connection is noticed immediately
- Telnet parser as a state machine: option negotiation, subnegotiation, escaped `0xFF` bytes, correct line endings
- Supported options: `ECHO`, `SUPPRESS-GO-AHEAD`, `TERMINAL-TYPE`, `WINDOW-SIZE` (also sent after the terminal is resized); every other option is refused
- Terminal mode follows the server:
  - line mode with local echo by default
  - line mode without echo when the server takes over echo (password prompts)
  - character mode when the server takes over echo and suppresses go-ahead (remote shell, full-screen programs)
- Terminal settings are restored on every exit, including `Ctrl+C` and `kill`
- Works with pipes and files as input and output

## Compilation

Compile the project with GCC (or any C99 compiler):

```sh
gcc -std=c99 -Wall -o telnet telnet.c
```

## Usage

```sh
./telnet [-d] [-t seconds] [host] [port]
```

| Argument     | Default     | Description                                 |
|--------------|-------------|---------------------------------------------|
| `-d`         | off         | Show option negotiation with the server     |
| `-t seconds` | `10`        | Connection timeout, 1 - 600                 |
| `host`       | `127.0.0.1` | Server address (IPv4 or IPv6) or host name  |
| `port`       | `23`        | Port number (1 - 65535) or service name     |

Example:

```sh
./telnet -d 192.168.1.10 23
```

Press `Ctrl+]` to close the connection. In line mode `Ctrl+C` closes it as well, and `Ctrl+D` tells the server that there is no more input. In character mode these keys are sent to the server, so only `Ctrl+]` ends the session.

Input can be piped. The client then sends everything, closes its sending side and displays the answer until the server disconnects:

```sh
printf 'HEAD / HTTP/1.0\n\n' | ./telnet example.com 80
```

Server data goes to standard output, client messages go to standard error.

## Adding a telnet option

Options are described by `optionTable` in `telnet.c`. To support a new one, add its code to `telnet_option_code` and one row to the table:

```c
// code         name            local  remote on_change  on_subnegotiation
{ OPTION_TTYPE, "TERMINAL-TYPE", true,  false, NULL,      ttype_subnegotiation },
```

- `local` / `remote` - whether the client agrees to enable the option on its own side / on the server side
- `on_change` - called after the option is switched on or off
- `on_subnegotiation` - called with the content of `IAC SB <option> ... IAC SE`

## Security

- Telnet is not encrypted - everything, including passwords, is sent as plain text. Use it only in trusted networks.
- Data from the server is treated as untrusted: all buffers have a fixed size, oversized or broken subnegotiations are dropped, and a server which floods the client with requests is slowed down instead of filling the memory.
- The only local information given to the server is the terminal size and the `TERM` variable, both only on request. Environment variables are never sent.
- Text from the server is displayed without filtering, so it can contain terminal escape sequences, like in every telnet client.

## Limitations

- The client never starts a negotiation, it only answers the server.
- No interactive command prompt - the escape key closes the connection.
- `LINEMODE`, `BINARY`, `NEW-ENVIRON` and encryption/authentication options are not supported.

## License

This project is licensed under the GNU General Public License v2.0 - see the [LICENSE](LICENSE) file.
