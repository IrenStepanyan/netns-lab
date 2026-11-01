# netns-lab

A small networking lab that uses Linux **network namespaces** and a **veth pair**
to simulate two isolated machines on one computer, then sends data between them
over a plain TCP socket, written in C.

This is the first stage of a larger project. The plan is to grow this into a
**4-node pipeline**:

```
sender  --->  encrypt  --->  decrypt  --->  receiver
```

Each stage will live in its own network namespace, connected by veth pairs,
so the setup mirrors real network hops rather than just function calls in one
process.

## Current stage: sender <-> receiver (no encryption)

```
ns_sender (10.0.0.1) <---veth pair---> ns_receiver (10.0.0.2)
```

## Requirements

- Linux with `iproute2` (`ip` command) - installed by default on most distros
- `gcc` (or any C compiler)
- `sudo` privileges (creating namespaces and interfaces requires root)

## Project structure

```
netns-lab/
├── setup_netns.sh     # creates the namespaces + veth pair, assigns IPs
├── cleanup_netns.sh   # tears everything down
├── sender.c           # runs inside ns_sender, connects and sends a message
├── receiver.c         # runs inside ns_receiver, listens and prints the message
└── README.md
```

## How to run

1. **Create the virtual network:**

   ```bash
   chmod +x setup_netns.sh cleanup_netns.sh
   sudo ./setup_netns.sh
   ```

   This creates `ns_sender` (10.0.0.1/24) and `ns_receiver` (10.0.0.2/24),
   links them with a veth pair, brings the interfaces up, and pings between
   them to confirm connectivity.

2. **Compile both programs:**

   ```bash
   gcc -Wall -o receiver receiver.c
   gcc -Wall -o sender sender.c
   ```

3. **Start the receiver** (in one terminal):

   ```bash
   sudo ip netns exec ns_receiver ./receiver
   ```

   It will print `Listening on 10.0.0.2:5000 ...` and wait.

4. **Run the sender** (in a second terminal):

   ```bash
   sudo ip netns exec ns_sender ./sender
   ```

   Expected output:

   ```
   [sender] Connected to 10.0.0.2:5000
   [sender] Sent: Hello from sender namespace!
   ```

   And on the receiver side:

   ```
   [receiver] Connection established from 10.0.0.1:<port>
   [receiver] Received: Hello from sender namespace!
   ```

5. **Clean up** when done:

   ```bash
   sudo ./cleanup_netns.sh
   ```

## How it works

- **Network namespace** - an isolated copy of the Linux network stack (its
  own interfaces, IP addresses, routing table). Processes inside a namespace
  can only see the network devices that belong to it.
- **veth pair** - two virtual Ethernet interfaces linked like two ends of a
  cable; whatever goes in one comes out the other. Putting one end in each
  namespace creates a private point-to-point link between them.
- **Sockets (C, POSIX API)** - `sender.c` and `receiver.c` use the standard
  BSD socket API (`<sys/socket.h>`, `<arpa/inet.h>`): the receiver `bind()`s
  to an address, `listen()`s, and `accept()`s a connection; the sender
  `connect()`s to the receiver's address and `send()`s bytes over the link.

## Roadmap

- [ ] Add `encrypt` and `decrypt` namespaces between sender and receiver
- [ ] Chain all four namespaces with veth pairs (or a bridge) so traffic
      flows sender -> encrypt -> decrypt -> receiver
- [ ] Swap the placeholder "no encryption" step for a real cipher
      (e.g. AES) once the pipeline topology is working
- [ ] Optional: add a script that automates the full multi-namespace setup

## License

MIT (or your choice)
