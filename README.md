# drop-drop

`drop-drop` is a clean-room reimplementation of the Bullfrog project, designed as a GitHub Action for network observability and security. It uses Tetragon for eBPF-based event collection and `nftables` for firewalling.

## Features

*   **GitHub Action:** `drop-drop` is designed to be used as a GitHub Action, making it easy to integrate into your CI/CD workflows.
*   **Tetragon Integration:** `drop-drop` uses Tetragon to collect eBPF-based events, providing deep visibility into your system's behavior.
*   **Firewalling:** `drop-drop` can apply firewall rules using `nftables` to control network traffic.
*   **Process Correlation:** `drop-drop` correlates network packets with the processes that sent them, providing valuable context for security analysis.

## How it Works

`drop-drop` consists of two main components:

*   **The Agent:** A Go application that runs on the target system. The agent connects to the Tetragon gRPC server to receive events, and it can also receive packets from an `nfqueue`. It correlates this information to provide a complete picture of network activity.
*   **The Action:** A TypeScript GitHub Action that orchestrates the agent. The action is responsible for downloading and running the agent, as well as installing Tetragon if requested.

## Usage

To use `drop-drop` in your GitHub Actions workflow, add the following step:

```yaml
- name: Run drop-drop
  uses: your-username/drop-drop@v1
  with:
    firewall-mode: 'audit'
    agent-url: 'https://your-url/to/the/agent'
    install-tetragon: 'true'
```

### Inputs

*   `firewall-mode`: The firewall mode to apply. One of: `audit`, `block`, `block-with-dns`. Default: `audit`.
*   `tetragon-address`: The address of the Tetragon gRPC server. Default: `localhost:54321`.
*   `agent-url`: The URL to download the `drop-drop` agent from. This is a required input.
*   `install-tetragon`: Whether to install Tetragon. Default: `false`.
*   `nfqueue-num`: The `nfqueue` number to listen on. Default: `0`.

## Building

### Agent

To build the agent, you need to have Go installed. Then, run the following command:

```bash
make build
```

### Action

To build the action, you need to have Node.js and npm installed. Then, run the following commands:

```bash
cd action
npm install
npm run build
```

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.
