# MOBA - Network Connection Tracker

eBPF-based TCP connection tracker with state-based monitoring.

## Overview

This project implements comprehensive TCP connection tracking using eBPF's `inet_sock_set_state` tracepoint. It monitors both client and server-side connections, tracking connection attempts, successes, failures, and latency.

## Features

- **State-based tracking**: Uses `inet_sock_set_state` tracepoint for accurate connection monitoring
- **Client and server support**: Tracks connections from both perspectives
- **Comprehensive state coverage**: Monitors all important TCP state transitions:
  - Client: CLOSE→SYN_SENT, SYN_SENT→ESTABLISHED, SYN_SENT→CLOSE
  - Server: LISTEN→SYN_RECV, SYN_RECV→ESTABLISHED, SYN_RECV→CLOSE
- **Kernel process filtering**: Automatically filters out kernel processes (PID 0, kernel threads)
- **Connection statistics**: Tracks attempts, failures, latency per connection pair
- **Traffic monitoring**: Tracks bytes sent/received via TCP/UDP sendmsg/recvmsg hooks

## Building

Prerequisites:
- clang (LLVM compiler)
- libbpf-dev
- bpftool
- Linux kernel with BTF support

Build the BPF program:
```bash
make
```

Clean build artifacts:
```bash
make clean
```

## Implementation Details

### Key Changes from Connect-Based Tracking

The previous implementation used `sys_enter_connect` and `sys_exit_connect` syscall tracepoints. This new implementation uses `inet_sock_set_state` which provides:

1. **Better coverage**: Captures both client and server connections
2. **More accurate timing**: State transitions are kernel-internal events
3. **Handles all connection types**: Including those not initiated via connect() syscall

### Kernel Process Filtering

The implementation filters out kernel processes by:
1. Checking for PID 0 (idle/swapper process)
2. Verifying that the task has an mm pointer (userspace processes have memory mappings, kernel threads don't)

### State Transitions Tracked

**Client-side**:
- `CLOSE → SYN_SENT`: Start timing, increment attempts
- `SYN_SENT → ESTABLISHED`: Calculate latency, record success
- `SYN_SENT → CLOSE`: Record failure

**Server-side**:
- `LISTEN → SYN_RECV`: Start timing, increment attempts
- `SYN_RECV → ESTABLISHED`: Calculate latency, record success
- `SYN_RECV → CLOSE`: Record failure

## Maps

- `ipv4_recv_bytes`: Tracks bytes sent/received per connection
- `conn_stats_map`: Connection statistics (attempts, failures, latency) per connection pair
- `sock_start_map`: Temporary storage for connection start timestamps (keyed by socket address)
- `sample_rate_map`: Sampling configuration

## License

GPL
