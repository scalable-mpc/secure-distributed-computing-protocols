# Secure Distributed Computing Protocols

This repository implements a collection of secure distributed computing protocols that serve as building blocks for larger distributed systems. The protocols are designed to provide security guarantees in adversarial environments. 
However, this code has been written as a research prototype and has not been vetted for security. 
Therefore, this repository can contain serious security vulnerabilities. 
Use at your own risk.

## Repository Structure

### Core Protocol Modules
#### **Broadcast Protocols** ([`broadcast/`](broadcast/))
- **CTRBC (Cachin-Tessaro's Reliable Broadcast Protocol)** ([`broadcast/ctrbc/`](broadcast/ctrbc/)) - Cachin-Tessaro's Reliable broadcast protocol based on the protocol in `CT05`. 

- **ECC-RBC (Error-Correcting Code Reliable Broadcast)** ([`broadcast/ecc_rbc/`](broadcast/ecc_rbc/)) - Reliable broadcast using Reed-Solomon error-correcting codes in `NDD+22`.


#### **Dissemination Protocols** ([`dissemination/`](dissemination/))
- **ASKS (Asynchronous Secret Key Sharing)/ AwVSS (Asynchronous weak Verifiable Secret Sharing)** ([`dissemination/asks/`](dissemination/asks/)) - ASKS/AwVSS protocol in the `DDL+24,BBB+24`. 

- **AVID (Asynchronous Verifiable Information Dispersal)** ([`dissemination/avid/`](dissemination/avid/)) - Verifiable information dispersal protocols based on DispersedLedger `SPA+22`. 


#### **Consensus Protocols** ([`consensus/`](consensus/))

- **ACS (Asynchronous Common Subset)** ([`consensus/acs/`](consensus/acs/)) - Implements asynchronous common subset consensus protocol in the `DDL+24`
- **Binary Byzantine Agreement** ([`consensus/binary_ba/`](consensus/binary_ba/)) - Asynchronous Binary BA in `IBY22`.
- **FIN-MVBA (Finite Multi-Valued Byzantine Agreement)** ([`consensus/fin_mvba/`](consensus/fin_mvba/)) - Asynchronous Multi-valued Byzantine agreement protocol in FIN (`SWZ23`).
- **IBFT (Istanbul Byzantine Fault Tolerance)** ([`consensus/ibft/`](consensus/ibft/)) - PBFT-style Leader-based consensus protocol only using Message Authentication Codes in `Hen20`. 
- **RA (Reliable Agreement)** ([`consensus/ra/`](consensus/ra/)) - Reliable agreement protocol in `DDL+24`

## Building and Usage

This is a Rust project using Cargo. The compatibility between dependencies has been tested for Rust version `1.83.0`. To build all components:

```bash
cargo build --release
```
Run the following sequence of steps to start a protocol. 

1. **Generate Configuration Files**: This step generates the necessary configuration files for an $n$ party distributed system. 
```
mkdir testdata/
./target/release/genconfig --base_port 15000 --client_base_port 19000 --client_run_port 19500 --NumNodes 4 --blocksize 100 --delay 100 --target testdata/ --local true
```
These instructions generate configuration files for $n=4$ parties. Party $i$ runs on port `15000+i`, listens to requests on port `19000+i`, and syncs with a global synchronizer (this part is optional) on port `19500`. Please ensure the directory has been created to run this command. 

2. **Create channels and invoke protocol**: The following snippet of code illustrates a basic composition of distributed protocols. It is the real `spawn` from [`node/src/main.rs`](node/src/main.rs).

```rust
/// Handles that must outlive the protocol they started.
///
/// Every field here is load-bearing, because each context treats the far end of
/// these channels as a shutdown signal. See "Keeping a module alive" below.
#[must_use = "dropping ProtocolHandles shuts the spawned protocol down immediately"]
pub struct ProtocolHandles {
    /// Issue requests to the module on this channel.
    pub req_send: Sender<Vec<u8>>,
    /// One exit handle per spawned context.
    pub exit_handles: Vec<oneshot::Sender<()>>,
}

pub async fn spawn(config: Node) -> Result<ProtocolHandles> {
    // req_send: used to issue message requests to the RBC module.
    // req_recv: passed as an argument; the RBC module listens on it.
    let (ctrbc_req_send_channel, ctrbc_req_recv_channel) = channel(10000);

    // out_send: passed as an argument; the RBC module sends outputs on it.
    // out_recv: polled here to receive those outputs.
    let (ctrbc_out_send_channel, mut ctrbc_out_recv_channel) = channel(10000);

    // Start Cachin-Tessaro RBC. Keep the exit handle it returns.
    let mut exit_handles = Vec::new();
    exit_handles.push(ctrbc::Context::spawn(
        config,
        ctrbc_req_recv_channel,
        ctrbc_out_send_channel,
        false,
    )?);

    tokio::spawn(async move {
        while let Some(msg) = ctrbc_out_recv_channel.recv().await {
            log::debug!("Received message from CTRBC channel {:?}", msg);
        }
    });

    ctrbc_req_send_channel.send(Vec::new()).await
        .map_err(|_| anyhow!("CTRBC stopped before the initial request was sent"))?;

    Ok(ProtocolHandles { req_send: ctrbc_req_send_channel, exit_handles })
}
```

Protocols utilize `tokio` asynchronous channels or queues to receive requests and send outputs.
Each protocol takes two `tokio` channels as input: a receiver channel from which it receives requests (`req_recv` channel), and a sender channel to which it can send outputs (`out_send` channel).
Each protocol's invocation takes these channels as arguments.
A prominent example of protocol composition is in `consensus/acs`.
This folder implements an Asynchronous Common Subset (ACS) protocol from Reliable Broadcast (CTRBC), Secret Key Sharing (ASKS), and Reliable Agreement (RA).

### Keeping a module alive

**A spawned module stops as soon as you drop the handles it was given.** This is the
single most common way to get a protocol that appears to start and then does nothing,
so it is worth stating explicitly.

Every context's run loop selects over three things, and two of them are shutdown
signals driven purely by ownership on *your* side:

| You drop | The context sees | It logs and exits with |
| --- | --- | --- |
| the `oneshot::Sender<()>` returned by `Context::spawn` | its exit receiver resolving with `RecvError` | `Consensus error: channel closed` |
| the request `Sender` | `req_recv.recv()` returning `None` | `Networking layer has closed` |

Neither is an error you can see at the call site: the code compiles, `spawn` succeeds,
and the module dies milliseconds later. So follow these rules.

**Hold every handle for as long as the protocol should run.** Bind them in a scope that
lives that long -- typically `main` -- not inside a block that ends sooner:

```rust
// WRONG: `handles` is dropped at the end of the match arm, so the protocol
// is already dead by the time we wait for a signal.
match protocol {
    "ctrbc" => { let handles = spawn(config).await?; }
    _ => return Ok(()),
}
signals.forever().next();

// RIGHT: `handles` lives until `main` returns.
let handles = match protocol {
    "ctrbc" => spawn(config).await?,
    _ => return Ok(()),
};
signals.forever().next();
handles.shutdown();
```

**Never bind handles to `_`.** `let _ = Context::spawn(..)` drops the handle
immediately; `let _handle = ..` keeps it. This is why `ProtocolHandles` is
`#[must_use]`, and why the composed protocols in `consensus/acs`, `consensus/ibft`,
and `consensus/fin_mvba` collect every sub-context handle into a `statuses` vector
and return it to their caller rather than letting it fall out of scope.

**Return handles up the stack when you compose.** A module that spawns sub-modules
owns their handles and must pass them to *its* caller, so the lifetime decision stays
with whoever knows how long the protocol should run.

**Shut down explicitly rather than by dropping.** Sending on an exit handle lets the
context break out of its loop and return `Ok(())`; dropping it makes the same thing
happen via an error path, which is noisier and harder to distinguish from a real fault.

3. **Build code and run parties**: After compiling the code, run $n=4$ parties to start the protocol. Each party waits until it establishes a tcp channel with **all** parties. 
The `scripts/test.sh` script can also be used to start all four parties locally. 


## Key Features

### Byzantine Fault Tolerance
All protocols are designed to handle Byzantine faults, where up to `t` out of `n` nodes can behave arbitrarily (where typically `n ≥ 3t + 1`).

### Asynchronous Operation
Most protocols operate in asynchronous network models, making no assumptions about message delivery times or clock synchronization.

### Modular Design
Each protocol is implemented as a separate module with well-defined interfaces, allowing them to be composed into larger systems.

### Network Abstraction
The implementation includes a robust networking layer with:
- TCP-based reliable communication
- Message acknowledgments
- Automatic connection management


## Applications

These protocols serve as building blocks for:
- Distributed ledgers and blockchains
- Secure asynchronous multi-party computation protocols
- Byzantine fault-tolerant state machine replication

## Research Context

This implementation is part of ongoing research in secure distributed computing, focusing on practical implementations of theoretically sound protocols that can handle adversarial conditions in distributed systems.

### Supporting Infrastructure

#### **Cryptographic Primitives** ([`crypto/`](crypto/))
- SHA256 Hash function, and Merkle trees based on Hardware-accelerated Hash based on AES
- Symmetric encryption (AES-based)
- Cryptographic utilities and random number generation

#### **Configuration Management** ([`config/`](config/))
- Network configuration and node setup
- Protocol parameter management

#### **Type Definitions** ([`types/`](types/))
- Common data structures and type definitions
- Replica identifiers and protocol messages

#### **Utilities** ([`util/`](util/))
- Helper functions and common utilities
- Networking abstractions

#### **Tools** ([`tools/`](tools/))
- **genconfig** - Configuration generation utility

## References
[1] Cachin, Christian, and Stefano Tessaro. "Asynchronous verifiable information dispersal." 24th IEEE Symposium on Reliable Distributed Systems (SRDS'05). IEEE, 2005.

[2] Alhaddad, Nicolas, Sourav Das, Sisi Duan, Ling Ren, Mayank Varia, Zhuolun Xiang, and Haibin Zhang. "Balanced byzantine reliable broadcast with near-optimal communication and improved computation." In Proceedings of the 2022 ACM Symposium on Principles of Distributed Computing, pp. 399-417. 2022.

[3] Das, Sourav, Sisi Duan, Shengqi Liu, Atsuki Momose, Ling Ren, and Victor Shoup. "Asynchronous consensus without trusted setup or public-key cryptography." In Proceedings of the 2024 on ACM SIGSAC Conference on Computer and Communications Security, pp. 3242-3256. 2024.

[4] Bandarupalli, Akhil, Adithya Bhat, Saurabh Bagchi, Aniket Kate, and Michael K. Reiter. "Random beacons in monte carlo: Efficient asynchronous random beacon without threshold cryptography." In Proceedings of the 2024 on ACM SIGSAC Conference on Computer and Communications Security, pp. 2621-2635. 2024.

[5] Yang, Lei, Seo Jin Park, Mohammad Alizadeh, Sreeram Kannan, and David Tse. "{DispersedLedger}:{High-Throughput} byzantine consensus on variable bandwidth networks." In 19th USENIX Symposium on Networked Systems Design and Implementation (NSDI 22), pp. 493-512. 2022.

[6] Abraham, Ittai, Naama Ben-David, and Sravya Yandamuri. "Efficient and adaptively secure asynchronous binary agreement via binding crusader agreement." In Proceedings of the 2022 ACM Symposium on Principles of Distributed Computing, pp. 381-391. 2022.

[7] Duan, Sisi, Xin Wang, and Haibin Zhang. "Fin: Practical signature-free asynchronous common subset in constant time." In Proceedings of the 2023 ACM SIGSAC Conference on Computer and Communications Security, pp. 815-829. 2023.

[8] Moniz, Henrique. "The Istanbul BFT consensus algorithm." arXiv preprint arXiv:2002.03613 (2020).
