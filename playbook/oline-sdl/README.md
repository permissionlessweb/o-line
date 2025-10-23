# TERP O-Line - Run Terp Network Nodes on Akash

Make deploying Terp Network nodes onto [Akash](//github.com/akash-network/node)
easy and standardized.

## Step 1: O-line coach & center

```mermaid
graph LR
    A[snapshot-node] -->|Syncs via public snapshot & addrbook| Network[(Public Network)]
    B[seed-node] -->|Syncs via public snapshot & addrbook| Network

    A -->|Exports snapshots| Storage[(External Bucket)]
    A -.->|Persistent Peer| B

    subgraph Step1 ["Step 1: O-line Coach & Center"]
        direction LR
        A & B
    end

    classDef node fill:#b4582c,stroke:#1e88e5,px,font-size:14px;
    class A,B node
```

- 1 snapshot node + 1 seed node
- snapshot: syncs to untrusted peers via public snapshot & addrbook
- snapshot: maintains/creates snapshots for public to use
- snapshot: export snapshots to external buckets once created
- snapshot: PEX disabled
- snapshot: statesync enabled
- snapshot: set private peers as local nodes (becomes centry node)
- seed: sync to network via public snapshot & addrbook
- seed: PEX enabled
- seed: statesync enabled
- seed: swag enabled
- seed: prune everything

## Step 2: Left & Right tackles

```mermaid
graph LR
    LT[lt-node] -->|Persistent peer| S[snapshot-node
    *PEX-disabled*]
    RT[rt-node] -->|Persistent peer| S

    LT -->|Private peer| RT
    RT -->|Private peer| LT

    subgraph Step2 ["Step 2: Left & Right Tackles"]
        direction LR
        LT & RT
    end

    classDef tackler fill:#2c50b4,stroke:#e65100,font-size:14px;
    class LT,RT tackler
```

- lt: syncs to network via snapshot node
- lt: default pruning strategy
- lt: statesync enabled
- lt: PEX disabled
- lt: set private peers as local nodes (becomes centry node)
- lt: snaspshot-node is persistent peer
- rt: same configuration as lt

## Step 3: Left & Right Forwards

```mermaid
graph LR
    %% Nodes placed in visual order (left to right)
    LT[lt-node] -->|Unconditional peer| LF[lf-node]
    RT[rt-node] -->|Unconditional peer| RF[rf-node]

    LF -->|StateSync| S[snapshot-node]
    LF -->|Discovers peers| SD[seed-node]

    RF -->|StateSync| S
    RF -->|Discovers peers| SD

    %% Subgraph to group and control layout
    subgraph Step3 ["Step 3: Left & Right Forwards"]
        direction LR
        LT & RT & LF & RF
    end

    classDef forward fill:#862cb4,stroke:#43a047,font-size:14px;
    classDef tackle fill:#2c50b4,stroke:#e65100,font-size:14px;
    classDef snapshot fill:#b4582c,stroke:#1e88e5,px,font-size:14px;

    class LF,RF forward
    class LT,RT tackle
    class S,SD snapshot

```

- lf: sync to network via our seed & snapshots
- lf: statesync enabled
- lf: use public addrbook
- lf: PEX enabled
- lf: left & right tackles are private & unconditional peers
- lf: snapshot node is persistent peer
- syncs to latest height via public (untrusted) snapshots/peers
- rf: identical to left foraward
