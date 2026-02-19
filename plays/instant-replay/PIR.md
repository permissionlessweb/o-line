**You cannot turn a plain S3 bucket into a full cryptographic PIR system using only S3 itself.**  

S3 (or any object store) is completely passive — it only does GET/PUT by key. SimplePIR (and its sibling DoublePIR) from the 2023 USENIX Security paper “One Server for the Price of Two” requires active linear-time server computation per query (a fast matrix-vector multiply over the whole database). That computation is what hides the index.

However, you **can very practically turn your existing public-read S3 bucket into a SimplePIR-style private retrieval backend** with a tiny extra compute layer. This is exactly what people do in production-like deployments (e.g. private CT log auditing, private media libraries, private file sharing, etc.).

### Quick Summary of SimplePIR / DoublePIR (the paper you asked for)

| Scheme     | Hint size (one-time download) | Per-query comms | Server throughput | Best for |
|------------|-------------------------------|-----------------|-------------------|----------|
| **SimplePIR** | ~121 MB for 1 GB DB (scales as ~4√N KB) | ~484 KB round-trip | **10 GB/s/core** (81 % of memory bandwidth) | Maximum speed |
| **DoublePIR** (recommended) | **16 MB fixed** (almost independent of DB size) | ~690 KB round-trip | 7.4 GB/s/core | Real-world use |

Both are LWE-based (128-bit security with tiny parameters), single-server, static database, extremely simple (~1,400 lines of Go in the reference impl).

The flow:

1. **Offline (once)**: Client downloads the public hint (16–121 MB).
2. **Query**: Client sends a tiny encrypted query vector → server does one fast linear scan of the entire DB → returns answer vector.
3. Client locally recovers exactly the record it wanted (server learns nothing about the index).

### Recommended Architecture: “S3 + PIR Server” (fits perfectly with your Filebrowser + IPFS setup)

```
Clients
   ↓ (HTTPS)
PIR Server (tiny Go/Rust Docker container, stateless, auto-scale)
   ↔ S3 (your existing bucket)
      ├── raw files / objects (public reads, writes gated by keys — as you already have)
      ├── preprocessed PIR matrix DB (private to PIR server or public)
      └── public Hint file(s)
```

**Privacy achieved**

- The PIR server (and therefore AWS if you run it on EC2/Lambda/Fargate) learns **nothing** about which file/object the client wants.
- If you store the **full file content** as the PIR record → client gets the bytes privately. AWS only sees constant-size query traffic.
- If you store only metadata / S3 key / IPFS CID as the record → client does a second public S3 GET (or IPFS gateway GET). AWS then sees the final GET, but you already had public reads anyway.

### Step-by-Step How to Build It (2026-ready)

1. **Choose DoublePIR** (smaller hint, still blazing fast).

2. **Preprocessing job** (run on schedule or on bucket changes)
   - AWS Lambda or tiny EC2 spot instance.
   - List all objects (or only the ones you want private).
   - Decide record format:
     - Option A (true PIR): each file = one record (supports long records natively).
     - Option B (pointer): each record = {S3-key, size, IPFS-CID}.
   - Pack everything into the matrix format the Go code expects.
   - Run `simplepir preprocess` (or the DoublePIR variant) from the official repo.
   - Upload the new matrix DB + Hint to S3 (under `/pir/` prefix, e.g. versioned by timestamp).

3. **PIR Server** (add this as a new service in your existing docker-compose)
   - Use the official reference: <https://github.com/ahenzinger/simplepir> (Go, <2k LOC).
   - Or the Rust port: <https://crates.io/crates/simplepir>
   - On container start:
     - Download latest matrix + hint from S3 (or mmap from EBS volume for speed).
     - Expose two endpoints:
       - `GET /hint` → returns the 16 MB hint (CDN-cacheable, public).
       - `POST /query` → takes JSON { "query": base64(query_vector) } → returns answer vector.
   - Super lightweight: 1–2 vCPU, 2–4 GB RAM + enough RAM to hold the entire DB (or stream from S3 with minor slowdown).

4. **Client library** (you write once, 100 lines)
   - Download hint once.
   - For any index: `query, state = client.Query(index)`
   - Send to your `/query` endpoint.
   - `record = client.Recover(state, answer)`
   - If record contains the full file → done.
   - If record contains key/CID → do normal public S3 or IPFS GET.

5. **Integration with your existing Filebrowser + IPFS Docker image**
   - Add the PIR server as a third service in the same compose file (same network, same S3 mount via s3fs if you want).
   - In Filebrowser, add a custom command “Privately Download via PIR” that calls your PIR endpoint instead of direct S3 link.
   - For IPFS pinning: after recovering the CID privately, pin it via your lightweight IPFS gateway.

### Update Handling

- SimplePIR/DoublePIR are static-DB schemes.
- On any write → trigger re-preprocess (can be incremental for small changes in newer variants, or just full re-preprocess for <100 GB buckets — takes minutes on a decent machine).
- Or switch to a newer scheme like **Piano** (2024) or **YPIR** that supports faster updates/hintless variants if your bucket changes a lot.

### Cost & Performance (realistic)

- Hint download: 16 MB once per client (or cache forever).
- Per private download: ~700 KB extra traffic, <100 ms latency on a cheap server.
- Server cost: one t4g.medium or c7g.large can handle thousands of queries/sec.
- Storage overhead: ~1–2× the raw size (because of the matrix + hint).

### Ready-to-use starter

I can generate the full thing for you right now:

- Dockerfile for the PIR server (based on the official Go code)
- Preprocessing Lambda script (Python + boto3 + Go binary)
- Updated docker-compose.yml with PIR service
- Client example in JS/Python
- Exact S3 bucket policy + IAM for the preprocessing job

Just say the word (and whether you want full-file records or pointer records, and target language for the client).

This gives you exactly “S3 bucket as a PIR-style private information retrieval service” while keeping your existing public-read + key-gated-write setup 100 % intact. It’s the cleanest, fastest, and most practical way based directly on the SimplePIR paper.

## QUESTION: READ ACCESS PATTERNS

Yes, **you do still expose read access patterns to the raw S3 bucket** in the "pointer" variant (Option B), and potentially even in the "full-file" variant (Option A) depending on how you implement it. This is a very important caveat that wasn't fully emphasized in the original architecture description.

Let's break it down clearly by the two main options you have:

### 1. Pointer records (most common / lightweight variant)

- Each PIR "record" contains only `{S3 key, size, IPFS CID, ...}` (not the actual file bytes).
- The PIR server returns this pointer privately → the client learns the key/CID without the server knowing which index was queried.
- Then the client does a **separate public S3 GET** (or IPFS GET) using that key/CID.

**Result → access pattern leakage:**

- AWS sees every real `GetObject` request to the raw bucket.
- The S3 access logs (and CloudTrail, metrics, request patterns) reveal exactly **which files are being downloaded and when**.
- The PIR layer only hides **which logical index** the client chose (i.e. hides the query from the PIR server itself).
- But it **does not hide the final object access** from S3/AWS.

This is fine if your threat model is:

- "The PIR server (or whoever runs it) shouldn't learn which file I'm interested in"
- Or "I want to prevent metadata correlation attacks at the PIR layer"

But it **does not** give you private retrieval from the perspective of AWS / S3 logging / bucket-level analytics.

### 2. Full-file records (true end-to-end PIR for content)

- Each PIR record = the complete file bytes (padded if needed).
- The PIR server scans the entire matrix (containing all file contents) → returns the answer vector.
- Client locally reconstructs the exact bytes of the chosen file.

**Result → no direct access pattern leakage to raw objects:**

- Clients **never** issue a `GetObject` on the individual raw files in the public bucket.
- The only S3 reads the PIR server does are:
  - Loading the preprocessed matrix DB (bulk, sequential or mmap-style reads — looks like one giant scan, not individual file accesses).
  - Possibly loading the public hint file(s).
- From AWS's perspective, the access pattern is **constant / uniform**: just heavy sequential reads on the `/pir/matrix/*` objects whenever queries arrive (or prefetching/caching them).
- Individual client-chosen files are **not visible** in S3 request logs — AWS only sees traffic to the PIR server (small query + answer blobs) and the PIR server's bulk matrix reads.

**This is the version that actually achieves private retrieval wrt. the storage provider (AWS).**  
The price: 1.5–2× storage overhead (matrix encoding + some padding), higher preprocessing cost/time, and the PIR server needs fast access to the full matrix in memory or via very fast streaming.

### Quick comparison (2026 perspective)

| Variant              | Hides index from PIR server? | Hides which file from AWS/S3 logs? | Storage overhead | Server RAM needs          | Use-case fit                              |
|----------------------|-------------------------------|-------------------------------------|------------------|---------------------------|-------------------------------------------|
| Pointer (Option B)   | Yes                           | **No**                              | ~1×              | Low (can stream matrix)   | Metadata hiding, public-read acceptable   |
| Full-file (Option A) | Yes                           | **Yes**                             | ~1.5–2×          | High (hold matrix or fast NVMe/S3 streaming) | Strongest privacy (e.g. private media/CT logs) |

### Practical recommendations in your setup

- If your main concern is **AWS learning per-file access patterns** (e.g. private media library, audit logs, personal files), go full-file records. Make the raw files private to the PIR server only (no public-read on the bucket, or use a separate private bucket just for the matrix). Clients talk only to the PIR server → AWS sees no per-file GETs.
- If you're okay with AWS seeing accesses (your bucket is already public-read anyway, and the goal is just hiding the query logic from an untrusted PIR server or intermediate proxies), stick with pointers — it's simpler, cheaper, and integrates cleanly with Filebrowser/IPFS.
- Hybrid idea: Use full-file PIR only for the most sensitive subset of objects, pointers for the rest.

The architecture you described is still excellent and production-practical — just make sure the privacy boundary matches your actual threat model. The SimplePIR/DoublePIR papers and impls are explicitly about **computational privacy** (server doesn't learn index), not about hiding access patterns from the underlying storage engine when doing a second fetch.

If you want to go full private (no per-file S3 GETs), say the word and I can adjust the starter code suggestions toward the full-file approach (e.g. how to chunk large files into records, padding strategy, etc.).
