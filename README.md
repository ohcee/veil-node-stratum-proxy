# VEIL node stratum proxy

Solo mine [VEIL](https://veil-project.com/) straight to your own full node, with
the mining software of your choice and no pool in the middle.

The proxy speaks stratum to your miner and JSON-RPC to your node. It serves all
three of Veil's proof of work algorithms:

| algorithm | miners | notes |
|-----------|--------|-------|
| **ProgPoW** | T-Rex, WildRig | GPU |
| **RandomX** | xmrig | CPU |
| **SHA256D** | cgminer, bfgminer, cpuminer | CPU, FPGA and USB ASIC sticks |

SHA256D support requires a node new enough to serve sha256d work over RPC
(`sharpcheader` / `sharpccoinbase` / `sharpcsb`). ProgPoW and RandomX work with
wallet v1.4.0.0 or higher.

**No dependencies.** Python 3.8+ and nothing else; `pip install` is not needed.
`coloredlogs` is used if it happens to be installed, and skipped if not.

## Setup

1. **Set up your VEIL full node.** An example `veil.conf`:

   ```
   rpcuser=veil
   rpcpassword=veil
   rpcbind=127.0.0.1
   rpcallowip=127.0.0.1
   rpcport=5556
   server=1
   listen=1
   miningaddress=<your-mining-address>
   ```

   Replace `rpcuser`, `rpcpassword` and `<your-mining-address>`.
   `<your-mining-address>` must be a basecoin address, which you can generate in
   the desktop wallet under `Settings > Advanced Options > Console >
   getnewbasecoinaddress`. Without `miningaddress` the node will not hand out
   work, because it has nowhere to pay the coinbase.

2. **Start the proxy:**

   ```bash
   python3 veilproxy.py -p 5555 -n http://veil:veil@127.0.0.1:5556 -j
   ```

   Useful options:

   ```
   -a, --address        listen address (default 0.0.0.0)
   --algos              which algorithms to serve (default all three)
   --subscribe-algo     what a bare mining.subscribe means, progpow or sha256d
   --share-diff         sha256d share difficulty reported to miners
   -j, --jobs           log every new job
   -v, --verbose        debug logging
   --selftest           run internal consistency checks and exit
   ```

   The proxy only polls the node for algorithms that somebody is actually
   mining, so leaving all three enabled costs nothing.

3. **Start your miner.** Username and password can be anything.

   **T-Rex** (ProgPoW, 0.26.6+):
   ```bash
   ./t-rex --validate-shares -a progpow-veil --coin veil -o stratum+tcp://127.0.0.1:5555 -u x -p x
   ```

   **WildRig** (ProgPoW, 0.32.1+):
   ```bash
   ./wildrig --print-full -a progpow-veil -o 127.0.0.1:5555 -u x -p x
   ```

   **xmrig** (RandomX):
   ```bash
   ./xmrig -o 127.0.0.1:5555 -u x -p x
   ```

   **SHA256D with cpuminer-opt-veil** (CPU, the tested path). This miner
   speaks a Veil specific dialect, so run the proxy with
   `--sha256d-wire cpuminer`:
   ```bash
   python3 veilproxy.py -p 5557 -n http://veil:veil@127.0.0.1:5556 \
       --algos sha256d --subscribe-algo sha256d --sha256d-wire cpuminer
   cpuminer -a sha256dv -o stratum+tcp://127.0.0.1:5557 -u x -p x
   ```

   **SHA256D with a standard stratum miner** (cgminer / bfgminer, e.g. a USB
   ASIC stick). This uses the default `--sha256d-wire stratum`:
   ```bash
   python3 veilproxy.py -p 5557 -n http://veil:veil@127.0.0.1:5556 --algos sha256d --subscribe-algo sha256d
   cgminer -o stratum+tcp://127.0.0.1:5557 -u x -p x
   ```
   The two SHA256D wire formats differ; pick the one your miner speaks.
   cpuminer-opt-veil needs `cpuminer`; ASIC/cgminer style miners need
   `stratum`.

## Mining SHA256D on Veil

Veil's sha256d header is Bitcoin shaped but not Bitcoin. The 80 bytes that get
double SHA256'd are:

```
nVersion(4) || dataHash(32) || hashMerkleRoot(32) || nTime(4) || nNonce64(8)
```

where `dataHash = sha256d(hashPrevBlock || hashWitnessMerkleRoot ||
hashAccumulators || nBits)`.

The SHA256 hashing itself is completely standard, so ASIC silicon works
unmodified. Two Veil specifics shape how the proxy uses stratum:

- **No extranonce2 rolling.** `dataHash` commits the witness merkle root, which
  in Veil commits the coinbase, so changing the coinbase invalidates the work.
  The proxy advertises `extranonce2_size = 0` and issues fresh jobs instead.
- **A 64 bit nonce.** The last 8 bytes cover both the slot where Bitcoin keeps
  `nBits` and the slot where it keeps the nonce. Stratum only lets a miner roll
  32 bits, so the proxy varies the low half per job and ships it in the `nbits`
  field, which firmware treats as opaque. The real `nBits` cannot be forged
  because it is committed inside `dataHash`.

**What this means for hashrate.** Each job is worth `2^32` hashes multiplied by
whatever ntime range your miner rolls. That is comfortable for USB sticks and
small FPGAs: a 400 GH/s stick rolling ntime over a minute needs only a couple of
jobs per second. It does not scale to large modern ASICs, which would need
thousands of jobs per second. Veil's sha256d difficulty is low, so this is
rarely the binding constraint.

**Version rolling is refused.** Veil keeps its algorithm selector in `nVersion`,
so the proxy answers `mining.configure` with `version-rolling: false`.

## Troubleshooting

**"No sharpcheader in the template"** — `miningaddress` is not set in
`veil.conf`, or your node predates sha256d RPC support.

**"This node does not return sharpccoinbase"** — your node is too old to serve
standard stratum for sha256d. Update it.

**"Node reports mining_disabled"** — Veil allows at most a few consecutive PoW
blocks before a PoS block is required. The proxy keeps serving work and says so;
it clears on its own.

**Shares accepted but no blocks** — that is normal. The proxy validates every
share locally and only forwards to the node those that actually clear the block
target.

## Donations

Donations are on a voluntary basis and of course always much appreciated! Thanks!

**VEIL**: `sv1qqpjsrc60t60jhaywj5krmwla52ska70twc7wun6qnee65guxhvtxegpqwhuxypra4jn3pq86s24ryltcw6g2ss4573hyqac9u4g23m9mvxpyqqqwny49k`
