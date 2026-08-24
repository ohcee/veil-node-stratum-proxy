# VEIL node stratum proxy

Solo mine [VEIL](https://veil-project.com/) straight to your own full node, with
the mining software of your choice and no pool in the middle.

The proxy speaks stratum to your miner and JSON-RPC to your node. It serves all
three of Veil's proof of work algorithms:

| algorithm | miners | notes |
|-----------|--------|-------|
| **ProgPoW** | Veil-Miner, T-Rex, WildRig | GPU |
| **RandomX** | Veil-Miner-CPU, xmrig | CPU |
| **SHA256D** | Veil-Miner-SHA (GPU), cpuminer-opt-veil (CPU) | Veil aware miners only |

SHA256D support requires a node new enough to serve sha256d work over RPC
(`sharpcheader` / `sharpccoinbase` / `sharpcsb`). Those RPCs were merged into
veil master on 2026-08-24 ([Veil-Project/veil#1084](https://github.com/Veil-Project/veil/pull/1084)),
so build the wallet from master until the next release ships. ProgPoW and
RandomX work with wallet v1.4.0.0 or higher.

### SHA256D needs a Veil aware miner

Stock SHA256D miners (cgminer, bfgminer, unmodified cpuminer, and the USB ASIC
sticks they drive) **do not work** with Veil, and no proxy setting changes that.
They all require a rollable `extranonce2`, which is how an ordinary pool gives
each miner unique work by mutating the coinbase. Veil commits the coinbase
inside the header's `dataHash`, so the coinbase cannot be rolled; the proxy
advertises `extranonce2_size = 0` and stock miners refuse it with "Failed to
get extranonce2_size".

A working SHA256D miner must instead accept fixed work and grind the 64 bit
nonce. Today that means **cpuminer-opt-veil** with `-a sha256dv`, served by this
proxy in `--sha256d-wire cpuminer` mode. The default `--sha256d-wire stratum`
mode speaks standard stratum for any future miner written to tolerate a zero
width extranonce2, but no off the shelf miner does that yet.

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

   The default `--sha256d-wire stratum` mode speaks standard stratum for a
   future miner written to tolerate a zero width extranonce2, but stock
   cgminer / bfgminer / cpuminer will refuse it (see "SHA256D needs a Veil
   aware miner" above). Use `--sha256d-wire cpuminer` with cpuminer-opt-veil.

## Mining SHA256D on Veil

Veil's sha256d header is Bitcoin shaped but not Bitcoin. The 80 bytes that get
double SHA256'd are:

```
nVersion(4) || dataHash(32) || hashMerkleRoot(32) || nTime(4) || nNonce64(8)
```

where `dataHash = sha256d(hashPrevBlock || hashWitnessMerkleRoot ||
hashAccumulators || nBits)`.

The SHA256 hashing itself is completely standard, so ASIC silicon can compute
the hash. What makes Veil different from Bitcoin is not the hash but the work
delivery:

- **No extranonce2 rolling.** `dataHash` commits the witness merkle root, which
  in Veil commits the coinbase, so changing the coinbase invalidates the work.
  The proxy advertises `extranonce2_size = 0` and issues fresh jobs instead.
  This is why stock stratum miners, which require a rollable extranonce2, cannot
  mine Veil: the incompatibility is in the protocol, not the silicon.
- **A 64 bit nonce.** The last 8 bytes cover both the slot where Bitcoin keeps
  `nBits` and the slot where it keeps the nonce. The real `nBits` cannot be
  forged because it is committed inside `dataHash`.

**What would be needed for stock USB ASICs.** Either firmware that accepts fixed
work and grinds the 64 bit nonce without touching the coinbase, or a consensus
change that stops committing the coinbase in `dataHash` so Veil sha256d behaves
like ordinary Bitcoin sha256d. Neither exists today, so a USB stick with stock
firmware will not mine Veil.

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
