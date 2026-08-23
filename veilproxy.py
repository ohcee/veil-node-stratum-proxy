#!/usr/bin/env python3
"""Stratum proxy for solo mining VEIL against a local node.

Supports all three of Veil's proof of work algorithms:

  progpow   GPU miners speaking the ethash style stratum (T-Rex, WildRig)
  randomx   CPU miners speaking the xmrig login/job protocol
  sha256d   any sha256d miner speaking standard stratum v1, including USB
            ASIC sticks driven by cgminer/bfgminer

The node does the block assembly; this proxy only hands out work and relays
solutions back over RPC.

sha256d notes
-------------
Veil's sha256d header is Bitcoin shaped but not Bitcoin.  The 80 bytes that
get double sha256'd are

    nVersion(4) || dataHash(32) || hashMerkleRoot(32) || nTime(4) || nNonce64(8)

where dataHash = sha256d(hashPrevBlock || hashWitnessMerkleRoot ||
hashAccumulators || nBits).  Two consequences drive the design here:

  * dataHash commits the witness merkle root, which in Veil commits the
    coinbase.  Changing the coinbase invalidates the work, so extranonce2
    rolling is impossible and we advertise extranonce2_size = 0.
  * the last 8 bytes are a 64 bit nonce, occupying both the slot where
    Bitcoin keeps nBits and the slot where it keeps the nonce.  Stratum only
    lets the miner roll the high 32 bits, so the proxy varies the low 32 bits
    per job and ships them in the nbits field, which ASIC firmware treats as
    opaque.  Each job is therefore worth 2**32 hashes times whatever ntime
    range the miner rolls.
"""

import argparse
import asyncio
import base64
import json
import logging
import os
import random
import secrets
import string
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from hashlib import sha256

try:
    import coloredlogs
except ImportError:
    coloredlogs = None

VERSION = "3.0.1"

# Guard rails
MAX_LINE_BYTES = 128 * 1024        # a stratum line longer than this is hostile
RPC_TIMEOUT = 30                   # seconds, for ordinary calls
LONGPOLL_TIMEOUT = 120             # seconds, longpoll parks on the node
SUBMIT_RETRIES = 4                 # a found block is worth retrying hard
JOB_CACHE = 16                     # recent jobs still accepted on submit

log = logging.getLogger("veilproxy")


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def prune0x(s):
    return s[2:] if s.startswith("0x") else s


def swap_words(b):
    """Reverse each 4 byte word in place order, the stratum prevhash form."""
    return b"".join(b[i:i + 4][::-1] for i in range(0, len(b), 4))


def reverse_endianess(s):
    return bytearray.fromhex(s)[::-1].hex()


def is_hex(s, nbytes=None):
    if not isinstance(s, str):
        return False
    try:
        raw = bytes.fromhex(s)
    except ValueError:
        return False
    return nbytes is None or len(raw) == nbytes


def target_to_difficulty(target_hex):
    """Difficulty relative to a 0000ffff.. limit, matching the node."""
    try:
        target = int(target_hex, 16)
    except (TypeError, ValueError):
        return 0.0
    if target <= 0:
        return 0.0
    limit = 0x0000ffff * (1 << (8 * 26))
    return limit / target


def format_difficulty(target_hex):
    diff = target_to_difficulty(target_hex)
    for scale, unit in ((1e12, "T"), (1e9, "G"), (1e6, "M"), (1e3, "K")):
        if diff >= scale:
            return "{:.2f}{}".format(diff / scale, unit)
    return "{:.2f}".format(diff)


def difficulty_to_target(diff):
    limit = 0x0000ffff * (1 << (8 * 26))
    if diff <= 0:
        return limit
    return max(1, int(limit / diff))


def merkle_branch_for_coinbase(txids_le):
    """Merkle path proving position 0, given the other txids in tree order.

    txids_le are the internal byte order (little endian) hashes, i.e. what
    getblocktemplate returns reversed.
    """
    branch = []
    layer = [None] + list(txids_le)      # None is the coinbase placeholder
    while len(layer) > 1:
        if len(layer) % 2:
            layer.append(layer[-1])
        branch.append(layer[1])
        nxt = []
        for i in range(0, len(layer), 2):
            a, b = layer[i], layer[i + 1]
            if a is None:
                nxt.append(None)         # coinbase side stays unknown
            else:
                nxt.append(sha256(sha256(a + b).digest()).digest())
        layer = nxt
    return branch


def dsha256(b):
    return sha256(sha256(b).digest()).digest()


def split_rpc_url(url):
    """Pull basic auth credentials out of the url, as curl would."""
    parsed = urllib.parse.urlsplit(url if "://" in url else "http://" + url)
    creds = "{}:{}".format(urllib.parse.unquote(parsed.username or ""),
                           urllib.parse.unquote(parsed.password or ""))
    netloc = parsed.hostname or "127.0.0.1"
    if parsed.port:
        netloc += ":{}".format(parsed.port)
    clean = urllib.parse.urlunsplit((parsed.scheme or "http", netloc,
                                     parsed.path or "/", parsed.query, ""))
    return clean, base64.b64encode(creds.encode()).decode()


# --------------------------------------------------------------------------
# node RPC
# --------------------------------------------------------------------------

class NodeConnection:
    """Polls getblocktemplate for one algorithm and relays submissions."""

    algo = None
    tag = "?"

    def __init__(self, url, _unused=None):
        self.url, self.auth = split_rpc_url(url)
        self.last_job = None
        self.jobs = {}                    # job_id -> job dict
        self.job_order = []
        self.subscribers = []
        self.submitted = 0
        self.accepted = 0
        self.log = logging.getLogger(self.tag_plain)
        # Created lazily inside the running loop. Constructing an asyncio.Event
        # here would bind it to the wrong loop on Python 3.9, which raises
        # "got Future attached to a different loop" once asyncio.run() starts.
        self._wanted = None
        self._pending = set()

    def _wanted_event(self):
        if self._wanted is None:
            self._wanted = asyncio.Event()
        return self._wanted

    # -- subclass contract -------------------------------------------------

    @property
    def tag_plain(self):
        raise NotImplementedError

    def template_request(self):
        raise NotImplementedError

    def submit_request(self, *args):
        raise NotImplementedError

    def set_job_id(self, job):
        raise NotImplementedError

    def prepare_job(self, job):
        """Optional per-template derivation; may raise to reject the job."""

    # -- plumbing ----------------------------------------------------------

    def add_subscriber(self, s):
        self.subscribers.append(s)
        self._wanted_event().set()

    def remove_subscriber(self, s):
        if s in self.subscribers:
            self.subscribers.remove(s)
        if not self.subscribers:
            self._wanted_event().clear()

    def remember(self, job):
        self.jobs[job["job_id"]] = job
        self.job_order.append(job["job_id"])
        while len(self.job_order) > JOB_CACHE:
            self.jobs.pop(self.job_order.pop(0), None)

    @property
    def counters(self):
        failed = self.submitted - self.accepted
        colour = "\x1b[31m{}\x1b[0m" if failed else "{}"
        return ("(\x1b[32m{}\x1b[0m/" + colour + ")").format(self.accepted, failed)

    def _post(self, payload, timeout):
        """Blocking JSON-RPC POST, run in a worker thread."""
        body = json.dumps(payload).encode()
        req = urllib.request.Request(self.url, data=body, headers={
            "Content-Type": "application/json",
            "Authorization": "Basic " + self.auth,
        })
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            # The node reports RPC errors with HTTP 500 and a JSON error body,
            # so the body matters far more than the status code.
            return e.code, e.read().decode("utf-8", "replace")

    async def rpc(self, payload, timeout):
        """One JSON-RPC call. Returns (result, error). Never raises."""
        loop = asyncio.get_event_loop()
        try:
            status, text = await loop.run_in_executor(None, self._post, payload, timeout)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            return None, {"code": -1, "message": "{}: {}".format(type(e).__name__, e)}

        if status == 401:
            return None, {"code": -1,
                          "message": "Unauthorized, check the rpc user and password"}
        try:
            data = json.loads(text)
        except ValueError:
            return None, {"code": -1,
                          "message": "HTTP {}: {}".format(status, text[:200].strip())}
        if data.get("error"):
            return None, data["error"]
        return data.get("result"), None

    async def run(self):
        """Poll for templates, but only while somebody is mining this algo."""
        backoff = 1
        while True:
            try:
                await self._wanted_event().wait()
                payload = self.template_request()
                if self.last_job and self.last_job.get("longpollid"):
                    payload["params"][0]["longpollid"] = self.last_job["longpollid"]
                    timeout = LONGPOLL_TIMEOUT
                else:
                    timeout = RPC_TIMEOUT

                result, error = await self.rpc(payload, timeout)
                if error:
                    self.log.error("getblocktemplate failed (%s): %s",
                                   error.get("code"), error.get("message"))
                    await asyncio.sleep(min(backoff, 30))
                    backoff = min(backoff * 2, 30)
                    continue
                backoff = 1
                if not result:
                    continue

                if self.last_job and result.get("longpollid") == self.last_job.get("longpollid"):
                    continue

                try:
                    self.set_job_id(result)
                    self.prepare_job(result)
                except Exception as e:
                    self.log.error("Unusable template: %s", e)
                    await asyncio.sleep(2)
                    continue

                fresh = not self.last_job or self.last_job["job_id"] != result["job_id"]
                self.last_job = result
                self.remember(result)

                if fresh:
                    if result.get("mining_disabled"):
                        self.log.warning(
                            "Node reports mining_disabled at height %s, a PoS block is "
                            "needed before this algo can win; still serving work",
                            result.get("height"))
                    if SHOW_JOBS:
                        self.log.info(
                            "New %s job diff \x1b[1m%s\x1b[0m height \x1b[1m%s\x1b[0m",
                            self.tag, format_difficulty(result["target"]), result.get("height"))
                    for s in list(self.subscribers):
                        try:
                            s.on_new_job(result)
                        except asyncio.CancelledError:
                            raise
                        except Exception:
                            self.log.exception("Failed pushing job to a miner")
            except asyncio.CancelledError:
                return
            except Exception:
                self.log.exception("Template loop error")
                await asyncio.sleep(1)

    async def submit(self, *args):
        """Submit a solution, retrying because a block is worth real effort."""
        self.submitted += 1
        payload = self.submit_request(*args)
        log.debug("Submitting %s", json.dumps(payload))

        last_error = {"code": 25, "message": "Unknown error"}
        for attempt in range(1, SUBMIT_RETRIES + 1):
            result, error = await self.rpc(payload, RPC_TIMEOUT)
            if error is None:
                if result is True:
                    self.accepted += 1
                    self.log.info("\x1b[32mBlock accepted\x1b[0m %s", self.counters)
                    return True
                # A string result is the node's rejection reason.
                self.log.error("Block rejected by node: %s", result)
                return {"code": 26, "message": str(result)}
            last_error = error
            self.log.error("Block submission failed (attempt %d/%d) (%s): %s",
                           attempt, SUBMIT_RETRIES, error.get("code"), error.get("message"))
            # Only worth retrying transport level failures.
            if error.get("code") not in (-1, None):
                break
            await asyncio.sleep(0.5 * attempt)

        self.log.critical("GIVING UP on a solved block, solution was: %s",
                          json.dumps(payload["params"]))
        return last_error

    def track(self, coro):
        """Keep a strong reference so a submission cannot be collected."""
        task = asyncio.ensure_future(coro)
        self._pending.add(task)
        task.add_done_callback(self._pending.discard)
        return task


class ProgPowNode(NodeConnection):
    algo = "progpow"

    @property
    def tag_plain(self):
        return "progpow"

    @property
    def tag(self):
        return "\x1b[0;36mprogpow\x1b[0m"

    def template_request(self):
        return {"jsonrpc": "1.0", "method": "getblocktemplate",
                "params": [{"algo": "progpow"}]}

    def submit_request(self, header_hash, mix_hash, nonce):
        return {"jsonrpc": "1.0", "method": "pprpcsb",
                "params": [header_hash, mix_hash, nonce]}

    def set_job_id(self, job):
        if "pprpcheader" in job and "pprpcnextepoch" not in job:
            raise RuntimeError("Update your VEIL wallet to 1.4.0.0 or higher")
        if "pprpcheader" not in job:
            raise RuntimeError("No pprpcheader in the template. Is miningaddress set in veil.conf?")
        job["job_id"] = job["pprpcheader"]


class RandomXNode(NodeConnection):
    algo = "randomx"

    @property
    def tag_plain(self):
        return "randomx"

    @property
    def tag(self):
        return "\x1b[0;33mrandomx\x1b[0m"

    def template_request(self):
        return {"jsonrpc": "1.0", "method": "getblocktemplate",
                "params": [{"algo": "randomx"}]}

    def submit_request(self, header, rx_hash, nonce):
        return {"jsonrpc": "1.0", "method": "rxrpcsb",
                "params": [header, rx_hash, nonce]}

    def set_job_id(self, job):
        if "rxrpcheader" not in job:
            raise RuntimeError("No rxrpcheader in the template. Is miningaddress set in veil.conf?")
        job["job_id"] = sha256(job["rxrpcheader"].encode()).hexdigest()

    def prepare_job(self, job):
        # The blob is 148 bytes; the 32 bit nonce lives at byte 140, which is
        # hex offset 280..288.  Assert rather than corrupt work silently.
        blob = job["rxrpcheader"]
        if len(blob) != 296:
            raise RuntimeError("rxrpcheader is {} hex chars, expected 296".format(len(blob)))


class Sha256dNode(NodeConnection):
    algo = "sha256d"

    @property
    def tag_plain(self):
        return "sha256d"

    @property
    def tag(self):
        return "\x1b[0;35msha256d\x1b[0m"

    def template_request(self):
        return {"jsonrpc": "1.0", "method": "getblocktemplate",
                "params": [{"algo": "sha256d", "rules": ["segwit"]}]}

    def submit_request(self, header, sha_hash, nonce, ntime=None):
        params = [header, sha_hash, nonce]
        if ntime is not None:
            params.append(ntime)
        return {"jsonrpc": "1.0", "method": "sharpcsb", "params": params}

    def set_job_id(self, job):
        if "sharpcheader" not in job:
            raise RuntimeError("No sharpcheader in the template. Is miningaddress set in "
                               "veil.conf, and is the node new enough to serve sha256d work?")
        job["job_id"] = sha256(job["sharpcheader"].encode()).hexdigest()[:16]

    def prepare_job(self, job):
        blob = job["sharpcheader"]
        if len(blob) != 160:
            raise RuntimeError("sharpcheader is {} hex chars, expected 160".format(len(blob)))
        raw = bytes.fromhex(blob)
        job["_version"] = struct.unpack("<I", raw[0:4])[0]
        job["_datahash"] = raw[4:36]
        job["_merkle"] = raw[36:68]
        job["_ntime"] = struct.unpack("<I", raw[68:72])[0]
        if raw[72:80] != b"\x00" * 8:
            raise RuntimeError("sharpcheader nonce is not zeroed")

        # Standard stratum needs the coinbase so the miner can rebuild the
        # merkle root itself.  Older nodes do not provide it.
        cb = job.get("sharpccoinbase")
        job["_coinbase"] = bytes.fromhex(cb) if cb else None
        if job["_coinbase"] is not None:
            txids = [bytes.fromhex(t["txid"])[::-1] for t in job.get("transactions", [])]
            branch = merkle_branch_for_coinbase(txids)
            job["_branch"] = [h.hex() for h in branch]
            # Sanity: the branch must fold our coinbase into the template's root.
            root = dsha256(job["_coinbase"])
            for h in branch:
                root = dsha256(root + bytes.fromhex(h))
            if root != job["_merkle"]:
                raise RuntimeError("merkle branch does not reproduce the template root")
        else:
            job["_branch"] = None


# --------------------------------------------------------------------------
# stratum server
# --------------------------------------------------------------------------

class StratumSession(asyncio.Protocol):

    def connection_made(self, transport):
        self.transport = transport
        self.peer = transport.get_extra_info("peername") or ("?", 0)
        self.buf = bytearray()
        self.node = None
        self.worker = None
        self.closed = False
        # sha256d bookkeeping
        self.extranonce_lo = None
        self.share_target = None
        self.share_diff = 1.0
        self.shares = 0
        self.stale = 0
        self.first_share = None
        log.info("Miner connected from %s:%s", *self.peer)

    def connection_lost(self, exc):
        self.closed = True
        log.info("Miner from %s:%s disconnected", *self.peer)
        if self.node:
            self.node.remove_subscriber(self)

    # -- io ----------------------------------------------------------------

    def send(self, obj):
        if self.closed:
            return
        obj.setdefault("jsonrpc", "2.0")
        try:
            self.transport.write(json.dumps(obj).encode() + b"\n")
        except Exception:
            log.exception("Failed writing to miner %s:%s", *self.peer)

    def error(self, id_, code, message):
        self.send({"id": id_, "result": None, "error": {"code": code, "message": message}})

    def data_received(self, data):
        """Stratum is newline delimited; buffer and split rather than assuming
        one whole message per packet, which silently loses shares."""
        self.buf.extend(data)
        if len(self.buf) > MAX_LINE_BYTES:
            log.warning("Miner %s:%s sent an oversized line, dropping it", *self.peer)
            self.transport.close()
            return
        while True:
            nl = self.buf.find(b"\n")
            if nl < 0:
                break
            line = bytes(self.buf[:nl])
            del self.buf[:nl + 1]
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line.decode("utf-8", "replace"))
            except ValueError as e:
                log.warning("Bad JSON from %s:%s (%s): %.120s", self.peer[0], self.peer[1], e, line)
                continue
            if not isinstance(msg, dict):
                log.warning("Non object message from %s:%s", *self.peer)
                continue
            try:
                self.handle(msg)
            except asyncio.CancelledError:
                raise
            except Exception:
                # Never let one bad message kill the connection.
                log.exception("Error handling message from %s:%s", *self.peer)
                self.error(msg.get("id"), 20, "Internal proxy error")

    # -- dispatch ----------------------------------------------------------

    def handle(self, msg):
        method = msg.get("method")
        id_ = msg.get("id")
        params = msg.get("params")

        if method is None:
            return
        if method == "keepalived":
            self.send({"id": id_, "result": "ack", "error": None})
            return

        if method == "mining.subscribe":
            self.on_subscribe(id_, params)
        elif method == "mining.configure":
            self.on_configure(id_, params)
        elif method == "mining.authorize":
            if isinstance(params, list) and params:
                self.worker = str(params[0])
            self.send({"id": id_, "result": True, "error": None})
        elif method == "mining.extranonce.subscribe":
            self.send({"id": id_, "result": True, "error": None})
        elif method == "login":
            self.on_login(id_, params)
        elif method == "mining.submit":
            self.on_stratum_submit(id_, params)
        elif method == "submit":
            self.on_rx_submit(id_, params)
        else:
            self.error(id_, 20, "Unsupported request " + str(method))

    # -- subscribe ---------------------------------------------------------

    def on_configure(self, id_, params):
        """Refuse version rolling: Veil keeps algo selector bits in nVersion."""
        self.send({"id": id_, "error": None,
                   "result": {"version-rolling": False}})

    def on_subscribe(self, id_, params):
        if self.node:
            self.error(id_, 21, "Already subscribed")
            return
        # progpow and sha256d both use mining.subscribe, so pick by what the
        # operator enabled, preferring an explicit algo suffix if given.
        node = SUBSCRIBE_NODE
        if isinstance(params, list) and params and isinstance(params[0], str):
            hint = params[0].lower()
            if "sha256" in hint and "sha256d" in NODES:
                node = NODES["sha256d"]
            elif "progpow" in hint and "progpow" in NODES:
                node = NODES["progpow"]
        if node is None:
            self.error(id_, 20, "No mining.subscribe algorithm is enabled on this proxy")
            return

        self.node = node
        node.add_subscriber(self)
        sub_id = "".join(random.choice(string.ascii_uppercase + string.digits) for _ in range(13))

        if node.algo == "sha256d":
            self.extranonce_lo = secrets.randbits(32)
            self.nonce_hi = secrets.randbits(32)
            if SHA256D_WIRE == "cpuminer":
                # cpuminer-opt-veil's stratum requires a parseable extranonce2
                # size in [2,16] even though its sha256dv path does not use one,
                # so advertise a token width. Work is separated by nonce_hi.
                self.send({"id": id_, "error": None,
                           "result": [[["mining.set_difficulty", sub_id],
                                       ["mining.notify", sub_id]],
                                      secrets.token_hex(2), 4]})
                # cpuminer-opt-veil submits at network difficulty (any hash
                # under the block target), so the proxy does not impose a
                # tighter share gate: non blocks are acknowledged, real blocks
                # are forwarded. Set it before the difficulty push below.
                self._no_share_gate = True
            else:
                # Standard stratum: extranonce2 cannot be rolled on Veil, so
                # advertise zero width and hand out fresh jobs instead.
                self.send({"id": id_, "error": None,
                           "result": [[["mining.set_difficulty", sub_id],
                                       ["mining.notify", sub_id]], "", 0]})
            self.set_difficulty(INITIAL_SHARE_DIFF)
        else:
            self.send({"id": id_, "error": None,
                       "result": [sub_id, secrets.token_hex(2)]})
        self.on_new_job()

    def on_login(self, id_, params):
        if self.node:
            self.error(id_, 21, "Already subscribed")
            return
        if "randomx" not in NODES:
            self.error(id_, 20, "randomx is not enabled on this proxy")
            return
        self.node = NODES["randomx"]
        self.node.add_subscriber(self)
        if isinstance(params, dict):
            self.worker = params.get("login")
        self.on_new_job(login_id=id_)

    def set_difficulty(self, diff):
        self.share_diff = diff
        self.share_target = difficulty_to_target(diff)
        self.send({"id": None, "method": "mining.set_difficulty", "params": [diff]})

    # -- job delivery ------------------------------------------------------

    def on_new_job(self, job=None, login_id=None):
        job = job or (self.node.last_job if self.node else None)
        if not job:
            return
        algo = self.node.algo
        if algo == "progpow":
            self.send({"id": None, "method": "mining.notify", "params": [
                job["job_id"],
                job["pprpcheader"],
                "",
                job["target"],
                False,
                job["height"],
                job["bits"],
                job["pprpcepoch"],
                job["pprpcnextepoch"],
                job["pprpcnextepochheight"],
            ]})
        elif algo == "randomx":
            blob = job["rxrpcheader"]
            blob = blob[:280] + secrets.token_hex(4) + blob[288:]
            data = {
                "job_id": job["job_id"],
                "blob": blob,
                "seed_hash": reverse_endianess(job["rxrpcseed"]),
                "target": reverse_endianess(job["target"][:16]),
                "height": job["height"],
                "algo": "rx/veil",
            }
            if login_id is not None:
                self.send({"id": login_id, "error": None, "result": {
                    "id": "rig", "job": data, "status": "OK", "extensions": ["algo"]}})
            else:
                self.send({"id": None, "method": "job", "params": data})
        elif algo == "sha256d":
            self.send_sha256d_job(job)

    def send_sha256d_job(self, job):
        if SHA256D_WIRE == "cpuminer":
            self.send_sha256d_job_cpuminer(job)
        else:
            self.send_sha256d_job_stratum(job)

    def send_sha256d_job_cpuminer(self, job):
        # cpuminer-opt-veil sha256dv notify: it hashes
        #   version_le || dataHash || merkle_le || ntime_le || nonce_lo || nonce_hi
        # so it needs the dataHash and merkle directly, not a coinbase. This
        # works even against a node that does not emit sharpccoinbase.
        self.send({"id": None, "method": "mining.notify", "params": [
            job["job_id"],
            job["_version"],                        # version, integer
            job["_datahash"].hex(),                 # midstate: bytes 4..35 of the header
            job["_merkle"][::-1].hex(),             # merkle, big endian (miner reverses it)
            "",                                     # index 4, unused by the miner
            job["_ntime"],                          # ntime, integer
            job.get("bits", "1d00ffff"),            # nbits, informational
            self.nonce_hi,                          # starting nonce_hi, our work split
            True,                                   # clean
            int(job.get("height", 0)),
            len(job.get("transactions", [])) + 1,   # tx_count including coinbase
        ]})

    def send_sha256d_job_stratum(self, job):
        if job.get("_coinbase") is None:
            if not getattr(self, "_warned_no_coinbase", False):
                self._warned_no_coinbase = True
                log.error(
                    "This node does not return sharpccoinbase, so standard stratum "
                    "cannot be served: the miner would have no way to rebuild the "
                    "merkle root. Update the node to one that provides it, or run "
                    "the proxy with --sha256d-wire cpuminer. Disconnecting %s:%s.",
                    *self.peer)
            self.transport.close()
            return
        # Rotate the low half of the 64 bit nonce per job: this is what lets a
        # miner keep working without ever touching the coinbase.
        self.extranonce_lo = (self.extranonce_lo + 1) & 0xffffffff
        job_key = "{}.{:08x}".format(job["job_id"], self.extranonce_lo)
        self.send({"id": None, "method": "mining.notify", "params": [
            job_key,
            swap_words(job["_datahash"]).hex() if PREVHASH_SWAP else job["_datahash"].hex(),
            job["_coinbase"].hex(),                 # coinb1, the whole coinbase
            "",                                     # coinb2, nothing to append
            job["_branch"],
            "{:08x}".format(job["_version"]),
            "{:08x}".format(self.extranonce_lo),    # the nbits slot is our extranonce
            "{:08x}".format(job["_ntime"]),
            True,
        ]})

    # -- submissions -------------------------------------------------------

    def lookup(self, job_id):
        job = self.node.jobs.get(job_id)
        if job is None and self.node.last_job and self.node.last_job["job_id"] == job_id:
            job = self.node.last_job
        return job

    def on_stratum_submit(self, id_, params):
        if not self.node:
            self.error(id_, 24, "Not subscribed")
            return
        if self.node.algo == "progpow":
            self.submit_progpow(id_, params)
        elif self.node.algo == "sha256d":
            self.submit_sha256d(id_, params)
        else:
            self.error(id_, 20, "mining.submit is not valid for this algorithm")

    def submit_progpow(self, id_, params):
        if not isinstance(params, list) or len(params) != 5:
            self.error(id_, 22, "Bad request: expected 5 parameters")
            return
        job_id = params[1]
        nonce = prune0x(str(params[2]))
        header_hash = prune0x(str(params[3]))
        mix_hash = prune0x(str(params[4]))
        if not (is_hex(nonce) and is_hex(header_hash) and is_hex(mix_hash)):
            self.error(id_, 22, "Bad request: non hex parameter")
            return
        if not self.lookup(job_id):
            self.error(id_, 23, "Stale share")
            return
        self.node.track(self._relay(id_, header_hash, mix_hash, nonce))

    def submit_sha256d(self, id_, params):
        if not isinstance(params, list) or len(params) < 5:
            self.error(id_, 22, "Bad request: expected 5 parameters")
            return
        try:
            if SHA256D_WIRE == "cpuminer":
                # [worker, job_id, nonce_hi_LE, ntime_LE, nonce_lo_LE]
                job_id = str(params[1])
                nonce_hi = int.from_bytes(bytes.fromhex(str(params[2])), "little")
                ntime = int.from_bytes(bytes.fromhex(str(params[3])), "little")
                nonce_lo = int.from_bytes(bytes.fromhex(str(params[4])), "little")
                job = self.lookup(job_id)
            else:
                # [worker, job_id.nonce_lo, extranonce2, ntime_BE, nonce_hi_BE]
                job_key, _en2, ntime_hex, nonce_hex = params[1], params[2], params[3], params[4]
                if not (is_hex(str(ntime_hex), 4) and is_hex(str(nonce_hex), 4)):
                    self.error(id_, 22, "Bad request: ntime and nonce must be 4 byte hex")
                    return
                if "." not in str(job_key):
                    self.error(id_, 23, "Stale share")
                    return
                job_id, _, lo_hex = str(job_key).partition(".")
                nonce_lo = int(lo_hex, 16)
                nonce_hi = int(str(nonce_hex), 16)
                ntime = int(str(ntime_hex), 16)
                job = self.lookup(job_id)
        except ValueError:
            self.error(id_, 22, "Bad request: unparseable share")
            return

        if not job:
            self.stale += 1
            self.error(id_, 23, "Stale share")
            return

        nonce64 = (nonce_hi << 32) | nonce_lo

        # Rebuild exactly what the miner hashed and check it ourselves. This
        # costs nothing and turns silent misconfiguration into a clear error.
        header = (struct.pack("<I", job["_version"]) + job["_datahash"] +
                  job["_merkle"] + struct.pack("<I", ntime) +
                  struct.pack("<Q", nonce64))
        powhash = dsha256(header)
        value = int.from_bytes(powhash, "little")

        if (not getattr(self, "_no_share_gate", False)
                and self.share_target is not None and value >= self.share_target):
            self.error(id_, 23, "Share above target")
            return

        self.shares += 1
        if self.first_share is None:
            self.first_share = time.time()

        block_target = int(job["target"], 16)
        if value >= block_target:
            # A valid share, but not a block. Acknowledge so the miner sees
            # progress; nothing to send the node.
            self.send({"id": id_, "result": True, "error": None})
            return

        log.info("\x1b[1msha256d block candidate\x1b[0m from %s at height %s",
                 self.worker or "miner", job.get("height"))
        self.node.track(self._relay_sha(id_, job, powhash, nonce64, ntime))

    def on_rx_submit(self, id_, params):
        if not self.node or self.node.algo != "randomx":
            self.error(id_, 20, "submit is only valid for randomx")
            return
        if not isinstance(params, dict) or not all(
                k in params for k in ("job_id", "nonce", "result")):
            self.error(id_, 22, 'Bad request: expected "job_id", "nonce" and "result"')
            return
        if not is_hex(str(params["nonce"]), 4):
            self.error(id_, 22, "Bad request: nonce must be 4 byte hex")
            return
        job = self.lookup(params["job_id"])
        if not job:
            self.error(id_, 23, "Stale share")
            return
        nonce = reverse_endianess(str(params["nonce"]))
        self.node.track(
            self._relay_rx(id_, job["rxrpcheader"], str(params["result"]), nonce))

    async def _relay(self, id_, *args):
        res = await self.node.submit(*args)
        if res is True:
            self.send({"id": id_, "result": True, "error": None})
        else:
            self.send({"id": id_, "result": False, "error": res})

    async def _relay_rx(self, id_, *args):
        res = await self.node.submit(*args)
        if res is True:
            self.send({"id": id_, "result": {"status": "OK"}, "error": None})
        else:
            self.send({"id": id_, "result": None, "error": res})

    async def _relay_sha(self, id_, job, powhash, nonce64, ntime):
        res = await self.node.submit(
            job["sharpcheader"], powhash[::-1].hex(),
            "{:016x}".format(nonce64),
            "{:08x}".format(ntime) if ntime != job["_ntime"] else None)
        if res is True:
            self.send({"id": id_, "result": True, "error": None})
        else:
            self.send({"id": id_, "result": False, "error": res})


# --------------------------------------------------------------------------
# self test
# --------------------------------------------------------------------------

def selftest():
    """Check the pieces that are easy to get subtly wrong."""
    ok = True

    # merkle branch reproduces a known root
    txids = [os.urandom(32) for _ in range(5)]
    coinbase = os.urandom(120)
    branch = merkle_branch_for_coinbase(txids)
    root = dsha256(coinbase)
    for h in branch:
        root = dsha256(root + h)
    # recompute the honest way
    layer = [dsha256(coinbase)] + txids
    while len(layer) > 1:
        if len(layer) % 2:
            layer.append(layer[-1])
        layer = [dsha256(layer[i] + layer[i + 1]) for i in range(0, len(layer), 2)]
    if root != layer[0]:
        print("FAIL: merkle branch does not reproduce the root")
        ok = False

    # single transaction block: branch is empty, root is the coinbase hash
    if merkle_branch_for_coinbase([]) != []:
        print("FAIL: empty branch expected for a coinbase only block")
        ok = False

    # word swapping is its own inverse
    b = os.urandom(32)
    if swap_words(swap_words(b)) != b:
        print("FAIL: swap_words is not an involution")
        ok = False

    # difficulty and target round trip
    if abs(target_to_difficulty("%064x" % difficulty_to_target(1000)) - 1000) > 1:
        print("FAIL: difficulty/target round trip")
        ok = False

    # header assembly matches the node's layout
    ver, ntime, nonce64 = 0x31000000, 0x66000000, 0x0123456789abcdef
    dh, mr = os.urandom(32), os.urandom(32)
    header = (struct.pack("<I", ver) + dh + mr +
              struct.pack("<I", ntime) + struct.pack("<Q", nonce64))
    if len(header) != 80:
        print("FAIL: header is not 80 bytes")
        ok = False
    if header[72:76] != struct.pack("<I", nonce64 & 0xffffffff):
        print("FAIL: nonce low half is not in the nbits slot")
        ok = False
    if header[76:80] != struct.pack("<I", nonce64 >> 32):
        print("FAIL: nonce high half is not in the nonce slot")
        ok = False

    print("selftest:", "ok" if ok else "FAILED")
    return 0 if ok else 1


# --------------------------------------------------------------------------


def main():
    p = argparse.ArgumentParser(
        prog="veilproxy",
        description="Stratum proxy for solo mining VEIL (progpow, randomx, sha256d).")
    p.add_argument("-a", "--address", default="0.0.0.0",
                   help="address to listen on, defaults to 0.0.0.0")
    p.add_argument("-p", "--port", type=int, help="port to listen on")
    p.add_argument("-n", "--node",
                   help="node rpc url, e.g. http://user:pass@127.0.0.1:58812")
    p.add_argument("--algos", default="progpow,randomx,sha256d",
                   help="comma separated algorithms to serve")
    p.add_argument("--subscribe-algo", default="progpow",
                   choices=("progpow", "sha256d"),
                   help="which algorithm a bare mining.subscribe means")
    p.add_argument("--share-diff", type=float, default=1.0,
                   help="sha256d share difficulty reported to miners")
    p.add_argument("--raw-prevhash", action="store_true",
                   help="send the sha256d prevhash slot without the usual "
                        "stratum 32 bit word swap")
    p.add_argument("--sha256d-wire", default="stratum",
                   choices=("stratum", "cpuminer"),
                   help="sha256d job format: 'stratum' is standard stratum v1 "
                        "for ASIC/cgminer style miners; 'cpuminer' is the "
                        "cpuminer-opt-veil sha256dv format")
    p.add_argument("-j", "--jobs", action="store_true", help="show jobs in the log")
    p.add_argument("-v", "--verbose", "--debug", action="store_true",
                   help="set log level to debug")
    p.add_argument("--selftest", action="store_true",
                   help="run internal consistency checks and exit")
    p.add_argument("--version", action="version", version="%(prog)s " + VERSION)
    args = p.parse_args()

    if args.selftest:
        sys.exit(selftest())
    if not args.port or not args.node:
        p.error("--port and --node are required")

    global SHOW_JOBS, NODES, SUBSCRIBE_NODE, INITIAL_SHARE_DIFF, PREVHASH_SWAP, SHA256D_WIRE
    SHOW_JOBS = args.jobs or args.verbose
    INITIAL_SHARE_DIFF = args.share_diff
    PREVHASH_SWAP = not args.raw_prevhash
    SHA256D_WIRE = args.sha256d_wire

    level = "DEBUG" if args.verbose else "INFO"
    if coloredlogs:
        coloredlogs.install(level=level, milliseconds=True)
        for name in ("progpow", "randomx", "sha256d", "veilproxy"):
            coloredlogs.install(logger=logging.getLogger(name), level=level, milliseconds=True)
    else:
        logging.basicConfig(level=level, format="%(asctime)s %(name)s %(levelname)s %(message)s")

    classes = {"progpow": ProgPowNode, "randomx": RandomXNode, "sha256d": Sha256dNode}
    NODES = {}
    for name in [a.strip() for a in args.algos.split(",") if a.strip()]:
        if name not in classes:
            p.error("unknown algorithm " + name)
        NODES[name] = classes[name](args.node)
    if not NODES:
        p.error("no algorithms enabled")
    SUBSCRIBE_NODE = NODES.get(args.subscribe_algo)

    async def runner():
        tasks = [asyncio.ensure_future(n.run()) for n in NODES.values()]
        loop = asyncio.get_event_loop()
        server = await loop.create_server(StratumSession, args.address, args.port)
        log.info("veilproxy %s serving [%s] on %s:%d", VERSION,
                 ", ".join(NODES), *server.sockets[0].getsockname()[:2])
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            pass
        finally:
            server.close()
            for t in tasks:
                t.cancel()

    try:
        asyncio.run(runner())
    except KeyboardInterrupt:
        log.info("Shutting down")


if __name__ == "__main__":
    main()
