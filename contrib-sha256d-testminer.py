#!/usr/bin/env python3
"""Minimal standard-stratum-v1 sha256d miner, standing in for a USB ASIC.

Does exactly what cgminer does: subscribe, authorize, take mining.notify,
rebuild the coinbase and merkle root itself, assemble the 80 byte header,
roll the nonce, submit worker/job/extranonce2/ntime/nonce.
"""
import json
import socket
import struct
import sys
from hashlib import sha256


def dsha(b):
    return sha256(sha256(b).digest()).digest()


def swap_words(b):
    return b"".join(b[i:i + 4][::-1] for i in range(0, len(b), 4))


class Client:
    def __init__(self, host, port, swap=True):
        self.s = socket.create_connection((host, port), timeout=60)
        self.f = self.s.makefile("rwb")
        self.id = 0
        self.swap = swap
        self.diff = 1.0

    def call(self, method, params):
        self.id += 1
        self.f.write(json.dumps({"id": self.id, "method": method,
                                 "params": params}).encode() + b"\n")
        self.f.flush()
        return self.id

    def readmsg(self):
        line = self.f.readline()
        if not line:
            raise EOFError("proxy closed the connection")
        return json.loads(line)

    def run(self, max_headers=400000):
        sub_id = self.call("mining.subscribe", ["asic-sim/1.0"])
        auth_id = None
        submit_id = None
        sub = None
        while True:
            m = self.readmsg()
            mid = m.get("id")
            if mid == sub_id and m.get("result"):
                sub = m["result"]
                print("subscribed: extranonce1=%r extranonce2_size=%r" %
                      (sub[1], sub[2]))
                auth_id = self.call("mining.authorize", ["tester", "x"])
            elif mid == auth_id:
                print("authorized:", m.get("result"))
            elif m.get("method") == "mining.set_difficulty":
                self.diff = m["params"][0]
                print("share difficulty:", self.diff)
            elif m.get("method") == "mining.notify":
                job = m["params"]
                print("job %s version=%s ntime=%s nbits(nonce_lo)=%s branch=%d" %
                      (job[0], job[5], job[7], job[6], len(job[4])))
                submit_id = self.mine(job, sub, max_headers)
                if submit_id is None:
                    print("no share found in this job, waiting for the next")
            elif mid is not None and mid == submit_id:
                print("SUBMIT RESPONSE:", m.get("result"), m.get("error"))
                return 0 if m.get("result") is True else 1

    def mine(self, job, sub, max_headers):
        job_id, prevhash_hex, coinb1, coinb2, branch, ver_hex, nbits_hex, ntime_hex, _clean = job[:9]
        extranonce1 = sub[1]
        en2_size = sub[2]
        extranonce2 = "00" * en2_size

        coinbase = bytes.fromhex(coinb1 + extranonce1 + extranonce2 + coinb2)
        root = dsha(coinbase)
        for h in branch:
            root = dsha(root + bytes.fromhex(h))

        prevslot = bytes.fromhex(prevhash_hex)
        if self.swap:
            prevslot = swap_words(prevslot)

        version = int(ver_hex, 16)
        ntime = int(ntime_hex, 16)
        nonce_lo = int(nbits_hex, 16)

        prefix = (struct.pack("<I", version) + prevslot + root +
                  struct.pack("<I", ntime) + struct.pack("<I", nonce_lo))
        assert len(prefix) == 76, len(prefix)

        # share target from difficulty, same formula as the proxy
        limit = 0x0000ffff * (1 << (8 * 26))
        target = max(1, int(limit / self.diff)) if self.diff > 0 else limit

        for nonce in range(max_headers):
            h = dsha(prefix + struct.pack("<I", nonce))
            if int.from_bytes(h, "little") < target:
                print("found nonce %08x hash %s" % (nonce, h[::-1].hex()))
                return self.call("mining.submit",
                                 ["tester", job_id, extranonce2, ntime_hex, "%08x" % nonce])
        print("no share in %d nonces" % max_headers)
        return None


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2] if len(sys.argv) > 2 else 3333)
    swap = "--raw" not in sys.argv
    sys.exit(Client(host, port, swap).run())
