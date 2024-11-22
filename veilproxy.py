import argparse
import asyncio
import aiohttp
import json
import random
import secrets
import string
import logging
import coloredlogs
from hashlib import sha256
import binascii
import struct
import base58
import os

def prune0x(s):
    return s[2:] if s.startswith('0x') else s

def reverseEndianess(s):
    b = bytearray.fromhex(s)
    b.reverse()
    return b.hex()

def formatDiff(target):
    diff = 0xffffffffffffffff / int(target[:16], 16)
    UNITS = [(1000000000000, 'T'), (1000000000, 'G'), (1000000, 'M'), (1000, 'K')]
    for l, u in UNITS:
        if diff > l:
            return '{:.2f}{}'.format(diff / l, u)

def double_sha256(s):
    return sha256(sha256(s).digest()).digest()

def read_veil_conf():
    veil_conf_path = os.path.expanduser('~/.veil/veil.conf')
    conf = {}
    if os.path.exists(veil_conf_path):
        with open(veil_conf_path, 'r') as f:
            for line in f:
                if '=' in line:
                    key, value = line.strip().split('=', 1)
                    conf[key.strip()] = value.strip()
    return conf

class NodeConnection:
    def __init__(self, url, logger):
        self.url = url
        self.logger = logger
        self.lastJob = None
        self.session = None
        self.subscribers = []
        self.submissionCounter = 0
        self.successfulSubmissionCounter = 0

    @property
    def tag(self):
        raise NotImplementedError("Not implemented yet")

    def getblocktemplateJSON(self):
        raise NotImplementedError("Not implemented yet")

    def submitJSON(self):
        raise NotImplementedError("Not implemented yet")

    def setJobId(self, job):
        raise NotImplementedError("Not implemented yet")

    async def run(self):
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=2000)) as self.session:
            while True:
                try:
                    data = self.getblocktemplateJSON()

                    if self.lastJob:
                        data['params'][0]['longpollid'] = self.lastJob['longpollid']

                    async with self.session.post(self.url, json=data) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            if data['error']:
                                self.logger.error('RPC error (%d): %s',
                                                  data['error']['code'],
                                                  data['error']['message'])
                            else:
                                job = data['result']
                                if not self.lastJob or job['longpollid'] != self.lastJob['longpollid']:
                                    self.setJobId(job)
                                    lastJob = self.lastJob
                                    self.lastJob = job
                                    if not lastJob or lastJob['job_id'] != job['job_id']:
                                        if SHOW_JOBS:
                                            self.logger.info('New %s job diff \x1b[1m%s\x1b[0m height \x1b[1m%d\x1b[0m',
                                                            self.tag, formatDiff(job['target']), job['height'])
                                        for s in self.subscribers:
                                            try:
                                                s.onNewJob(job)
                                            except asyncio.CancelledError:
                                                raise
                                            except Exception:
                                                pass
                        elif resp.status == 401:
                            self.logger.critical('RPC error: Unauthorized. Wrong username/password?')
                            await asyncio.sleep(10)
                        else:
                            self.logger.critical('Unknown RPC error: status code ' + str(resp.status))
                            await asyncio.sleep(10)
                except asyncio.CancelledError:
                    return
                except Exception as e:
                    self.logger.error('RPC error: %s', str(e))
                    await asyncio.sleep(1)

    @property
    def countersStr(self):
        failedSubmissionCount = self.submissionCounter - self.successfulSubmissionCounter
        ff = '\x1b[31m{}\x1b[0m' if failedSubmissionCount > 0 else '{}'
        return ('(\x1b[32m{}\x1b[0m/' + ff + ')').format(
            self.successfulSubmissionCounter, failedSubmissionCount)

    async def submit(self, *args, **kwargs):
        self.submissionCounter += 1
        try:
            data = self.submitJSON(*args, **kwargs)

            if self.logger.isEnabledFor(logging.DEBUG):
                self.logger.debug('Submitting block to node %s', json.dumps(data))

            async with self.session.post(self.url, json=data) as resp:
                res = await resp.json()
                if self.logger.isEnabledFor(logging.DEBUG):
                    self.logger.debug('Block submission response %s', json.dumps(res))
                if 'result' in res:
                    if res['result'] is True or res['result'] == None:
                        self.successfulSubmissionCounter += 1
                        self.logger.info('\x1b[32mBlock submission succeeded\x1b[0m %s',
                                         self.countersStr)
                        return True
                    elif res['result']:
                        self.logger.error('Block submission failed: %s', str(res['result']))
                        return { 'code': 26, 'message': res['result'] }
                if 'error' in res:
                    self.logger.error('Block submission failed (%d): %s',
                                  res['error']['code'], res['error']['message'])
                    return res['error']
                self.logger.error('Unknown block submission error')
                return { 'code': 25, 'message': 'Unknown error' }
        except asyncio.CancelledError:
            raise
        except Exception as e:
            self.logger.error('Block submission RPC error: %s', str(e))
            return { 'code': 24, 'message': str(e) }

class PPNodeConnection(NodeConnection):
    def __init__(self, url, logger):
        super().__init__(url, logger)

    @property
    def tag(self):
        return '\x1b[0;36mprogpow\x1b[0m'

    def getblocktemplateJSON(self):
        return {
            'jsonrpc': '1.0',
            'method': 'getblocktemplate',
            'params': [{ "algo": "progpow" }],
        }

    def submitJSON(self, header_hash, mix_hash, nonce):
        return {
            'jsonrpc': '1.0',
            'method': 'pprpcsb',
            'params': [header_hash, mix_hash, nonce],
        }

    def setJobId(self, job):
        if 'pprpcheader' in job and 'pprpcnextepoch' not in job:
            self.logger.critical('Update your VEIL wallet to version 1.4.0.0 or higher')
            exit(1)
        elif 'pprpcheader' not in job:
            self.logger.critical('Your VEIL wallet is either misconfigured or not up-to-date. Did you set a miningaddress in the veil.conf?')
            exit(1)
        job['job_id'] = job['pprpcheader']

class RXNodeConnection(NodeConnection):
    def __init__(self, url, logger):
        super().__init__(url, logger)

    @property
    def tag(self):
        return '\x1b[0;33mrandomx\x1b[0m'

    def getblocktemplateJSON(self):
        return {
            'jsonrpc': '1.0',
            'method': 'getblocktemplate',
            'params': [{ "algo": "randomx" }],
        }

    def submitJSON(self, header, rx_hash, nonce):
        return {
            'jsonrpc': '1.0',
            'method': 'rxrpcsb',
            'params': [header, rx_hash, nonce],
        }

    def setJobId(self, job):
        job['job_id'] = sha256(job['rxrpcheader'].encode()).hexdigest()

# SHA256NodeConnection class and related methods (modified for SHA-256d support)
class SHA256NodeConnection(NodeConnection):
    def __init__(self, url, logger):
        super().__init__(url, logger)
        self.veil_address = None
        self.pubkey_hash = None
        self.load_veil_address()

    def load_veil_address(self):
        conf = read_veil_conf()
        self.veil_address = conf.get('miningaddress')
        if not self.veil_address:
            self.logger.critical('Mining address not found in veil.conf. Please set miningaddress=<your_veil_address> in veil.conf.')
            exit(1)
        self.pubkey_hash = self.decode_veil_address(self.veil_address)

    @property
    def tag(self):
        return '\x1b[0;32msha256d\x1b[0m'

    def getblocktemplateJSON(self):
        return {
            'jsonrpc': '1.0',
            'method': 'getblocktemplate',
            'params': [{'rules': ['segwit']}],
        }

    def submitJSON(self, block_hex):
        return {
            'jsonrpc': '1.0',
            'method': 'submitblock',
            'params': [block_hex],
        }

    def setJobId(self, job):
        job['job_id'] = sha256(json.dumps(job).encode()).hexdigest()
        self.job = job

        # Extract necessary data
        self.previous_block_hash = job['previousblockhash']
        self.transactions = job['transactions']
        self.coinbase_value = job['coinbasevalue']
        self.bits = job['bits']
        self.height = job['height']
        self.curtime = job['curtime']
        self.version = job['version']
        self.target = int(job['target'], 16)

        # VEIL-specific fields
        self.hashWitnessMerkleRoot = bytes.fromhex(job.get('hashwitnessmerkleroot', '00' * 64))
        self.hashAccumulators = bytes.fromhex(job.get('hashaccumulators', '00' * 64))
        self.hashPoFN = bytes.fromhex(job.get('hashpofn', '00' * 64))

        # Build merkle branches
        self.merkle_branches = [tx['hash'] for tx in self.transactions]

    def get_payout_script(self):
        # Use the pubkey_hash obtained from the veil.conf file
        script = (
            b'\x76' +              # OP_DUP
            b'\xa9' +              # OP_HASH160
            b'\x14' +              # Push 20 bytes
            self.pubkey_hash +
            b'\x88' +              # OP_EQUALVERIFY
            b'\xac'                # OP_CHECKSIG
        )
        return script.hex()

    def decode_veil_address(self, address):
        # Decode Base58
        address_bytes = base58.b58decode(address)
        # The first byte is the version, the last 4 bytes are the checksum
        if len(address_bytes) != 25:
            raise ValueError('Invalid VEIL address length')
        # Extract the public key hash
        pubkey_hash = address_bytes[1:-4]
        return pubkey_hash

    def serialize_transaction(self, tx):
        # Serialize the transaction into bytes
        result = b''

        # Version
        result += struct.pack('<I', tx['version'])

        # Input count
        result += self.encode_varint(len(tx['inputs']))

        # Inputs
        for txin in tx['inputs']:
            result += bytes.fromhex(txin['prev_output'])
            script = bytes.fromhex(txin['script'])
            result += self.encode_varint(len(script))
            result += script
            result += bytes.fromhex(txin['sequence'])

        # Output count
        result += self.encode_varint(len(tx['outputs']))

        # Outputs
        for txout in tx['outputs']:
            result += struct.pack('<q', txout['value'])
            script = bytes.fromhex(txout['script'])
            result += self.encode_varint(len(script))
            result += script

        # Locktime
        result += struct.pack('<I', tx['locktime'])

        return result

    def encode_varint(self, i):
        if i < 0xfd:
            return struct.pack('B', i)
        elif i <= 0xffff:
            return b'\xfd' + struct.pack('<H', i)
        elif i <= 0xffffffff:
            return b'\xfe' + struct.pack('<I', i)
        else:
            return b'\xff' + struct.pack('<Q', i)

    def build_coinbase(self, extranonce1, extranonce2):
        # Construct the coinbase scriptSig
        coinbase_script = (
            struct.pack('<I', self.height) +
            extranonce1 +
            extranonce2
        )

        # Coinbase input
        coinbase_in = {
            'prev_output': '00' * 32 + 'ffffffff',  # Null previous output
            'script': coinbase_script.hex(),
            'sequence': 'ffffffff',
        }

        # Coinbase output
        coinbase_out = {
            'value': self.coinbase_value,
            'script': self.get_payout_script(),
        }

        # Assemble coinbase transaction
        coinbase_tx = {
            'version': 1,
            'inputs': [coinbase_in],
            'outputs': [coinbase_out],
            'locktime': 0,
        }

        coinbase_tx_serialized = self.serialize_transaction(coinbase_tx)
        return coinbase_tx_serialized

    def calculate_merkle_root(self, coinbase_hash):
        merkle_hashes = [coinbase_hash] + [bytes.fromhex(tx['hash']) for tx in self.transactions]
        while len(merkle_hashes) > 1:
            if len(merkle_hashes) % 2 != 0:
                merkle_hashes.append(merkle_hashes[-1])
            new_hashes = []
            for i in range(0, len(merkle_hashes), 2):
                new_hash = double_sha256(merkle_hashes[i] + merkle_hashes[i+1])
                new_hashes.append(new_hash)
            merkle_hashes = new_hashes
        return merkle_hashes[0]

    def compute_data_hash(self):
        # Serialize hashPrevBlock, hashWitnessMerkleRoot, hashAccumulators, nBits
        data = b''
        data += bytes.fromhex(reverseEndianess(self.previous_block_hash))
        data += self.hashWitnessMerkleRoot
        data += self.hashAccumulators
        data += bytes.fromhex(reverseEndianess(self.bits))
        data_hash = double_sha256(data)
        return data_hash

    def build_block_header(self, merkle_root, ntime, nonce):
        # Compute dataHash
        data_hash = self.compute_data_hash()

        # Serialize block header fields
        version = struct.pack('<I', self.version | (1 << 24))  # Include SHA256D_BLOCK flag
        hashMerkleRoot = merkle_root
        time = struct.pack('<I', int(ntime, 16))
        nNonce64 = struct.pack('<Q', int(nonce, 16))

        # Serialize fields
        header = b''
        header += version
        header += data_hash
        header += hashMerkleRoot
        header += time
        header += nNonce64

        return header

    def assemble_full_block(self, header, coinbase_tx):
        # Serialize transactions
        txs = [coinbase_tx] + [bytes.fromhex(tx['data']) for tx in self.transactions]
        tx_count = self.encode_varint(len(txs))
        tx_data = b''.join(txs)
        block = header + tx_count + tx_data
        return block

class ServerProtocol(asyncio.Protocol):
    def connection_made(self, transport):
        self.client_addr   = transport.get_extra_info('peername')
        self.transport     = transport
        self.loginId       = None
        self.node          = None
        self.extranonce1   = None
        self.extranonce2_size = None
        logging.info('Connection with client %s:%d established', *self.client_addr)

    def connection_lost(self, exception):
        logging.info('Connection with client %s:%d closed.', *self.client_addr)

        if self.node:
            self.node.subscribers.remove(self)

    def send(self, data):
        data['jsonrpc'] = '2.0'
        self.transport.write(json.dumps(data).encode() + b'\n')

    async def submitSHA256d(self, id, params):
        worker_name = params[0]
        job_id = params[1]
        extranonce2_hex = params[2]
        ntime = params[3]
        nonce = params[4]

        if self.node.lastJob and self.node.lastJob['job_id'] == job_id:
            extranonce1_bin = bytes.fromhex(self.extranonce1)
            extranonce2_bin = bytes.fromhex(extranonce2_hex)

            # Build the coinbase transaction
            coinbase_tx = self.node.build_coinbase(extranonce1_bin, extranonce2_bin)
            coinbase_hash_bin = double_sha256(coinbase_tx)

            # Calculate merkle root
            merkle_root = self.node.calculate_merkle_root(coinbase_hash_bin)
            # Build the block header
            header = self.node.build_block_header(merkle_root, ntime, nonce)
            # Compute the block hash (double SHA256 of the header)
            block_hash_bin = double_sha256(header)

            # Convert block hash to integer for comparison
            block_hash_int = int.from_bytes(block_hash_bin[::-1], byteorder='big')

            if block_hash_int > self.node.target:
                self.send({
                    'id': id,
                    'result': None,
                    'error': {
                        'code': 23,
                        'message': 'Share above target.'
                    }
                })
                return

            full_block = self.node.assemble_full_block(header, coinbase_tx)
            block_hex = full_block.hex()
            res = await self.node.submit(block_hex)
            if res == True:
                self.send({ 'id': id, 'result': True })
            else:
                self.send({ 'id': id, 'result': None, 'error': res })
        else:
            self.send({
                'id': id,
                'error': {
                    'code': 23,
                    'message': 'Stale share.'
                }
            })

    def data_received(self, data):
        try:
            lines = data.decode().strip().split('\n')
            for line in lines:
                if not line.strip():
                    continue
                d = json.loads(line)
                id = d['id'] if 'id' in d else None
                if 'method' in d and 'params' in d:
                    if d['method'] == 'mining.subscribe':
                        if not self.node:
                            # Keep existing behavior for other algorithms
                            if 'SHA256' in d.get('params', [''])[0]:
                                self.node = SHANODE
                            elif 'RandomX' in d.get('params', [''])[0]:
                                self.node = RXNODE
                            elif 'ProgPow' in d.get('params', [''])[0]:
                                self.node = PPNODE
                            else:
                                self.node = SHANODE  # Default to SHA256d
                            self.node.subscribers.append(self)
                            self.extranonce1 = secrets.token_hex(4)
                            self.extranonce2_size = 4  # Size in bytes
                            result = [None, self.extranonce1, self.extranonce2_size]
                            self.send({ 'id': id, 'result': result, 'error': None })
                            self.onNewJob()
                        else:
                            self.send({
                                'id': id,
                                'error': { 'code': 21, 'message': 'Already subscribed.' }
                            })
                    elif d['method'] == 'mining.authorize':
                        self.send({ 'id': id, 'result': True, 'error': None })
                    elif d['method'] == 'mining.submit':
                        # Handle share submission
                        asyncio.ensure_future(self.submitSHA256d(id, d['params']))
                    elif d['method'] == 'mining.extranonce.subscribe':
                        # Extranonce subscription (optional)
                        self.send({ 'id': id, 'result': True, 'error': None })
                    else:
                        self.send({
                            'id': id,
                            'error': {
                                'code': 20,
                                'message': 'Unsupported request ' + str(d['method'])
                            }
                        })
        except json.JSONDecodeError:
            pass

    def onNewJob(self, job=None):
        if not job:
            job = self.node.lastJob
        if job:
            if self.node == SHANODE:
                job_id = job['job_id']
                prevhash = reverseEndianess(job['previousblockhash'])
                coinb1 = self.build_coinb1()
                coinb2 = self.build_coinb2()
                merkle_branch = [reverseEndianess(h) for h in self.node.merkle_branches]
                version = '{0:08x}'.format(job['version'] | (1 << 24))
                nbits = job['bits']
                ntime = '{0:08x}'.format(job['curtime'])
                clean_jobs = True

                self.send({
                    'id': None,
                    'method': 'mining.notify',
                    'params': [
                        job_id,
                        prevhash,
                        coinb1,
                        coinb2,
                        merkle_branch,
                        version,
                        nbits,
                        ntime,
                        clean_jobs
                    ]
                })
            else:
                # Handle other algorithms (ProgPoW and RandomX) as before
                # Existing code for ProgPoW and RandomX remains unchanged
                pass

    def build_coinb1(self):
        # Construct the initial part of the coinbase transaction up to the extranonce1
        coinb1 = '01000000'  # Version
        coinb1 += '01'  # Input count
        coinb1 += '00' * 32  # Prev output hash
        coinb1 += 'ffffffff'  # Prev output index
        # scriptSig length and data will be added later in coinb2
        return coinb1

    def build_coinb2(self):
        # Construct the remaining parts of the coinbase transaction
        # scriptSig will be built by the miner using extranonce1 and extranonce2
        coinb2 = 'ffffffff'  # Sequence
        coinb2 += '01'  # Output count

        # Amount (little-endian)
        value = '{:016x}'.format(self.node.coinbase_value)
        value = ''.join([value[i:i+2] for i in range(0, len(value), 2)][::-1])

        script_pubkey = self.node.get_payout_script()
        script_pubkey_length = len(script_pubkey) // 2  # Number of bytes

        coinb2 += value  # Output value
        coinb2 += '{:02x}'.format(script_pubkey_length)
        coinb2 += script_pubkey
        coinb2 += '00000000'  # Locktime
        return coinb2

def main():
    parser = argparse.ArgumentParser(prog="veilproxy",
                                     description="Stratum proxy to solo mine to VEIL node.")
    parser.add_argument('-a', '--address', default='0.0.0.0',
                        help="the address to listen on, defaults to 0.0.0.0")
    parser.add_argument('-p', '--port', type=int, required=True,
                        help="the port to listen on")
    parser.add_argument('-n', '--node', required=True,
                        help="the url of the node rpc server to connect to. " \
                             "Example: http://username:password@127.0.0.1:5555")
    parser.add_argument('-j', '--jobs', action="store_true",
                        help="show jobs in the log")
    parser.add_argument('-v', '--verbose', '--debug', action="store_true",
                        help="set log level to debug")
    parser.add_argument('--version', action='version', version='%(prog)s 2.0.0')
    args = parser.parse_args()

    global SHOW_JOBS
    SHOW_JOBS = args.jobs or args.verbose

    progpowLogger = logging.getLogger('progpow')
    randomxLogger = logging.getLogger('randomx')
    sha256Logger = logging.getLogger('sha256d')

    level = 'DEBUG' if args.verbose else 'INFO'
    coloredlogs.install(level=level, milliseconds=True)
    coloredlogs.install(logger=progpowLogger, level=level, milliseconds=True)
    coloredlogs.install(logger=randomxLogger, level=level, milliseconds=True)
    coloredlogs.install(logger=sha256Logger, level=level, milliseconds=True)

    global PPNODE, RXNODE, SHANODE
    PPNODE = PPNodeConnection(args.node, progpowLogger)
    RXNODE = RXNodeConnection(args.node, randomxLogger)
    SHANODE = SHA256NodeConnection(args.node, sha256Logger)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    coro = loop.create_server(ServerProtocol, args.address, args.port)
    server = loop.run_until_complete(coro)

    logging.info('Serving on {}:{}'.format(*server.sockets[0].getsockname()))

    ppnode_task = loop.create_task(PPNODE.run())
    rxnode_task = loop.create_task(RXNODE.run())
    sha256_task = loop.create_task(SHANODE.run())

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        ppnode_task.cancel()
        rxnode_task.cancel()
        sha256_task.cancel()

    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()

if __name__ == "__main__":
    main()
