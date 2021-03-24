"""
The script demonstrates the Unbound Tech blockchain-crypto-mpc library.
This example has two instances, a client and a server, which cooperate to execute crypto primitives via MPC.

A simple protocol is executed that starts with client sending command parameters to the server.
Messages are sent as is, preceded by length.

Usage:
    Server instance should have the '--server' flag.
    Client instance should have the hostname ('--host') of the server.
    Run with '--help' flag to see all parameter details.

Example 1: Generate a split EDDSA key
    user1@host1> python mpc_demo.py --out_file key_share.bin --server
    user2@host2> python mpc_demo.py --type EDDSA --command generate --out_file key_share.bin --host host1

Example 2: Sign with the split EDDSA key
    user1@host1> python mpc_demo.py --in_file key_share.bin --data_file data.dat --server
    user2@host2> python mpc_demo.py --type EDDSA --command sign --in_file key_share.bin --data_file data.dat --host host1
"""
import sys
import argparse
import socket
import struct
import datetime
import hashlib

import mpc_crypto
import bitcoin
from bitcoin.wallet import CBitcoinAddress
import ecdsa
import codecs

CLIENT = 1
SERVER = 2

def parse_element(hex_str, offset, element_size):
    """
    :param hex_str: string to parse the element from.
    :type hex_str: hex str
    :param offset: initial position of the object inside the hex_str.
    :type offset: int
    :param element_size: size of the element to extract.
    :type element_size: int
    :return: The extracted element from the provided string, and the updated offset after extracting it.
    :rtype tuple(str, int)
    """

    return hex_str[offset:offset+element_size], offset+element_size


def dissect_signature(hex_sig):
    """
    Extracts the r, s and ht components from a Bitcoin ECDSA signature.
    :param hex_sig: Signature in  hex format.
    :type hex_sig: hex str
    :return: r, s, t as a tuple.
    :rtype: tuple(str, str, str)
    """

    offset = 0
    # Check the sig contains at least the size and sequence marker
    assert len(hex_sig) > 4, "Wrong signature format."
    sequence, offset = parse_element(hex_sig, offset, 2)
    # Check sequence marker is correct
    assert sequence == '30', "Wrong sequence marker."
    signature_length, offset = parse_element(hex_sig, offset, 2)
    # Check the length of the remaining part matches the length of the signature + the length of the hashflag (1 byte)
    assert len(hex_sig[offset:])/2 == int(signature_length, 16), "Wrong length."
    # Get r
    marker, offset = parse_element(hex_sig, offset, 2)
    assert marker == '02', "Wrong r marker."
    len_r, offset = parse_element(hex_sig, offset, 2)
    len_r_int = int(len_r, 16) * 2   # Each byte represents 2 characters
    r, offset = parse_element(hex_sig, offset, len_r_int)
    # Get s
    marker, offset = parse_element(hex_sig, offset, 2)
    assert marker == '02', "Wrong s marker."
    len_s, offset = parse_element(hex_sig, offset, 2)
    len_s_int = int(len_s, 16) * 2  # Each byte represents 2 characters
    s, offset = parse_element(hex_sig, offset, len_s_int)

    return r, s



def public_to_address(public_key):
    public_key_bytes = codecs.decode(public_key,'hex')
    sha256_bpk_digest = hashlib.sha256(public_key_bytes).digest()
    ripemd160_bpk = hashlib.new('ripemd160')
    ripemd160_bpk.update(sha256_bpk_digest)
    ripemd160_bpk_digest = ripemd160_bpk.digest()
    ripemd160_bpk_hex = codecs.encode(ripemd160_bpk_digest,'hex')
    network_byte = b'6f' #比特币测试网地址版本号
    network_bitcoin_public_key = network_byte + ripemd160_bpk_hex
    network_bitcoin_public_key_bytes = codecs.decode(network_bitcoin_public_key,'hex')
    sha256_nbpk_digest = hashlib.sha256(network_bitcoin_public_key_bytes).digest()
    sha256_2_nbpk_digest = hashlib.sha256(sha256_nbpk_digest).digest()
    sha256_2_hex = codecs.encode(sha256_2_nbpk_digest,'hex')
    checksum = sha256_2_hex[:8]
    address_hex = (network_bitcoin_public_key + checksum).decode('utf-8')
    wallet = base58(address_hex)
    return wallet


def base58(address_hex):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    b58_string = ''
    leading_zeros = len(address_hex) - len(address_hex.lstrip('0'))
    address_int = int(address_hex,16)
    while address_int > 0:
        digit = address_int % 58
        digit_char = alphabet[digit]
        b58_string = digit_char + b58_string
        address_int//=58
    ones = leading_zeros//2
    for one in range(ones):
        b58_string = '1' + b58_string
    return b58_string


def perform_step(obj, inMsgBuf):
    inMsg = mpc_crypto.messageFromBuf(inMsgBuf)

    outMsg, flags = mpc_crypto.step(obj.ctx, inMsg)
    mpc_crypto.freeMessage(inMsg)

    finished = flags & mpc_crypto.PROTOCOL_FINISHED_FLAG

    if flags & mpc_crypto.SHARE_CHANGED_FLAG:
        obj.setShare(mpc_crypto.getShare(obj.ctx))

    outMsgBuf = mpc_crypto.messageToBuf(outMsg)
    mpc_crypto.freeMessage(outMsg)
    return finished, outMsgBuf


def send_message(messageBuf):
    if not messageBuf:
        return
    length = len(messageBuf)
    clientsocket.send(struct.pack("!i", length))
    clientsocket.send(messageBuf)


def receive_message():
    rec = clientsocket.recv(4)
    length = struct.unpack("!i", rec)[0]
    chunks = []
    bytes_recd = 0
    while bytes_recd < length:
        chunk = clientsocket.recv(min(length - bytes_recd, 8192))
        if chunk == b'':
            raise RuntimeError("socket connection broken")
        chunks.append(chunk)
        bytes_recd = bytes_recd + len(chunk)
    return b''.join(chunks)


def exec_mpc_exchange(obj):
    finished = False
    messageBufIn = None
    messageBufOut = None
    while not finished:
        if peer == SERVER or messageBufOut:  # skip first receive by client
            messageBufIn = receive_message()

        finished, messageBufOut = perform_step(obj, messageBufIn)

        send_message(messageBufOut)


def run_eddsa_gen():
    print("Generating EDDSA key...")
    eddsaObj = mpc_crypto.Eddsa(peer)
    eddsaObj.initGenerate()
    exec_mpc_exchange(eddsaObj)
    print(" ok")
    return eddsaObj


def run_generate(cryptoType, size):
    print("Generating key...")
    if cryptoType == 'EDDSA':
        obj = mpc_crypto.Eddsa(peer)
        obj.initGenerate()
    elif cryptoType == 'ECDSA':
        obj = mpc_crypto.Ecdsa(peer)
        obj.initGenerate()
    elif cryptoType == 'generic':
        obj = mpc_crypto.GenericSecret(peer)
        obj.initGenerate(size)
    else:
        sys.exit("Generate not supported for " + cryptoType)
    with obj:
        exec_mpc_exchange(obj)
        print(" ok")
        return obj.exportShare()


def run_sign(inShare, cryptoType):
    print(cryptoType + " signing...")
    if not args.data_file:
        sys.exit("Input data missing")
    with open(args.data_file, "r") as f:
        filecontent = f.read()
        inData = bytes.fromhex(filecontent)

    if cryptoType == 'ECDSA':
        if len(inData) > 32:
            sys.exit("Input too long. Data should be hashed before ECDSA signing.")
        obj = mpc_crypto.Ecdsa(peer, inShare)
    elif cryptoType == 'EDDSA':
        obj = mpc_crypto.Eddsa(peer, inShare)
    else:
        sys.exit("Sign not supported for " + cryptoType)

    with obj:
        obj.initSign(inData)
        exec_mpc_exchange(obj)
        sig = obj.getSignResult()
    print("ok")
    return sig


def run_import(inShare, cryptoType='generic'):
    print("Importing key...")
    if not inShare:
        sys.exit("Input share missing")
    if cryptoType == 'generic':
        obj = mpc_crypto.GenericSecret(peer)
        obj.initImport(inShare)
    else:
        sys.exit("Import not supported for " + cryptoType)
    with obj:
        exec_mpc_exchange(obj)
        print(" ok")
        return obj.exportShare()


def run_derive(inShare, cryptoType='BIP32'):
    if cryptoType != 'BIP32':
        sys.exit("Derive not supported for " + args.type)
    srcObj = mpc_crypto.GenericSecret(peer, inShare)
    with srcObj:
        obj = mpc_crypto.Bip32(peer)
        with obj:
            obj.initDerive(srcObj, args.index, args.hardened)
            exec_mpc_exchange(obj)
            obj.getDeriveResult()
            return obj.exportShare()


def run_getpubkey(inShare, cryptoType):
    print("Getting public key...")

    if cryptoType == 'ECDSA':
        obj = mpc_crypto.Ecdsa(peer, inShare)
    elif cryptoType == 'EDDSA':
        obj = mpc_crypto.Eddsa(peer, inShare)
    else:
        sys.exit("getpubkey not supported for " + cryptoType)

    with obj:
        pk = obj.getPublic()
    print("ok")
    return pk


def run_verify(inShare, cryptoType):
    print("Verifying...")
    if not args.data_file:
        sys.exit("Input data missing")
    with open(args.data_file, "r") as f:
        filecontent = f.read()
        inData = bytes.fromhex(filecontent)

    if not args.sig_file:
        sys.exit("Signature file missing")
    with open(args.sig_file, "rb") as f:
        sigData = f.read()

    if cryptoType == 'ECDSA':
        obj = mpc_crypto.Ecdsa(peer, inShare)
    elif cryptoType == 'EDDSA':
        obj = mpc_crypto.Eddsa(peer, inShare)
    else:
        sys.exit("verify not supported for " + cryptoType)

    with obj:
        obj.verify(inData, sigData)
    print("ok")
    return 1

def run_command(params):
    inStr = None
    if args.in_file:
        with open(args.in_file, "rb") as f:
            inStr = f.read()
    if params.command == 'generate':
        out = run_generate(params.type, params.size)
        outFileDefault = params.type + '_share'
    elif params.command == 'import':
        out = run_import(inStr, params.type)
        outFileDefault = params.type + '_share'
    elif params.command == 'derive':
        out = run_derive(inStr, params.type)
        outFileDefault = params.type + '_derived'
    elif params.command == 'sign':
        out = run_sign(inStr, params.type)
        outFileDefault = params.type + '_signature'
    elif params.command == 'getpubkey':
        out = run_getpubkey(inStr, params.type)
        outFileDefault = params.type + '_pubkey'        
    elif params.command == 'verify':
        out = run_verify(inStr, params.type) 
        outFileDefault = params.type + '_verify'  
    outputFile = args.out_file if args.out_file else outFileDefault + \
        '_' + str(peer) + '.dat'
    return out, outputFile


def run_server():
    serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serversocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serversocket.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
    serversocket.bind((args.host, args.port))
    serversocket.listen(5)

    global clientsocket
    clientsocket, address = serversocket.accept()
    params = argparse.Namespace()
    while True:
        header = clientsocket.recv(3*4)
        if not header:
            break
        params.command = commands[struct.unpack("i", header[:4])[0]]
        params.type = types[struct.unpack("i", header[4:8])[0]]
        params.size = struct.unpack("i", header[8:])[0]
        # print(params)
        out, outputFile = run_command(params)

    if params.command != 'sign' and params.command != 'verify':  # only client receives the signature
        with open(outputFile, "wb" if params.command != 'getpubkey' else "w") as f:
            f.write(out if params.command != 'getpubkey' else out.hex())

    if params.command == 'getpubkey':
        pubkeyhexstr = out.hex()
        pubaddr = public_to_address(out.hex())
        print("btc testnet address: ", pubaddr)
        bitcoin.SelectParams("testnet")
        print("btc testnet ScriptPubKey: ", CBitcoinAddress(pubaddr).to_scriptPubKey().hex())
        print("btc pub key x: ", pubkeyhexstr[-128:-64])
        print("btc pub key y: ", pubkeyhexstr[-64:])

    clientsocket.close()


def run_client():
    global clientsocket
    clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    clientsocket.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
    clientsocket.connect((args.host, args.port))

    header = struct.pack("i", commands.index(args.command)) + \
        struct.pack("i", types.index(args.type)) + \
        struct.pack("i", args.size)
    startTime = datetime.datetime.now()
    for _ in range(args.repeat):
        clientsocket.send(header)
        out, outputFile = run_command(args)
    endTime = datetime.datetime.now()
    tookMs = (endTime - startTime).total_seconds() * 1000 / args.repeat
    tookStr = 'Took ' + str(tookMs) + ' ms'
    if args.repeat > 1:
        tookStr += ' on average'
    print(tookStr)

    if args.command != 'verify':
        with open(outputFile, "wb" if args.command != 'getpubkey' else "w") as f:
            f.write(out if args.command != 'getpubkey' else out.hex())
        clientsocket.close()
        if args.command == 'sign':
            print("contents wrote to file ", outputFile, " :", out.hex())
            example_sig = out.hex()
            r, s = dissect_signature(example_sig)
            print("r: %s\ns: %s\n" % (r, s))
            if int(s,16) > int("007FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0",16):
                print("large! please try again")

commands = ['generate', 'import', 'sign', 'derive', 'getpubkey', 'verify']
types = ['EDDSA', 'ECDSA', 'BIP32', 'generic']
parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter,
                                 conflict_handler='resolve',
                                 description='''Simple tester script.
                                  Executes queries from the test directry and compares with expected results''')

parser.add_argument('-h', '--host', default='localhost', help='Host name')
parser.add_argument('-p', '--port', default=15435,
                    type=int, help='MPC Server port')
parser.add_argument('-s', '--server', action='store_true',
                    help='Run MPC server')
parser.add_argument('-o', '--out_file', help='Output file name')
parser.add_argument('-i', '--in_file', help='Input file name')
parser.add_argument('-d', '--data_file', help='Data file name')
parser.add_argument('-g', '--sig_file', help='Signature file name')
parser.add_argument('-c', '--command', choices=commands, help='MPC Operation')
parser.add_argument('-t', '--type', choices=types, help='MPC Operation')
parser.add_argument('--hardened', action='store_true',
                    help='BIP32 derive parameter')
parser.add_argument('--index', type=int, default=0,
                    help='BIP32 derive parameter')
parser.add_argument('--size', type=int, default=256,
                    help='Size parameter')
parser.add_argument('--repeat', type=int, default=1,
                    help='Run the command N times to measure performance')


args = parser.parse_args()
if not args.server:
    if not args.command or not args.type:
        parser.error('Command and Type required for Client')
clientsocket = None
if args.server:
    peer = SERVER
    run_server()
else:
    peer = CLIENT
    run_client()
