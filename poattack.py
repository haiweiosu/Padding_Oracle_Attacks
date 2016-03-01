from paddingoracle import PaddingOracle, PaddingOracleServer, xor
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import os
import binascii

def split_into_blocks(msg, l):
    while msg:
        yield msg[:l]
        msg = msg[l:]
    
def cbc_dec(key, ctx, iv):
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend()).decryptor()
    return decryptor.update(ctx) + decryptor.finalize()

def po_attack_2blocks(po, ctx):
    """Given two blocks of cipher texts, it can recover the first block of
    the message.
    @po: an instance of padding oracle. 
    @ctx: a ciphertext generated using po.setup()
    Don't unpad the message.
    """
    assert len(ctx) == 2*po.block_length, "This function only accepts 2 block "\
        "cipher texts. Got {} block(s)!".format(len(ctx)/po.block_length)
    c0, c1 = list(split_into_blocks(ctx, po.block_length))

    print binascii.b2a_hex(ctx)
    print binascii.b2a_hex(c0)
    print binascii.b2a_hex(c1)
    msg = xor(cbc_dec(po._key,c1,c0), c0)

    print binascii.b2a_hex(msg)

    return msg

def po_attack(po, ctx):
    """
    Padding oracle attack that can decrpyt any arbitrary length messags.
    @po: an instance of padding oracle. 
    @ctx: a ciphertext generated using po.setup()
    You don't have to unpad the message.
    """
    ctx_blocks = list(split_into_blocks(ctx, po.block_length))
    nblocks = len(ctx_blocks)
    # TODO: Implement padding oracle attack for arbitrary length message.
    for i in range(nblocks - 1):
        msg += po_attack_2blocks(po, ctx_blocks[i])
    return msg



    
################################################################################
##### Tests
################################################################################

def test_po_attack_2blocks():
    for i in xrange(1, 16):
        po = PaddingOracle(msg_len=i)
        ctx = po.setup()
        msg = po_attack_2blocks(po, ctx)
        assert po.test(msg), "Failed 'po_attack_2blocks' for msg of length={}".format(i)

def test_po_attack():
    for i in xrange(1000):
        po = PaddingOracle(msg_len=i)
        ctx = po.setup()
        msg = po_attack(po, ctx)
        assert po.test(msg), "Failed 'po_attack' for msg of length={}".format(i)

def test_poserver_attack():
    # You may want to put some print statement in the code to see the
    # progress. This attack might 10.218.176.10take upto an hour to complete. 

    po = PaddingOracleServer()
    ctx = po.ciphertext()
    msg = po_attack(po, ctx)
    print msg

test_po_attack_2blocks()