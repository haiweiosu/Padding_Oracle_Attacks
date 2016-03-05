"""
CS-5830: Homework 2
Padding Oracle Attack

Daniel Speiser and Haiwei Su
"""
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

def po_attack_2blocks(po, ctx, padding=True):
    """Given two blocks of cipher texts, it can recover the first block of
    the message.
    @po: an instance of padding oracle. 
    @ctx: a ciphertext generated using po.setup()
    Don't unpad the message.
    """
    assert len(ctx) == 2*po.block_length, "This function only accepts 2 block "\
        "cipher texts. Got {} block(s)!".format(len(ctx)/po.block_length)
    c0, c1 = list(split_into_blocks(ctx, po.block_length))

    #initialize padding index and byte
    pad_idx, pad_byte = 16, 1
    #initialize the plain we want to get
    msg = [''] * po.block_length
    # if there's padding, we must determine where it begins
    if padding:
        for i in range(len(c0)): # loop through ciphertext
            # increment current c0 index by 1 (modulo 255 so we deal with overflow issues) to find where padding begins
            new_c0 = c0[:i] + chr((ord(c0[i]) + 1) % 256) + c0[i + 1:]
            # if the decrypt fails, we know we've changed a padding value. Now we know where padding begins
            if not po.decrypt(new_c0 + c1):
                pad_idx, pad_byte = i, len(c0) - i # store padding index and byte
                break # break
    else: 
    # otherwise handle possible special case where padding would return true, although there may be
    # two possible options for a byte value (example is force last byte to 0x01, po returns true, but the 
    # second to last byte could be 0x02, and we accidentally changed the last byte to 0x02 and returned true)
    # There exists one edge case for each byte index.
        for i in range(256):
            # attempt to force first byte to 1
            new_c0 = c0[:-1] + chr(ord(c0[-1]) ^ i ^ 1)
            if po.decrypt(new_c0 + c1): # if returns true, check previous byte
                previous_byte = chr(ord(c0[-2]) ^ 1) # flip byte and check
                new_c0 = c0[:-2] + previous_byte + new_c0[-1]
                if po.decrypt(new_c0 + c1):
                    msg[-1] = chr(i) # set last index of msg array to this confirmed byte
                    break

    # we now try to get the plain text msg one byte at a time
    for j in reversed(xrange(pad_idx)):
        pad_len = len(c1) - j # current length of pad 
        new_iv = list(c0)
        old_iv = list(c0)
        # if the index is at a position of padding byte that has been used, we xor the 
        # original with the current pad, otherwise we xor the index byte and current pad
        for k in xrange(j + 1, len(c0)):
            if k >= pad_idx:
                new_iv[k] = chr(ord(old_iv[k]) ^ pad_byte ^ pad_len)
            else:
                new_iv[k] = chr(ord(old_iv[k]) ^ ord(msg[k]) ^ pad_len)
        #since we don't know which value is the correct one, we loop through all 256 possible values
        for i in xrange(256):
            new_iv[j] = chr(ord(old_iv[j]) ^ i ^ pad_len)
            IV = ''.join(new_iv)
            if po.decrypt(IV + c1):
                msg[j] = chr(i)
                break
    return ''.join(msg)

def po_attack(po, ctx):
    """
    Padding oracle attack that can decrpyt any arbitrary length messags.
    @po: an instance of padding oracle. 
    @ctx: a ciphertext generated using po.setup()
    You don't have to unpad the message.
    """
    ctx_blocks = list(split_into_blocks(ctx, po.block_length))
    nblocks = len(ctx_blocks)
    # initialize empty msg array
    msg = ['']
    # attack 2 blocks at a time, up until the last 2 blocks (where we know the last has padding)
    for i in range(nblocks - 2):
        msg += po_attack_2blocks(po, ctx_blocks[i] + ctx_blocks[i + 1], padding=False)
    # handle the case with padding (padding param is defaulted to true) and append result to msg
    msg += po_attack_2blocks(po, ctx_blocks[-2] + ctx_blocks[-1])
    return ''.join(msg)

################################################################################
##### Tests
################################################################################

def test_po_attack_2blocks():
    for i in xrange(1, 16):
        po = PaddingOracle(msg_len=i)
        ctx = po.setup()
        msg = po_attack_2blocks(po, ctx)
        print "{0}: {1}".format(i, binascii.b2a_hex(msg))
        assert po.test(msg), "Failed 'po_attack_2blocks' for msg of length={}".format(i)

def test_po_attack():
    for i in xrange(1000):
        po = PaddingOracle(msg_len=i)
        ctx = po.setup()
        msg = po_attack(po, ctx)
        if i > 1:
            print "{0}: {1}".format(i, binascii.b2a_hex(msg))
        else:
            print "{0}: {1}".format(i, msg)
        assert po.test(msg), "Failed 'po_attack' for msg of length={}".format(i)

def test_poserver_attack():
    po = PaddingOracleServer()
    ctx = po.ciphertext()
    msg = po_attack(po, ctx)
    print msg

test_po_attack()

# Recovered plaintext from server-side po attack:
# {"msg": "Congrats you have cracked a secret message!", "name": "Padding Oracle"}