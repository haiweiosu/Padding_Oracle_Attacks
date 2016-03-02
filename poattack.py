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

    #initialize padding index
    pad_index = 0

    #here, we define our IV as c0
    IV = list(c0)

    #looping through the IV and change its byte once a time till decryption function
    #return false
    for i in xrange(len(IV)):
        #We first start byte value for 01 then iterate 255 times to find the right one
        if ord(IV[i]) < 255:
            IV[i] = chr(ord(IV[i]) + 1)
        else:
            IV[i] = chr(1)

        #We can create our own personalize IV
        IV2 = "".join(IV)
        #then we decrypt the message and check the boolean result
        new_ctx = IV2 + c1
        res = po.decrypt(new_ctx)

        #If result is False then we know the length of padding and length of msg
        if res is False:
            pad_index = i
            break

    #initialize the padding byte
    pad_byte = len(c1) - pad_index

    #initialize the plain we want to get
    msg = [''] * pad_index

    #we now try to get the plain text msg one byte at a time
    for j in reversed(xrange(pad_index)):
        actual_pad_length = len(c1) - j
        new_iv = list(c0)
        old_iv = list(c0)

        for k in xrange(j + 1, len(c0)):
            if k >= pad_index:
                new_iv[k] = chr(ord(old_iv[k]) ^ pad_byte ^ actual_pad_length)
            else:
                new_iv[k] = chr(ord(old_iv[k]) ^ ord(msg[k]) ^ actual_pad_length)

        #since we don't know which value is the correct one, we loop through all 256 possible
        #values
        for i in xrange(256):
            new_iv[j] = chr(ord(old_iv[j]) ^ i ^ actual_pad_length)
            IV2 = ''.join(new_iv)
            temp = IV2+c1
            res = po.decrypt(temp)

            if res:
                msg[j] = chr(i)
                break
    # print ''.join(msg)
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
    # TODO: Implement padding oracle attack for arbitrary length message.
    msg = ''
    for i in range(nblocks - 1):
        msg = po_attack_2blocks(po, ctx_blocks[i])
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

test_po_attack()