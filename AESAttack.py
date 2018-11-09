#!/usr/bin/env python2

import vulnerable

import datetime
import random
import sys

# Sorry for this mess.
# It _kinda_ works, though.
# TODO: Explain "kinda".
def main(argv):
    #ciphertext = argv[1]
    #desired_plaintext = argv[2]
    # For testing
    ciphertext = vulnerable.encr(43*'S')
    desired_plaintext = 'pwned'
    #
    cipher_bytes = map(ord, ciphertext)
    cipher_mod = cipher_bytes[0:16] + [random.randint(0x80, 0xff) for i in xrange(16)] + cipher_bytes[32:48]
    decr_out = []
    for n_pad in xrange(1, 17):
        #print(vulnerable.decr_dbg(''.join(map(chr, cipher_mod))))
        #print('--------------------------------------------')
        for bval in xrange(0, 256):
            cipher_mod[32 - n_pad] = bval
            if vulnerable.decr(''.join(map(chr, cipher_mod))) == "SUCCESS":
                decr_out.insert(0, bval^n_pad)
                cipher_mod[32 - n_pad:32] = [x^y for (x, y) in zip(decr_out, [n_pad + 1]*n_pad)]
                #print(vulnerable.decr_dbg(''.join(map(chr, cipher_mod))))
                #print('a')
                #print(decr_out)
                break
        #print(cipher_mod[16:32])
    desired_bytes = map(ord, desired_plaintext)
    #print(vulnerable.decr_dbg(''.join(map(chr, cipher_bytes))))
    cipher_bytes[32 - len(desired_bytes) - 1:31] = [x^y for (x, y) in zip(decr_out[16 - len(desired_bytes) - 1:15], desired_bytes)]
    cipher_bytes[31] = decr_out[15]^0x01
    #print(vulnerable.decr_dbg(''.join(map(chr, cipher_bytes))))
    #print(''.join(map(chr, [x^y for (x, y) in zip(decr_out, cipher_bytes[16:32])])))
    print(''.join(map(chr, cipher_bytes)))

if __name__ == "__main__":
    random.seed(datetime.datetime.now())
    main(sys.argv)
