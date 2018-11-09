#!/usr/bin/env python2

import vulnerable

import datetime
import random
import sys

def main(argv):
    #ciphertext = argv[1]
    #desired_plaintext = argv[2]
    # For testing
    ciphertext = vulnerable.encr(47*'a')
    desired_plaintext = 'abcd'
    #
    cipher_bytes = map(ord, ciphertext)
    cipher_mod = cipher_bytes[0:16] + [random.randint(0x80, 0xff) for i in xrange(16)] + cipher_bytes[32:48]
    decr_out = []
    for n_pad in xrange(1, 16):
        #print(vulnerable.decr_dbg(''.join(map(chr, cipher_mod))))
        #print('--------------------------------------------')
        for bval in xrange(0, 256):
            cipher_mod[32 - n_pad] = bval
            if vulnerable.decr(''.join(map(chr, cipher_mod))) == "SUCCESS":
                decr_out.insert(0, bval^n_pad)
                cipher_mod[32 - n_pad:32] = [x^y for (x, y) in zip(decr_out, [n_pad + 1]*n_pad)]
                #print(vulnerable.decr_dbg(''.join(map(chr, cipher_mod))))
                #print('a')
                print(decr_out)
                break
        #print(cipher_mod[16:32])

if __name__ == "__main__":
    random.seed(datetime.datetime.now())
    main(sys.argv)
