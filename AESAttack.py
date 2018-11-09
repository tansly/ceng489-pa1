#!/usr/bin/env python2

import vulnerable

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
    print(cipher_mod)
    decr_out = []
    for i in xrange(31, 15, -1):
        orig_byte = cipher_bytes[i]
        for bval in xrange(0, 0xff):
            cipher_mod[i] = bval
            if vulnerable.decr(''.join(map(chr, cipher_mod))) == "SUCCESS":
                decr_out.append(bval^0x01^orig_byte)
                cipher_mod[i] = decr_out[-1]^0x02
                print(decr_out)

if __name__ == "__main__":
    main(sys.argv)
