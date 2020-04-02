#!/usr/bin/env python3

import math,binascii,time,optparse

def int_to_string(i):
    # convert int to hex, unhexlify and decode
    return binascii.unhexlify(hex(i)[2:]).decode('utf-8')

def brute(m, d, n):
    while m is None:
        print(d)
        try:
            m = int_to_string(pow(c, d, n))
        except:
            pass
        d += 1

        # time.sleep(.0001)
    print(m)

def main():
    m = None
    parser=optparse.OptionParser()
    parser.description="Brute force guess private key"
    parser.add_option("-m", dest="args",nargs=2,help="Specifiy cipher text to decrypt and public key")

    (options, args) = parser.parse_args()

    if(options.args):
        print(options.args)
        c=open(options.args[0], "r")
        cipher=c.read()
        k=open(options.args[1], "r")
        public_key=k.read()
        print(cipher)
        print(public_key)
    else:
        print("")

    # brute()

# execute main
if __name__ == "__main__":
    main()
