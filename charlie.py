#!/usr/bin/env python3

import math,binascii,time,optparse,json

def int_to_string(i):
    # convert int to hex, unhexlify and decode
    return binascii.unhexlify(hex(i)[2:]).decode('utf-8')

def brute(d, n, c):
    m=None
    while m is None:
        print(d)
        try:
            m = int_to_string(pow(c, d, n))
        except:
            pass
        d += 1

        time.sleep(.00001)
    print("d: ", d)
    print("m: ", m)

def main():
    m = None
    parser=optparse.OptionParser()
    parser.description="Brute force guess private key"
    parser.add_option("-m", dest="args",nargs=2,help="Specifiy cipher text to decrypt and public key")

    (options, args) = parser.parse_args()

    if(options.args):
        # print(options.args)
        c=open(options.args[0], "r")
        cipher=json.load(c)
        k=open(options.args[1], "r")
        public_key=json.load(k)
        print(cipher)
        print("PUBLIC KEY:")
        print(public_key)

        brute(0, public_key['n'], cipher["cipher"])
    else:
        print("Specify ciphertext and public key with -m")

    # brute()

# execute main
if __name__ == "__main__":
    main()
