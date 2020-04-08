#!/usr/bin/env python3

import math,binascii,time,optparse,json,secrets,random

def int_to_string(i):
    # convert int to hex, unhexlify and decode
    return binascii.unhexlify(hex(i)[2:]).decode('utf-8')

def string_to_int(s):
    # https://stackoverflow.com/questions/12625627/python3-convert-unicode-string-to-int-representation
    # encode as utf-8, convert bytes to hexcodes as bytestring...
    # and convert to int specifying base 16(hex)
    i  = int(binascii.hexlify(s.encode('utf-8')), 16)
    return i

def brute(d, pub):
    """ Attempts to guess private key"""
    # Test message
    print("--------------------------------------------------------------------------------------------")
    print("---------------- Cipher test message -------------------------------------------------------")
    print("--------------------------------------------------------------------------------------------")
    # Encrypt test message m
    m=string_to_int("H")
    c_ = pow(m, pub["e"],pub["n"])
    print("------------- c: ", c_)
    print("--------------------------------------------------------------------------------------------")
    print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>BRUTE FORCING Guessing private key>>>>>>>>>>>>>>>>>>>>>>")
    print("--------------------------------------------------------------------------------------------")
    # set correct guess to None
    m_correct=None
    # number of trys
    trys=0
    d = 0
    print(m)
    while True:
        # Random d guess
        #d = secrets.randbits(10)
        d= secrets.randbelow(pub["n"])
        # print(d)
        # Attempt decryption
        m_try = pow(c_, d, pub["n"])
        # If decryption works
        if(m==m_try):
            # set m_correct to value
            m_correct=m_try
            print("--------------------------------------------------------------------------------------------")
            print("------------------------ FOUND key ---------------------------------------------------------")
            print("--------------------------------------------------------------------------------------------")
            print("----------------------------------------------------- private key d ------------------------")
            print("------------ d: ", d)
            print("--------------------------------------------------------------------------------------------")
            time.sleep(1)
        # increment number of trys
        trys+=1
        #d+=1
        ######## print trys
        print("----------------- Number of trys %s -------------"% trys, end="\r")
    ############### print success message ###############


def main():
    # Command line optinos parser
    m = None
    # Options parser
    parser=optparse.OptionParser()
    parser.description="Brute force guess private key"
    # Add option
    parser.add_option("-m", dest="filename",help="Specifiy cipher text to decrypt and public key")
    # parse args and get options and arguments
    (options, args) = parser.parse_args()
    # If options -m
    if(options.filename):
        # open public key file
        k=open(options.filename, "r")
        public_key=json.load(k)
        print("PUBLIC KEY:")
        print(public_key)
        # pass to brute function
        brute(0, public_key )
    else:
        print("Specify ciphertext and public key with -m")

# execute main
if __name__ == "__main__":
    main()
