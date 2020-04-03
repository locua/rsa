#!/usr/bin/env python3
import binascii, sys, json
from optparse import OptionParser
from helpers import *

class RSA:
    """
        RSA class with encryption and decryption methods
    """
    def __init__(self):
        pass

    def encrypt(self, message, pub, blocksize=30):
        # message=message.strip()
        if (len(message)<blocksize):
            blocksize=len(message)//2
        msplit = [message[i:i+blocksize] for i in range(0,len(message), blocksize)]
        cipher=""
        blengths=[]
        for m in msplit:
            m = self.string_to_int(m)
            if (m > pub["n"]):
                print("Please make the p and q size bigger or blocksize smaller")
                assert m < pub["n"]
            c_ = pow(m, pub["e"], pub["n"])
            c_=str(c_)
            blengths.append(len(c_))
            cipher+=c_
        cipherfull={"cipher":cipher, "block_lengths":blengths}
        with open("cipher.json", "w") as outfile:
            json.dump(cipherfull, outfile)
        return cipherfull

    def decrypt(self, cipher, d, pub):
        ciphertext=cipher["cipher"]
        blengths=cipher["block_lengths"]
        # Cumulative block length
        cum_blength=0
        plainout=''
        for i, blength in enumerate(blengths):
            # Splitting ciphertext into blocks
            if(i==0):
                c=ciphertext[:blength]
            elif(i==len(blengths)-1):
                c=ciphertext[cum_blength:]
            else:
                c=ciphertext[cum_blength:cum_blength+blength]
            cum_blength+=blength
            c=int(c)
            # Decrypt
            plaintext = self.int_to_string(pow(c, d, pub["n"]))
            # print(plaintext)
            plainout+=plaintext
        # outfile=open("decrypted.txt", "w")
        # outfile.write(plainout)
        return plainout

    def string_to_int(self, s):
        # https://stackoverflow.com/questions/12625627/python3-convert-unicode-string-to-int-representation

        # encode as utf-8, convert bytes to hexcodes as bytestring...
        # and convert to int specifying base 16(hex)
        i  = int(binascii.hexlify(s.encode('utf-8')), 16)
        return i

    def int_to_string(self, i):
        # Convert to hex and check for odd string length
        n = hex(i)[2:]
        # if odd length pad with zero and return decoded string
        if((len(n)%2)!=0):
            n = '0%x'%int(n, 16)
            return binascii.unhexlify(n).decode('utf-8')
        else:
            # return decoded string
            return binascii.unhexlify(hex(i)[2:]).decode('utf-8')

    def generateKeys(self, pqsize=870):
        # generate two large primes p and q (each approx 100 digits)
        p = generate_prime_number(pqsize)
        #print(len(str(p)))
        q = generate_prime_number(pqsize)
        #print(len(str(q)))
        # computer n = p*q
        n = p*q
        r = (p - 1) * (q - 1)
        # print("SIZE OF r in bits", sys.getsizeof(r)*8)
        # choose large prime e: 1 < e < r
        e = randbelow(r)
        e = 11
        #Use Euclid's Algorithm to verify that e and phi(n) are comprime
        g = math.gcd(e, r)
        while g != 1:
            e = randbelow(r)
            g = math.gcd(e, r)

        d = modinv(e, r)
        print("Size of d in bits", sys.getsizeof(d)*8)
        print("Size of e in bits", sys.getsizeof(e)*8)
        print("Size of n in bits", sys.getsizeof(n)*8)
        # keeps d private publish pair(e, n) {public key
        public = {"e" : e, "n": n}
        private = d
        return (public, private)


def main():
    # option argument parser
    parser = OptionParser()
    parser.description = "Simple command line program for RSA encryption"
    parser.add_option("-g", "--generate-keys", help="Generate public and private keys optionally specify the size of p and q with --pqsize",action='store_true', dest='generate', default=False)
    parser.add_option("-p", "--pqsize", help="Specify the size of p and q", dest='pqsize', type='int')
    parser.add_option("-e", "--encrypt",dest='message_file', default=None, help="encrypt message in file")
    parser.add_option("-d", "--decrypt",dest='cipher_file', default=None, help="decrpyt message")
    parser.add_option("-f", "--loadkey/s",dest='filenames', help="Load key files")
    # parser args
    (options, args)  = parser.parse_args()
    # rsa class
    rsa = RSA()
    # Generate keys
    if (options.generate==True):
        pqsize=380
        if(options.pqsize!=None):
            pqsize=options.pqsize
        print("\nGenerating keys")
        print("----------------------------")
        public, private = rsa.generateKeys(pqsize)
        with open("key_rsa.pub", 'w') as outfile:
            json.dump(public, outfile)
        private={"private":private}
        with open("key_rsa", "w") as outfile:
            json.dump(private, outfile)
        print("----------------------------")
        print("Generated keys!")
        print("Public key stored in key_rsa.pub")
        print("Private key stored in key_rsa.", "Keep this secret!")
        print("----------------------------\n")
    # Encrypt
    elif (options.message_file!=None):
        if(options.filenames):
            with open(options.filenames) as json_file:
                with open(options.message_file) as plaintext:
                    m = plaintext.read()
                    public = json.load(json_file)
                    cipher = rsa.encrypt(m, public)
                    print("Generated file cipher.json")
        else:
            print("Also requires you to specifiy a file containing public key using -f")
    # Decrypt
    elif (options.cipher_file!=None):
        if(options.filenames):
            filename_pub=options.filenames
            if (args):
                filename_private=args[0]
            else:
                print("ERROR please specify filename key private key.\n Eg. \n -f key_rsa.pub key_rsa")
                sys.exit(1)
            with open(filename_pub) as public:
                public = json.load(public)
                with open(filename_private) as private:
                    with open(options.cipher_file) as ciphertext:
                        c=json.load(ciphertext)
                        private = json.load(private)
                        message=rsa.decrypt(c, private["private"], public)
                        with open("decrypted.txt", "w") as decrypted:
                            print("Decrypted message and written to file decrypted.txt")
                            decrypted.write(message)
        else:
            print("-----------------------\nERROR")
            print("Specifiy filenames for public and private keys")
    # No options given
    else:
        print("run: python3 rsa.py -h \n...to see use")

# execute main
if __name__ == "__main__":
    main()
