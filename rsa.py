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
        """ Encrypt message.
            Takes:
                  - message
                  - public key
                  - block size
             Returns cipher and saves to file cipher.json
        """
        # message=message.strip()
        if (len(message)<blocksize):
            blocksize=len(message)//2
        # Split message into blocks and store
        msplit = [message[i:i+blocksize] for i in range(0,len(message), blocksize)]
        # Initialise cipher and block lengths
        cipher=""
        blengths=[]
        # Loop over splits
        for m in msplit:
            # convert string to int
            m = self.string_to_int(m)
            # Assert block is less than public key n value
            if (m > pub["n"]):
                print("Please make the p and q size bigger or blocksize smaller")
                assert m < pub["n"]
            # Encrypt block
            c_ = pow(m, pub["e"], pub["n"])
            # Convert to string
            c_=str(c_)
            # store block length
            blengths.append(len(c_))
            # Append cipher string to final string
            cipher+=c_
        # Store cipher and block lengths in dictionary
        cipherfull={"cipher":cipher, "block_lengths":blengths}
        # Write to cipher.json file
        with open("cipher.json", "w") as outfile:
            json.dump(cipherfull, outfile)
        # Return cipher
        return cipherfull

    def decrypt(self, cipher, d, pub):
        """ Decrypt RSA cipher
                Takes:
                      - cipher
                      - private key
                      - public key
                 Returns: decrypted message and saves to file decrypted.txt
        """
        # Get cipher and block lengths from cipher dict
        ciphertext=cipher["cipher"]
        blengths=cipher["block_lengths"]
        # Cumulative block length
        cum_blength=0
        plainout=''
        # Loop over block lengths
        for i, blength in enumerate(blengths):
            # Split ciphertext into blocks
            if(i==0):
                c=ciphertext[:blength]
            elif(i==len(blengths)-1):
                c=ciphertext[cum_blength:]
            else:
                c=ciphertext[cum_blength:cum_blength+blength]
            # Increment cumulative block lengths
            cum_blength+=blength
            # Convert each cipher block to an int
            c=int(c)
            # Decrypt
            plaintext = self.int_to_string(pow(c, d, pub["n"]))
            # print(plaintext)
            plainout+=plaintext
        # Write decrypted text to file
        outfile=open("decrypted.txt", "w")
        outfile.write(plainout)
        # Return decrypted message
        return plainout

    def string_to_int(self, s):
        """ Encode string as integer """
        # https://stackoverflow.com/questions/12625627/python3-convert-unicode-string-to-int-representation
        # encode as utf-8, convert bytes to hexcodes as bytestring...
        # and convert to int specifying base 16(hex)
        i  = int(binascii.hexlify(s.encode('utf-8')), 16)
        return i

    def int_to_string(self, i):
        """ Decodes integer as string """
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
        """ Generate keys
                Takes:
                   - pqsize, Set size of p and q
                Returns public and private keys
        """
        # generate two large primes p and q (each approx 100 digits)
        p = generate_prime_number(pqsize)
        q = generate_prime_number(pqsize)
        # Computer n = p*q
        n = p*q
        # Compute r
        r = (p - 1) * (q - 1)
        # choose large random number e: 1 < e < r
        e = randbelow(r)
        #Use Euclid's Algorithm to verify that e and phi(n) are comprime
        g = math.gcd(e, r)
        while g != 1:
            e = randbelow(r)
            g = math.gcd(e, r)
        # Compute d
        d = modinv(e, r)
        # print size of keys
        print("Size of d in bits", sys.getsizeof(d)*8)
        print("Size of e in bits", sys.getsizeof(e)*8)
        print("Size of n in bits", sys.getsizeof(n)*8)
        # Store private and public keys
        public = {"e" : e, "n": n}
        private = d
        # Return keys
        return (public, private)


def main():
    # option argument parser
    parser = OptionParser()
    parser.description = "Simple command line program for RSA encryption"
    # Add command line options
    parser.add_option("-g", "--generate-keys", help="Generate public and private keys optionally specify the size of p and q with --pqsize",action='store_true', dest='generate', default=False)
    parser.add_option("-p", "--pqsize", help="Specify the size of p and q", dest='pqsize', type='int')
    parser.add_option("-e", "--encrypt",dest='message_file', default=None, help="encrypt message in file")
    parser.add_option("-d", "--decrypt",dest='cipher_file', default=None, help="decrpyt message")
    parser.add_option("-f", "--loadkey/s",dest='filenames', help="Load key files")
    # parser args
    (options, args)  = parser.parse_args()
    # rsa class
    rsa = RSA()
    # Generate keys; parse -g option and arguments
    if (options.generate==True):
        pqsize=380
        if(options.pqsize!=None):
            pqsize=options.pqsize
        print("\nGenerating keys")
        print("----------------------------")
        # Generate keys
        public, private = rsa.generateKeys(pqsize)
        with open("key_rsa.pub", 'w') as outfile:
            json.dump(public, outfile)
        private={"private":private}
        with open("key_rsa", "w") as outfile:
            json.dump(private, outfile)
        # Print message
        print("----------------------------")
        print("Generated keys!")
        print("Public key stored in key_rsa.pub")
        print("Private key stored in key_rsa.", "Keep this secret!")
        print("----------------------------\n")
    # Encrypt parse -e arguments
    elif (options.message_file!=None):
        if(options.filenames):
            with open(options.filenames) as json_file:
                with open(options.message_file) as plaintext:
                    # Load and read plaintext
                    m = plaintext.read()
                    public = json.load(json_file)
                    # Encrypt
                    cipher = rsa.encrypt(m, public)
                    # print message
                    print("----------------------------")
                    print("Generated file cipher.json")
                    print("----------------------------\n")
        else:
            # Print error message
            print("----------------------------")
            print("Also requires you to specifiy a file containing public key using -f")
            print("----------------------------\n")
    # Decrypt
    elif (options.cipher_file!=None):
        if(options.filenames):
            filename_pub=options.filenames
            if (args):
                filename_private=args[0]
            else:
                print("----------------------------")
                print("ERROR please specify filename key private key.\n Eg. \n -f key_rsa.pub key_rsa")
                print("----------------------------\n")
                sys.exit(1)
            with open(filename_pub) as public:
                # Load keys and cipher
                public = json.load(public)
                with open(filename_private) as private:
                    with open(options.cipher_file) as ciphertext:
                        # Load cipher
                        c=json.load(ciphertext)
                        private = json.load(private)
                        # Decrypt
                        message=rsa.decrypt(c, private["private"], public)
                        print("Decrypted message and written to file decrypted.txt")
                        # with open("decrypted.txt", "w") as decrypted:
                            # decrypted.write(message)
        else:
            # Print error
            print("----------------------------")
            print("-----------------------\nERROR")
            print("Specifiy filenames for public and private keys")
            print("----------------------------\n")
    # No options given
    else:
        print("run: python3 rsa.py -h \n...to see use")

# execute main
if __name__ == "__main__":
    main()
