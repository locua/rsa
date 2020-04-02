import binascii, sys, json
from helpers import *
from optparse import OptionParser

class RSA:
    """
        RSA class with encryption and decryption methods
    """
    def __init__(self):
        pass

    def encrypt(self, message, pub):
        print("message: ", message)
        m = self.string_to_int(message)
        block_size = None
        assert m < pub["n"]
        print("m: ", m)
        cipher = pow(m, pub["e"], pub["n"])
        print("c: " , cipher, "\n")
        return cipher

    def decrypt(self, c, d, pub):
        # m = c^d mod n
        assert c < pub["n"]
        plaintext = pow(c, d, pub["n"])
        return self.int_to_string(plaintext)

    def string_to_int(self, s):
        # https://stackoverflow.com/questions/12625627/python3-convert-unicode-string-to-int-representation

        # encode as utf-8, convert bytes to hexcodes as bytestring...
        # and convert to int specifying base 16(hex)
        i  = int(binascii.hexlify(s.encode('utf-8')), 16)
        #print(i)
        return i

    def int_to_string(self, i):
        # convert int to hex, unhexlify and decode
        return binascii.unhexlify(hex(i)[2:]).decode('utf-8')

    def generateKeys(self, keysize=870):
        # generate two large primes p and q (each approx 100 digits)
        p = generate_prime_number(keysize)
        #print(len(str(p)))
        q = generate_prime_number(keysize)
        #print(len(str(q)))
        # computer n = p*q
        n = p*q
        r = (p - 1) * (q - 1)
        print("SIZE OF r in bits", sys.getsizeof(r)*8)
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
        # keeps d private publish pair(e, n) {public key
        public = {"e" : e, "n": n}
        private = d
        return (public, private)


def main():
    # option argument parser
    # parser = argparse.ArgumentParser(description='Simple RSA implementation')
    parser = OptionParser()
    parser.add_option("-g", "--generate-keys", help="Generate public and private keys",action='store_true', dest='generate', default=False)
    parser.add_option("-e", "--encrypt",dest='message', default=None, help="encrypt message with public key. Takes message and public key file.")
    parser.add_option("-d", "--decrypt",dest='cipher_text', default=None, type='int', help="decrpyt message")
    # parser args
    (options, args)  = parser.parse_args()
    # rsa class
    rsa = RSA()
    # Generate keys
    if (options.generate==True):
        print("\nGenerating keys")
        print("----------------------------")
        public, private = rsa.generateKeys(300)
        # print("PUBLIC: ", public)
        # print("Private: ", private)
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
    elif (options.message!=None):
        print(options.message)
        filename='key_rsa.pub'
        with open(filename) as json_file:
            public = json.load(json_file)
            cipher = rsa.encrypt(options.message, public)
    # Decrypt
    elif (options.cipher_text!=None):
        filename_pub='key_rsa.pub'
        filename_private='key_rsa'
        with open(filename_pub) as public:
            public = json.load(public)
            with open(filename_private) as private:
                private = json.load(private)
                message=rsa.decrypt(options.cipher_text, private["private"], public)
                print(message)
    else:
        print("python3 rsa.py -h \n...to see use")

# execute main
if __name__ == "__main__":
    main()
