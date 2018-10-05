import os
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from master_sign import get_private_key


# check the file or key in file is valid
def verify_key(fn):
    if os.path.exists(os.path.join(fn)):
        # read RSA key
        fc = open(os.path.join(fn), "r").read()
        try:
            # check key
            key = RSA.importKey(fc)
            return True
        except ValueError or IndexError or TypeError:
            # not a valid key
            return False
    else:
        # file not exist
        return False


def decrypt_valuables(f):
    # TODO: For Part 2, you'll need to decrypt the contents of this file
    # The existing scheme uploads in plaintext
    # As such, we just convert it back to ASCII and print it out
    if verify_key("PriKey.pem"):
        # get key
        prikey = get_private_key()

        # decrypt file
        cipher = PKCS1_OAEP.new(prikey)
        try:
            plaintest = cipher.decrypt(f[256:])
            print(plaintest)
        except ValueError or AttributeError:
            print("The file has not been signed by the botnet master")



if __name__ == "__main__":
    fn = input("Which file in pastebot.net does the botnet master want to view? ")
    if not os.path.exists(os.path.join("pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        os.exit(1)
    f = open(os.path.join("pastebot.net", fn), "rb").read()
    decrypt_valuables(f)
