import os
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
from Crypto.Signature import PKCS1_PSS


# create private and public key of RAS
def create_keys():

        pri = os.path.join("PriKey.pem")
        pub = os.path.join("PubKey.pem")
        # create new RSA key
        prikey = RSA.generate(2048)
        pubkey = prikey.publickey()
        try:
            prikfile = open(pri, 'wb')
            pubkfile = open(pub, 'wb')
            prikfile.write(prikey.exportKey('PEM'))
            pubkfile.write(pubkey.exportKey('PEM'))
        except IOError:
            os.remove(pri)
            os.remove(pub)
        else:
            prikfile.close()
            pubkfile.close()
        return prikey, pubkey

def get_private_key():
    if os.path.exists(os.path.join("PriKey.pem")):
        # read RSA key
        file = open(os.path.join("PriKey.pem"), "rb+")
        fc = file.read()
        # empty key
        try:
            pri = RSA.importKey(fc)
        except ValueError or IndexError or TypeError:
            pri, pub = create_keys()
        file.close()
    else:
        # create new RSA key
        pri, pub = create_keys()
    return pri


def get_public_key():
    if os.path.exists(os.path.join("PubKey.pem")):
        # read RSA key
        file = open(os.path.join("PubKey.pem"), "rb+")
        fc = file.read()
        # empty key
        try:
            pub = RSA.importKey(fc)
        except ValueError or IndexError or TypeError:
            pri, pub = create_keys()
        file.close()
    else:
        # create new RSA key
        pri, pub = create_keys()
    return pub


def sign_file(f):
    # TODO: For Part 2, you'll use public key crypto here
    # The existing scheme just ensures the updates start with the line 'Caesar'
    # This is naive -- replace it with something better!
    prikey = get_private_key()

    # sign file
    h = SHA.new()
    h.update(f)
    signer = PKCS1_PSS.new(prikey)
    # signature is 256 bytes long
    signature = signer.sign(h)
    # 0-255:signature ; 256-end:cipher text
    return signature + f


if __name__ == "__main__":
    fn = input("Which file in pastebot.net should be signed? ")
    if not os.path.exists(os.path.join("pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        os.exit(1)
    f = open(os.path.join("pastebot.net", fn), "rb").read()
    signed_f = sign_file(f)
    signed_fn = os.path.join("pastebot.net", fn + ".signed")
    out = open(signed_fn, "wb")
    out.write(signed_f)
    out.close()
    print("Signed file written to", signed_fn)
