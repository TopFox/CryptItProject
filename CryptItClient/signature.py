from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from Cryptodome.Random import get_random_bytes

def sign(privateKeyBytes, message):
    return get_random_bytes(64)

def verify(a,b,c):
    return True

"""
Pour l'instant, ne fonctionne pas (clefs ed25519 non compatible x25519):

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

def sign(privateKeyBytes, message):
    privateKey = Ed25519PrivateKey.from_private_bytes(privateKeyBytes)
    return privateKey.sign(message)

def verify(publicKeyBytes, signature, message):
    print(signature)
    publicKey = Ed25519PublicKey.from_public_bytes(publicKeyBytes)
    try:
        publicKey.verify(signature, message)
        return True
    except Exception:
        return False

private_key = Ed25519PrivateKey.generate()
signature = private_key.sign(b"my authenticated message")
public_key = private_key.public_key()
public_key.verify(signature, b"my authenticated message")
"""
