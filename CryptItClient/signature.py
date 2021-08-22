from xeddsa.implementations import XEdDSA25519

def sign(privateKeyBytes, message):
    xeddsa = XEdDSA25519(mont_priv=privateKeyBytes)
    return xeddsa.sign(message)

def verify(publicKeyBytes, signature, message):
    xeddsa = XEdDSA25519(mont_pub=publicKeyBytes)
    return xeddsa.verify(message, signature)
