from xeddsa.implementations import XEdDSA25519

# Returns the signature of the given message signed with XEdDSA25519
def sign(privateKeyBytes, message):
    xeddsa = XEdDSA25519(mont_priv=privateKeyBytes)
    return xeddsa.sign(message)

# Verifies the signature given the key and message. Returns a boolean
def verify(publicKeyBytes, signature, message):
    xeddsa = XEdDSA25519(mont_pub=publicKeyBytes)
    return xeddsa.verify(message, signature)
