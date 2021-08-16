from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from Cryptodome.Protocol.KDF import HKDF
from Cryptodome.Hash import HMAC, SHA256


def HKDFRootKey(rootKey, DHOut):
    out = HKDF(DHOut, 64, rootKey, SHA256, 1)
    return out[:32], out[32:]

def HKDFChainKey(chainKey):
    chainKeyNextInput = HMAC.new(chainKey, digestmod=SHA256).update(b'\x01').digest()
    messageKey = HMAC.new(chainKey, digestmod=SHA256).update(b'\x02').digest()
    return chainKeyNextInput, messageKey

# Authenticated encryption with additional data
def encrypt(key, plaintext, associatedData):
    # TODO : create this function
    return

def decrypt(key, ciphertext, associatedData):
    # TODO
    return

def createHeader(DHPair, previousN, sendN):
    # TODO
    return

class DoubleRatchetClient(object):
    def __init__(self):
        self.keyRing = {}

    def createKeyRing(self, username, rootKey, DHSendingPair, DHReceivingKey, sendChainKey):
        self.keyRing[username] = {
        'rootKey': rootKey,
        'DHSendingPair': DHSendingPair,
        'DHReceivingKey': DHReceivingKey,
        'sendChainKey': sendChainKey,
        'readChainKey': None,
        'sendN': 0,
        'readN': 0,
        'previousN': 0
        }

    def initiateDoubleRatchetSender(self, username, sharedSecret, publicKey):
        DHPrivate = X25519PrivateKey.generate()
        DHSendingPair = [DHPrivate, DHPrivate.public_key()]
        DHReceivingKey = publicKey
        key = HKDFRootKey(sharedSecret, DHPair)
        rootKey = key
        sendChainKey = key
        self.createKeyRing(username, rootKey, DHSendingPair, DHReceivingKey, sendChainKey)

    def initiateDoubleRatchetReceiver(self, username, sharedSecret, keyPair):
        DHSendingPair = keyPair
        rootKey = sharedSecret
        self.createKeyRing(username, DHSendingPair, None, None)

    def ratchetEncrypt(self, username, plaintext, ad):
        keyRing = self.keyRing[username]
        keyRing['sendChainKey'], messageKey = HKDFChainKey(keyRing['sendChainKey'])
        header = createHeader(keyRing['DHSendingPair'], keyRing['previousN'], keyRing['sendN'])
        keyRing['sendN'] += 1
        return header, encrypt(messageKey, plaintext, ad+header) # ad + header = concat(ad, header)

    def ratchetDecrypt(self, username, header, ciphertext, ad):
        #TODO
        keyRing = self.keyRing[username]
        keyRing['readChainKey'], messageKey = HKDFChainKey(keyRing['readChainKey'])
        keyRing['readN'] += 1
        return decrypt(messageKey, ciphertext, CONCAT(ad, header))
