from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from Cryptodome.Protocol.KDF import HKDF
from Cryptodome.Hash import HMAC, SHA256


def generateDH():
    DHPrivate = X25519PrivateKey.generate()
    return [DHPrivate, DHPrivate.public_key()]

def DH(DHPair, DHPublic):
    DHPrivate = DHPair[0]
    return DHPrivate.exchange(DHPublic)

def HKDFRootKey(rootKey, DHOut):
    out = HKDF(DHOut, 64, rootKey, SHA256)
    return out[:32], out[32:]

def HKDFChainKey(chainKey):
    chainKeyNextInput = HMAC.new(chainKey, digestmod=SHA256).update(b'\x01').digest()
    messageKey = HMAC.new(chainKey, digestmod=SHA256).update(b'\x02').digest()
    return chainKeyNextInput, messageKey

# Authenticated encryption with additional data
def encrypt(mk, plaintext, associatedData):
    # TODO : create this function
    key = HKDF(mk, 80, b'\0'*80, SHA256)
    encryptionKey = key[:32]
    authenticationKey= key[32:64]
    iv = key[64:]
    cipher = AES.new(encryptionKey, AES.MODE_CBC, iv=iv)
    ciphertext = cipher.encrypt(pad(plaintext, 16, style='pkcs7'))
    hmac = HMAC.new(authenticationKey, digestmod=SHA256).update(associatedData).digest()
    return ciphertext + hmac

def decrypt(mk, ciphertextAndHMAC, associatedData):
    ciphertext = ciphertextAndHMAC[:-256]
    hmac = ciphertextAndHMAC[-256:]
    key = HKDF(mk, 80, b'\0'*80, SHA256)
    encryptionKey = key[:32]
    authenticationKey= key[32:64]
    iv = key[64:]
    cipher = AES.new(encryptionKey, AES.MODE_CBC, iv=iv)
    plaintext = unpad(cipher.decrypt(ciphertext), 16, style='pkcs7')
    try:
        HMAC.new(authenticationKey, digestmod=SHA256).update(associatedData).verify(hmac)
    except ValueError:
        return None
    return plaintext

def createHeader(DHPair, previousN, sendN):
    header = json.loads({
    'DH': DHPair[1],
    'previousN': previousN,
    'sendN': sendN
    })
    return header

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
        DHSendingPair = generateDH()
        DHReceivingKey = publicKey
        rootKey, sendChainKey = HKDFRootKey(sharedSecret, DH(DHSendingPair, DHReceivingKey))
        self.createKeyRing(username, rootKey, DHSendingPair, DHReceivingKey, sendChainKey)

    def initiateDoubleRatchetReceiver(self, username, sharedSecret, keyPair):
        DHSendingPair = keyPair
        rootKey = sharedSecret
        self.createKeyRing(username, DHSendingPair, None, None)

    def DHRatchet(self, username, header):
        keyRing = self.keyRing[username]
        keyRing['previousN'] = keyRing['sendN']
        keyRing['sendN'] = 0
        keyRing['readN'] = 0
        keyRing['DHReceivingKey'] = header.dh
        keyRing['rootKey'], keyRing['readChainKey'] = HKDFRootKey(keyRing['rootKey'], DH(keyRing['DHSendingPair'], keyRing['DHReceivingKey']))
        keyRing['DHSendingPair'] = generateDH()
        keyRing['rootKey'], keyRing['sendChainKey'] = HKDFRootKey(keyRing['rootKey'], DH(keyRing['DHSendingPair'], keyRing['DHReceivingKey']))

    def ratchetEncrypt(self, username, plaintext, ad):
        keyRing = self.keyRing[username]
        keyRing['sendChainKey'], messageKey = HKDFChainKey(keyRing['sendChainKey'])
        header = createHeader(keyRing['DHSendingPair'], keyRing['previousN'], keyRing['sendN'])
        keyRing['sendN'] += 1
        return header, encrypt(messageKey, plaintext, ad+header)

    def ratchetDecrypt(self, username, ciphertext, ad, header):
        keyRing = self.keyRing[username]
        if header['DH'] != keyRing['DHReceivingKey']:
            DHRatchet(username, header)
        keyRing['readChainKey'], messageKey = HKDFChainKey(keyRing['readChainKey'])
        keyRing['readN'] += 1
        return decrypt(messageKey, ciphertext, ad+header)
