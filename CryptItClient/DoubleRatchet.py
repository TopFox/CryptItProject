from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization
from Cryptodome.Protocol.KDF import HKDF
from Cryptodome.Hash import HMAC, SHA256
from Cryptodome.Cipher import AES
import json


# Adds PKCS#7 padding
def pad(message):
    num = 16 - (len(message) % 16)
    return message + bytes([num] * num)

# Removes PKCS#7 padding
def unpad(message):
    return message[:-message[-1]]

# Returns the X25519 key generated from the given bytes
def fromBytes(inp, private):
    if private:
        return X25519PrivateKey.from_private_bytes(inp)
    else:
        return X25519PublicKey.from_public_bytes(inp)

# Encodes X25519 key in bytes
def toBytes(inp):
    if (type(inp).__name__ == '_X25519PrivateKey'):
        return inp.private_bytes(encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption())
    elif (type(inp).__name__ == '_X25519PublicKey'):
        return inp.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    else:
        return None

# Generates a DH key pair: [privateKey, publicKey]
def generateDH():
    DHPrivate = X25519PrivateKey.generate()
    return [toBytes(DHPrivate), toBytes(DHPrivate.public_key())]

# Returns the output from the Diffie-Hellman calculation between the private key
# from DHPair and the DH public key DHPublic
def DH(DHPair, DHPublic):
    DHPrivate = fromBytes(DHPair[0], True)
    return toBytes(DHPrivate.exchange(fromBytes(DHPublic, False)))

# Returns a pair (both 32 bytes) as the output of applying a KDF keyed by a 32-
# byte root key rk to a Diffie-Hellman output DHOut
def HKDFRootKey(rootKey, DHOut):
    out = HKDF(DHOut, 64, rootKey, SHA256)
    return out[:32], out[32:]

# Returns a pair (both 32 bytes) as the output of applying a KDF keyed by a 32-
# byte chain key chainKey to some constant
def HKDFChainKey(chainKey):
    chainKeyNextInput = HMAC.new(chainKey, digestmod=SHA256).update(b'\x01').digest()
    messageKey = HMAC.new(chainKey, digestmod=SHA256).update(b'\x02').digest()
    return chainKeyNextInput, messageKey

# Returns authenticated encryption of plaintext using key mk with additional data
def encrypt(mk, plaintext, associatedData):
    key = HKDF(mk, 80, b'\0'*80, SHA256)
    encryptionKey = key[:32]
    authenticationKey= key[32:64]
    iv = key[64:]
    cipher = AES.new(encryptionKey, AES.MODE_CBC, iv=iv)
    ciphertext = cipher.encrypt(pad(plaintext))
    hmac = HMAC.new(authenticationKey, digestmod=SHA256).update(associatedData.encode("utf8")).digest()

    return ciphertext + hmac

# Returns the authenticated decryption of ciphertext with key mk. If authentication
# fails, the function returns None
def decrypt(mk, ciphertextAndHMAC, associatedData):
    ciphertext = ciphertextAndHMAC[:-32]
    hmac = ciphertextAndHMAC[-32:]
    key = HKDF(mk, 80, b'\0'*80, SHA256)
    encryptionKey = key[:32]
    authenticationKey= key[32:64]
    iv = key[64:]
    cipher = AES.new(encryptionKey, AES.MODE_CBC, iv=iv)
    plaintext = unpad(cipher.decrypt(ciphertext))
    try:
        HMAC.new(authenticationKey, digestmod=SHA256).update(associatedData.encode("utf8")).verify(hmac)
    except ValueError:
        return None
    return plaintext

# Creates a new message header containing the DH ratchet public key from the key
# paie in DHPair, the previous chain length previousN, and the message number sendN
def createHeader(DHPair, previousN, sendN):
    header = json.dumps({
    'DH': DHPair[1].hex(),
    'previousN': previousN,
    'sendN': sendN
    })
    return header

class DoubleRatchetClient(object):
    def __init__(self):
        self.keyRing = {}

    # Adds a key ring to the dictionary with the following input
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

    # Called by the initiator of X3DH. Creates the appropriate key ring
    def initiateDoubleRatchetSender(self, username, sharedSecret, publicKey):
        DHSendingPair = generateDH()
        DHReceivingKey = publicKey
        rootKey, sendChainKey = HKDFRootKey(sharedSecret, DH(DHSendingPair, DHReceivingKey))
        self.createKeyRing(username, rootKey, DHSendingPair, DHReceivingKey, sendChainKey)

    # Called by the receiver of the X3DH hello message. Creates the appropriate
    # key ring
    def initiateDoubleRatchetReceiver(self, username, sharedSecret, keyPair):
        DHSendingPair = keyPair
        rootKey = sharedSecret
        self.createKeyRing(username, rootKey, DHSendingPair, None, None)

    # DH ratchet step
    def DHRatchet(self, username, header):
        keyRing = self.keyRing[username]
        keyRing['previousN'] = keyRing['sendN']
        keyRing['sendN'] = 0
        keyRing['readN'] = 0
        keyRing['DHReceivingKey'] = header['DH']
        keyRing['rootKey'], keyRing['readChainKey'] = HKDFRootKey(keyRing['rootKey'], DH(keyRing['DHSendingPair'], keyRing['DHReceivingKey']))
        keyRing['DHSendingPair'] = generateDH()
        keyRing['rootKey'], keyRing['sendChainKey'] = HKDFRootKey(keyRing['rootKey'], DH(keyRing['DHSendingPair'], keyRing['DHReceivingKey']))

    # Encrypts the plaintext with username's key ring. Returns header and encrypted text
    def ratchetEncrypt(self, username, plaintext, ad):
        keyRing = self.keyRing[username]
        keyRing['sendChainKey'], messageKey = HKDFChainKey(keyRing['sendChainKey'])
        header = createHeader(keyRing['DHSendingPair'], keyRing['previousN'], keyRing['sendN'])
        keyRing['sendN'] += 1
        return header, encrypt(messageKey, plaintext, ad+header)

    # Decrypts the ciphertext with username's key ring. Returns the plaintext or None
    def ratchetDecrypt(self, username, ciphertext, ad, header):
        keyRing = self.keyRing[username]
        headerJson = json.loads(header)
        headerJson = {
        'DH': bytes(bytearray.fromhex(headerJson['DH'])),
        'previousN': headerJson['previousN'],
        'sendN': headerJson['sendN']
        }

        if headerJson['DH'] != keyRing['DHReceivingKey']:
            self.DHRatchet(username, headerJson)

        if keyRing['readN'] > headerJson['sendN']:
            return ''.encode('utf8')

        while keyRing['readN'] < headerJson['sendN']:
            keyRing['readChainKey'], messageKey = HKDFChainKey(keyRing['readChainKey'])
            keyRing['readN'] += 1

        keyRing['readChainKey'], messageKey = HKDFChainKey(keyRing['readChainKey'])
        keyRing['readN'] += 1
        return decrypt(messageKey, ciphertext, ad+header)
