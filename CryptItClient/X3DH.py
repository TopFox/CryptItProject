from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from Cryptodome.Protocol.KDF import HKDF
from Cryptodome.Hash import SHA256
from cryptography.hazmat.primitives import serialization
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES
import json
import signature

# Constants
NUMBER_OF_OPK = 10
KDF_F = b'\xff' * 32
KDF_LEN = 32
KDF_SALT = b'\0' * KDF_LEN
AES_N_LEN = 16
AES_TAG_LEN = 16
EC_KEY_LEN = 32
EC_SIGN_LEN = 64

def X3DH_HKDF(dhs):
    keyBase = KDF_F + dhs
    return HKDF(keyBase, KDF_LEN, KDF_SALT, SHA256, 1)

def fromBytes(inp, private):
    if private:
        return X25519PrivateKey.from_private_bytes(inp)
    else:
        return X25519PublicKey.from_public_bytes(inp)

def toBytes(inp):
    if (type(inp).__name__ == '_X25519PrivateKey'):
        return inp.private_bytes(encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption())
    elif (type(inp).__name__ == '_X25519PublicKey'):
        return inp.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    else:
        return None

class X3DHClient(object):
    def __init__(self, username):
        self.identityKeyPrivate = toBytes(X25519PrivateKey.generate())
        self.identityKeyPublic = toBytes(fromBytes(self.identityKeyPrivate, True).public_key())
        self.signedPreKeyPrivate = toBytes(X25519PrivateKey.generate())
        self.signedPreKeyPublic = toBytes(fromBytes(self.signedPreKeyPrivate, True).public_key())
        self.signedPreKeySignature = signature.sign(self.identityKeyPrivate, self.signedPreKeyPublic)
        self.oneTimePublicPreKeys = []
        self.oneTimePreKeysPairs = []
        self.keyBundles = {}
        self.name = username
        for i in range(NUMBER_OF_OPK):
            privateKey = toBytes(X25519PrivateKey.generate())
            publicKey = toBytes(fromBytes(privateKey, True).public_key())
            self.oneTimePublicPreKeys.append(publicKey)
            self.oneTimePreKeysPairs.append((privateKey, publicKey))

    def publish(self):
        return json.dumps({
        'IK': self.identityKeyPublic.hex(),
        'SPK': self.signedPreKeyPublic.hex(),
        'SPK_sig': self.signedPreKeySignature.hex(),
        'OPKs': [key.hex() for key in self.oneTimePublicPreKeys]
        })

    def keyBundleStored(self, username):
        return username in self.keyBundles

    def storeKeyBundle(self, username, keyBundle):
        keyBundle = json.loads(keyBundle.rstrip())
        self.keyBundles[username] = {
        'IK': bytes(bytearray.fromhex(keyBundle['IK'])),
        'SPK': bytes(bytearray.fromhex(keyBundle['SPK'])),
        'SPK_sig': bytes(bytearray.fromhex(keyBundle['SPK_sig'])),
        'OPK': bytes(bytearray.fromhex(keyBundle['OPK']))
        }

    # TODO: write this function
    def isValidKeyBundle(keyBundle):
        return True

    def generateEphemeralKey(self, username):
        if self.keyBundleStored(username):
            secretKey = X25519PrivateKey.generate()
            self.keyBundles[username]['EK_private'] = toBytes(secretKey)
            self.keyBundles[username]['EK_public'] = toBytes(secretKey.public_key())
        return

    def generateSecretKeyOnSend(self, username):
        keyBundle = self.keyBundles[username]
        SPKPublicKey = fromBytes(keyBundle['SPK'], False)
        IKPublicKey = fromBytes(keyBundle['IK'], False)
        OPKPublicKey = fromBytes(keyBundle['OPK'], False)

        DH_1 = fromBytes(self.identityKeyPrivate, True).exchange(SPKPublicKey)
        DH_2 = fromBytes(keyBundle['EK_private'], True).exchange(IKPublicKey)
        DH_3 = fromBytes(keyBundle['EK_private'], True).exchange(SPKPublicKey)
        DH_4 = fromBytes(keyBundle['EK_private'], True).exchange(OPKPublicKey)

        if not signature.verify(keyBundle['IK'], keyBundle['SPK_sig'], keyBundle['SPK']):
            print('[X3DH] \t Failure: Unable to verify Signed Prekey')
            return

        keyBundle['SK'] = X3DH_HKDF(DH_1 + DH_2 + DH_3 + DH_4)
        print('[X3DH] \t SK generated for', username)

    def sendHelloMessage(self, username):
        additionalData = (json.dumps({
            'from': self.name,
            'to': username,
            'message': 'X3DH Hello'
        })).encode('utf-8')

        keyBundle = self.keyBundles[username]
        # 64 byte signature
        keyCombination = self.identityKeyPublic + keyBundle['EK_public'] + keyBundle['OPK']
        sign = signature.sign(self.identityKeyPrivate, keyCombination + additionalData)

        # 16 byte aes nonce
        nonce = get_random_bytes(AES_N_LEN)
        cipher = AES.new(keyBundle['SK'], AES.MODE_GCM, nonce=nonce)
        # 32 + 32 + len(ad) byte cipher text
        ciphertext, tag = cipher.encrypt_and_digest(sign + self.identityKeyPublic + keyBundle['IK'] + additionalData)
        # initial message: (32 + 32 +32) + 16 + 16 + 64 + 32 + 32 + len(ad)
        message = keyCombination + nonce + tag + ciphertext

        return message

    def decryptVerify(self, username, IK_pa, OPK_pb, EK_pa, nonce, tag, ciphertext):
        # Decrypt cipher text and verify
        cipher = AES.new(self.keyBundles[username]['SK'], AES.MODE_GCM, nonce=nonce, mac_len=AES_TAG_LEN)
        try:
            decipheredMessage = cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError:
            print('[X3DH] \t Warning: Unable to verify/decrypt ciphertext')
            return
        except Exception as e:
            print('[X3DH] \t Exception:', e)
            return

        # Byte format of plain text
        sign = decipheredMessage[:EC_SIGN_LEN]
        IK_pa_p = decipheredMessage[EC_SIGN_LEN:EC_SIGN_LEN+EC_KEY_LEN]
        IK_pb_p = decipheredMessage[EC_SIGN_LEN+EC_KEY_LEN:EC_SIGN_LEN+EC_KEY_LEN*2]
        ad = decipheredMessage[EC_SIGN_LEN+EC_KEY_LEN*2:]
        if (IK_pa != IK_pa_p and self.keyBundles[username]['IK'] != IK_pb_p):
            print("[X3DH] \t Warning: Keys from header and ciphertext not match")
            return

        if not signature.verify(IK_pa, sign, IK_pa_p + EK_pa + OPK_pb + ad):
            print("[X3DH] \t Warning: Unable to verify the message signature")
            return

        return json.loads(ad)

    def receiveHelloMessage(self, message, username):
        keyBundle = self.keyBundles[username]

        IK_pa = message[:EC_KEY_LEN]
        EK_pa = message[EC_KEY_LEN:EC_KEY_LEN*2]
        OPK_pb = message[EC_KEY_LEN*2:EC_KEY_LEN*3]
        nonce = message[EC_KEY_LEN*3:EC_KEY_LEN*3+AES_N_LEN]
        tag = message[EC_KEY_LEN*3+AES_N_LEN:EC_KEY_LEN*3+AES_N_LEN+AES_TAG_LEN]
        ciphertext = message[EC_KEY_LEN*3+AES_N_LEN+AES_TAG_LEN:]

        # Verify if the key in hello message matches the key bundles from server
        if (IK_pa != keyBundle['IK']):
            return [0, "Key in hello message doesn't match key from server"]

        # Verify Signed pre key from server
        if not signature.verify(keyBundle['IK'], keyBundle['SPK_sig'], keyBundle['SPK']):
                return [0, 'Unable to verify Signed Prekey']

        sk = self.generateSecretKeyOnRecv(IK_pa, EK_pa, OPK_pb)

        if sk is None:
            return [0, 'Key none']

        keyBundle['SK'] = sk
        message = self.decryptVerify(username, IK_pa, OPK_pb, EK_pa, nonce, tag, ciphertext)

        print('[X3DH] \t SK generated for', username)

        return [1, 'Operation successful']

    def findOPKSecretKeyFromPublic(self, OPKPublic):
        for private, public in self.oneTimePreKeysPairs:
            if public == OPKPublic:
                self.oneTimePreKeysPairs.remove((private, public))
                return private
        return None

    def generateSecretKeyOnRecv(self, IK_pa, EK_pa, OPK_pb):
        OPK_sb = self.findOPKSecretKeyFromPublic(OPK_pb)
        if OPK_sb is None:
            return None

        IK_pa = fromBytes(IK_pa, False)
        EK_pa = fromBytes(EK_pa, False)

        DH_1 = fromBytes(self.signedPreKeyPrivate, True).exchange(IK_pa)
        DH_2 = fromBytes(self.identityKeyPrivate, True).exchange(EK_pa)
        DH_3 = fromBytes(self.signedPreKeyPrivate, True).exchange(EK_pa)
        DH_4 = fromBytes(OPK_sb, True).exchange(EK_pa)

        return X3DH_HKDF(DH_1 + DH_2 + DH_3 + DH_4)

    def initiateX3DH(self, username):
        self.generateEphemeralKey(username)
        self.generateSecretKeyOnSend(username)
        helloMessage = self.sendHelloMessage(username)
        return helloMessage
