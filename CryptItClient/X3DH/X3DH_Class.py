from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from Cryptodome.Protocol.KDF import HKDF
from Cryptodome.Hash import SHA256
from cryptography.hazmat.primitives import serialization
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES
import json
import ast
from X3DH import signature


NUMBER_OF_OPK = 10
KDF_F = b'\xff' * 32
KDF_LEN = 32
KDF_SALT = b'\0' * KDF_LEN
# Length definition for hello message encryption
AES_N_LEN = 16
AES_TAG_LEN = 16
EC_KEY_LEN = 32

def X3DH_HKDF(dhs):
    keyBase = KDF_F + dhs
    return HKDF(keyBase, KDF_LEN, KDF_SALT, SHA256, 1)

def getBytesKey(key):
    key = key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
            )
    return key

def decryptVerify(IK_pa, EK_pa, nonce, tag, ciphertext):
    # Decrypt cipher text and verify
    cipher = AES.new(decodeB64Str(sk), AES.MODE_GCM, nonce=nonce, mac_len=AES_TAG_LEN)
    try:
        p_all = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        print('Unable to verify/decrypt ciphertext')
        return
    except Exception as e:
        print('e')
        return

    # Byte format of plain text
    sign = p_all[:EC_SIGN_LEN]
    IK_pa_p = p_all[EC_SIGN_LEN:EC_SIGN_LEN+EC_KEY_LEN]
    IK_pb_p = p_all[EC_SIGN_LEN+EC_KEY_LEN:EC_SIGN_LEN+EC_KEY_LEN*2]
    ad = p_all[EC_SIGN_LEN+EC_KEY_LEN*2:]
    if (IK_pa != IK_pa_p and IK_pb != IK_pb_p):
        print("Keys from header and ciphertext not match")
        return

    if not signature.verify([IK_pa, sign], IK_pa_p + EK_pa + OPK_pb + ad):
        print("Unable to verify the message signature")
        return

    print('Message: ', json.loads(ad))
    return json.loads(ad)

def respondToX3DH(username, message):
    receiveHelloMessage(message, username)

class X3DH_Client(object):
    def __init__(self, username):
        self.identityKey = X25519PrivateKey.generate()
        self.signedPreKey = X25519PrivateKey.generate()
        self.signedPreKeySignature = signature.sign(self.identityKey, self.signedPreKey.public_key())
        self.oneTimePublicPreKeys = []
        self.oneTimePreKeysPairs = []
        self.keyBundles = {}
        self.name = username
        for i in range(NUMBER_OF_OPK):
            privateKey = X25519PrivateKey.generate()
            publicKey = privateKey.public_key()
            self.oneTimePublicPreKeys.append(publicKey)
            self.oneTimePreKeysPairs.append((privateKey, publicKey))

    def publish(self):
        return {
        'IK': getBytesKey(self.identityKey.public_key()),
        'SPK': getBytesKey(self.signedPreKey.public_key()),
        'SPK_sig': self.signedPreKeySignature,
        'OPKs': [getBytesKey(key) for key in self.oneTimePublicPreKeys]
        }

    def keyBundleStored(self, userName):
        """
        if userName in self.keyBundles and userName in self.dr_keys:
            print('Already stored ' + user_name + ' locally, no need handshake again')
            return True
        self.keyBundles[user_name] = server.getKeyBundle(userName)
        return True
        """
        return userName in self.keyBundles

    def storeKeyBundle(self, userName, keyBundle):
        keyBundle = ast.literal_eval(keyBundle.rstrip())
        self.keyBundles[userName] = {
        'IK': X25519PublicKey.from_public_bytes(keyBundle['IK']),
        'SPK': X25519PublicKey.from_public_bytes(keyBundle['SPK']),
        'SPK_sig': keyBundle['SPK_sig'],
        'OPK': X25519PublicKey.from_public_bytes(keyBundle['OPK'])
        }

    # TODO: write this function
    def isValidKeyBundle(keyBundle):
        return True

    def generateEphemeralKey(self, userName):
        if self.keyBundleStored(userName):
            secretKey = X25519PrivateKey.generate()
            self.keyBundles[userName]['EK_private'] = secretKey
            self.keyBundles[userName]['EK_public'] = secretKey.public_key()
        return

    def generateSecretKeyOnSend(self, userName):
        keyBundle = self.keyBundles[userName]

        DH_1 = self.identityKey.exchange(keyBundle['SPK'])
        DH_2 = keyBundle['EK_private'].exchange(keyBundle['IK'])
        DH_3 = keyBundle['EK_private'].exchange(keyBundle['SPK'])
        DH_4 = keyBundle['EK_private'].exchange(keyBundle['OPK'])

        if not signature.verify(self.identityKey, keyBundle['SPK_sig']):
            print('Unable to verify Signed Prekey')
            return

        # create SK
        keyBundle['SK'] = X3DH_HKDF(DH_1 + DH_2 + DH_3 + DH_4)

    def sendHelloMessage(self, userName):
        # Binary additional data
        additionalData = (json.dumps({
            'from': self.name,
            'to': userName,
            'message': 'X3DH Hello'
        })).encode('utf-8')

        keyBundle = self.keyBundles[userName]
        # 64 byte signature
        keyCombination = getBytesKey(self.identityKey.public_key()) + getBytesKey(keyBundle['EK_public']) + getBytesKey(keyBundle['OPK'])
        sign = signature.sign(self.identityKey, keyCombination + additionalData)
        print("Alice message signature: ", sign)
        print("data: ", keyCombination + additionalData)

        # 16 byte aes nonce
        nonce = get_random_bytes(AES_N_LEN)
        cipher = AES.new(keyBundle['SK'], AES.MODE_GCM, nonce=nonce)
        # 32 + 32 + len(ad) byte cipher text
        ciphertext, tag = cipher.encrypt_and_digest(sign + getBytesKey(self.identityKey.public_key()) + getBytesKey(keyBundle['IK']) + additionalData)
        # initial message: (32 + 32 +32) + 16 + 16 + 64 + 32 + 32 + len(ad)
        message = keyCombination + nonce + tag + ciphertext
        return message

        # For Double Ratchet
        #self.initialize_dr_state(to, keyBundle['SK'], [keyBundle['EK_s'], keyBundle['EK_p']], "")

    def receiveHelloMessage(self, message, userName):
        # receive the hello message
        self.getKeyBundle(userName)

        keyBundle = self.keyBundles[userName]

        IK_pa = message[:EC_KEY_LEN]
        EK_pa = message[EC_KEY_LEN:EC_KEY_LEN*2]
        OPK_pb = message[EC_KEY_LEN*2:EC_KEY_LEN*3]
        nonce = message[EC_KEY_LEN*3:EC_KEY_LEN*3+AES_N_LEN]
        tag = message[EC_KEY_LEN*3+AES_N_LEN:EC_KEY_LEN*3+AES_N_LEN+AES_TAG_LEN]
        ciphertext = message[EC_KEY_LEN*3+AES_N_LEN+AES_TAG_LEN:]

        # Verify if the key in hello message matches the key bundles from server
        if (IK_pa != keyBundle['IK']):
            print("Key in hello message doesn't match key from server")
            return

        # Verify Signed pre key from server
        if not signature.verify(keyBundle['IK'], keyBundle['SPK_sig']):
                print('Unable to verify Signed Prekey')
                return

        sk = generateSecretKeyOnRecv(IK_pa, EK_pa, OPK_pb)
        print('bob sk: ', sk)

        if sk is None:
            return

        keyBundle['SK'] = sk
        message = decryptVerify(self, keyBundle, IK_pa, EK_pa, nonce, tag, ciphertext)

        # For Double Ratchet
        # self.initialize_dr_state(userName, sk, [], EK_pa)

        # Get Ek_pa and plaintext ad
        return EK_pa, message

    def generateSecretKeyOnRecv(self, IK_pa, EK_pa, OPK_pb):
        # Find corresponding secret OPK secret key
        # And remove the pair from the list
        OPK_sb = self.search_OPK_lst(OPK_pb)
        if OPK_sb is None:
            return

        IK_pa = x25519.X25519PublicKey.from_public_bytes(IK_pa)
        EK_pa = x25519.X25519PublicKey.from_public_bytes(EK_pa)

        DH_1 = self.signedPreKey.exchange(IK_pa)
        DH_2 = self.identityKey.exchange(EK_pa)
        DH_3 = self.signedPreKey.exchange(EK_pa)
        DH_4 = OPK_sb.exchange(EK_pa)

        # create SK
        return X3DH_HKDF(DH_1 + DH_2 + DH_3 + DH_4)

    def initiateX3DH(self, username):
        self.generateEphemeralKey(username)
        self.generateSecretKeyOnSend(username)
        helloMessage = self.sendHelloMessage(username)
        return helloMessage
