from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from signature import sign, verify
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from cryptography.hazmat.primitives import serialization
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import json


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

    if not verify(IK_pa], sign, IK_pa_p + EK_pa + OPK_pb + ad):
        print("Unable to verify the message signature")
        return

    print('Message: ', json.loads(ad))
    return json.loads(ad)



def respondToX3DH(username, message):
    receiveHelloMessage(message, username)

class X3DH_Client(object):
    def __init__(self):
        self.identityKey = X25519PrivateKey.generate()
        self.signedPreKey = X25519PrivateKey.generate()
        self.signedPreKeySignature = sign(self.identityKey, self.signedPreKey.public_key())
        self.oneTimePublicPreKeys = []
        self.oneTimePreKeysPairs = []
        self.keyBundles = {}
        for i in range(NUMBER_OF_OPK):
            privateKey = X25519PrivateKey.generate()
            publicKey = privateKey.public_key()
            self.oneTimePublicPreKeys.append(publicKey)
            self.oneTimePreKeysPairs.append((privateKey, publicKey))

    def publish(self):
        return {
        'IK': self.identityKey.public_key(),
        'SPK': self.signedPreKey.public_key(),
        'SPK_sig': self.signedPreKeySignature,
        'OPKs': self.oneTimePublicPreKeys
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
        self.keyBundles[userName] = keyBundle

    # TODO: write this function
    def isValidKeyBundle(keyBundle):
        return True

    def generateEphemeralKey(self, userName):
        if getKeyBundle(userName)
            secretKey = X25519PrivateKey.generate()
            self.keyBundles[userName]['EK_s'] = secretKey
            self.keyBundles[userName]['EK_p'] = secretKey.public_key()
        return

    def generateSecretKeyOnSend(self, userName):
        keyBundle = self.keyBundles[userName]

        DH_1 = self.IK_s.exchange(keyBundle['SPK_p'])
        DH_2 = keyBundle['EK_s'].exchange(keyBundle['IK_p'])
        DH_3 = keyBundle['EK_s'].exchange(keyBundle['SPK_p'])
        DH_4 = keyBundle['EK_s'].exchange(keyBundle['OPK_p'])

        if not verify(self.IK_s, keyBundle['SPK_sig']):
            print('Unable to verify Signed Prekey')
            return

        # create SK
        keyBundle['SK'] = X3DH_HKDF(DH_1 + DH_2 + DH_3 + DH_4)

    def sendHelloMessage(self, userName):
        # Binary additional data
        additionalData = (json.dumps({
            'from': self.name,
            'to': userName,
            'message': ad
        })).encode('utf-8')

        keyBundle = self.keyBundles[userName]
        # 64 byte signature
        keyCombination = getBytesKey(self.IK_p) + getBytesKey(keyBundle['EK_p']) + getBytesKey(keyBundle['OPK_p'])
        signature = sign(self.IK_s, keyCombination + additionalData)
        print("Alice message signature: ", signature)
        print("data: ", keyCombination + additionalData)

        # 16 byte aes nonce
        cipher = AES.new(keyBundle['SK'], AES.MODE_GCM, nonce=get_random_bytes(AES_N_LEN))
        # 32 + 32 + len(ad) byte cipher text
        ciphertext, tag = cipher.encrypt_and_digest(signature + getBytesKey(self.IK_p) + getBytesKey(keyBundle['IK_p']) + additionalData)
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
        if (IK_pa != keyBundle['IK_p']):
            print("Key in hello message doesn't match key from server")
            return

        # Verify Signed pre key from server
        if not verify(keyBundle['IK_p'], keyBundle['SPK_sig']):
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

        DH_1 = self.SPK_s.exchange(IK_pa)
        DH_2 = self.IK_s.exchange(EK_pa)
        DH_3 = self.SPK_s.exchange(EK_pa)
        DH_4 = OPK_sb.exchange(EK_pa)

        # create SK
        return X3DH_HKDF(DH_1 + DH_2 + DH_3 + DH_4)
        
    def initiateX3DH(self, username):
        generateEphemeralKey(username)
        generateSecretKeyOnSend(username)
        helloMessage = sendHelloMessage(username)
        return helloMessage
