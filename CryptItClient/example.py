arnaud = User('Arnaud', 'Passwordpassword')
arnaudKeyBundle = json.loads(arnaud.x3dh.publish().rstrip())
arnaudkeyBundleWithOneOPK = json.dumps({
'IK': arnaudKeyBundle['IK'],
'SPK': arnaudKeyBundle['SPK'],
'SPK_sig': arnaudKeyBundle['SPK_sig'],
'OPK': arnaudKeyBundle['OPKs'].pop()
})

quentin = User('Quentin', 'Passwordpassword')
quentinKeyBundle = quentin.x3dh.publish()
quentinKeyBundle = json.loads(quentin.x3dh.publish().rstrip())
quentinKeyBundleWithOneOPK = json.dumps({
'IK': quentinKeyBundle['IK'],
'SPK': quentinKeyBundle['SPK'],
'SPK_sig': quentinKeyBundle['SPK_sig'],
'OPK': quentinKeyBundle['OPKs'].pop()
})

arnaud.x3dh.storeKeyBundle('Quentin', quentinKeyBundleWithOneOPK)
arnaudHelloMessage = bytes(arnaud.x3dh.initiateX3DH('Quentin')).hex()
arnaud.doubleRatchet.initiateDoubleRatchetSender('Quentin', arnaud.x3dh.keyBundles['Quentin']['SK'], arnaud.x3dh.keyBundles['Quentin']['SPK'])
header, ciphertext = arnaud.doubleRatchet.ratchetEncrypt('Quentin', 'Hey', json.dumps({'from': 'Arnaud', 'to': 'Quentin'}))
header2, ciphertext2 = arnaud.doubleRatchet.ratchetEncrypt('Quentin', 'Comment ca va ?', json.dumps({'from': 'Arnaud', 'to': 'Quentin'}))


quentin.x3dh.storeKeyBundle('Arnaud', arnaudkeyBundleWithOneOPK)
quentin.x3dh.receiveHelloMessage(bytes(bytearray.fromhex(arnaudHelloMessage)), 'Arnaud')
quentin.doubleRatchet.initiateDoubleRatchetReceiver('Arnaud', quentin.x3dh.keyBundles['Arnaud']['SK'], [quentin.x3dh.signedPreKeyPrivate, quentin.x3dh.signedPreKeyPublic])
plaintext = quentin.doubleRatchet.ratchetDecrypt('Arnaud', ciphertext, json.dumps({'from': 'Arnaud', 'to': 'Quentin'}), header)
plaintext2 = quentin.doubleRatchet.ratchetDecrypt('Arnaud', ciphertext2, json.dumps({'from': 'Arnaud', 'to': 'Quentin'}), header2)
print(plaintext)
print(plaintext2)
