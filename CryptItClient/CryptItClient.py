from tkinter import *
from tkinter.messagebox import *
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
import pickle
import os
import X3DH
import DoubleRatchet
import json # TODO : remove this

FOLDER = './Users/'
AES_NONCE_LEN = 16

class User(object):
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.x3dh = X3DH.X3DHClient(username)
        self.doubleRatchet = DoubleRatchet.DoubleRatchetClient()

def initialFrame(currentFrame=None):
    if currentFrame != None:
        currentFrame.destroy()
    loginFrame = Frame(window)
    loginFrame.pack()
    label = Label(loginFrame, text='Welcome to crypt it client !')
    label.pack()

    signInButton = Button(loginFrame, text='Sign in', command=lambda: signInFrame(loginFrame))
    signInButton.pack()

    signUpButton = Button(loginFrame, text='Sign up', command=lambda: signUpFrame(loginFrame))
    signUpButton.pack()

def loadUserFromFile(username, key):
    filename = FOLDER + username + '.txt'
    with open(filename, 'rb') as myFile:
        nonce = myFile.read(AES_NONCE_LEN)
        encryptedUser = myFile.read()
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decryptedUser = cipher.decrypt(encryptedUser)
        try:
            user = pickle.loads(decryptedUser)
        except Exception as e:
            return None
        return user

def saveUserInFile(user):
    filename = FOLDER + user.username + '.txt'
    with open(filename, 'wb') as myFile:
        nonce = get_random_bytes(AES_NONCE_LEN)
        cipher = AES.new(user.password.encode("utf8"), AES.MODE_GCM, nonce=nonce)
        encryptedUser = cipher.encrypt(pickle.dumps(user))
        myFile.write(nonce + encryptedUser)
        window.destroy()

def fileExists(username):
    for filename in os.listdir('./Users/'):
        if filename == username+'.txt':
            return True
    return False

def signIn(username, password, currentFrame):
    if fileExists(username):
        user = loadUserFromFile(username, password.encode("utf8"))
        if user != None:
            window.protocol("WM_DELETE_WINDOW", lambda: saveUserInFile(user))
            print('[Account] \t' + username + ' logged in')
            mainFrame(user, currentFrame)
        else:
            showerror('Error','The password you entered is invalid')
    else:
        showerror('Error','The username you entered is invalid')

def signUp(username, password, password2, currentFrame):
    if len(password) != 16:
        showerror('Error','Please enter a 16 characters long password')
    elif password != password2:
        showerror('Error','The passwords are not matching')
    elif fileExists(username):
        showerror('Error','The username you entered is already used')
    else:
        user = User(username, password)
        window.protocol("WM_DELETE_WINDOW", lambda: saveUserInFile(user))
        print('[Account] \t' + username + ' signed in')
        publishFrame(user, currentFrame)

def signInFrame(currentFrame=None):
    if currentFrame != None:
        currentFrame.destroy()
    signInFrame = Frame(window)
    signInFrame.pack()

    label = Label(signInFrame, text='Please enter your username and password')
    label.pack()

    usernameString = StringVar()
    usernameString.set('Username')
    username = Entry(signInFrame, textvariable=usernameString, width=30)
    username.pack()

    passwordString = StringVar()
    passwordString.set('Password')
    password = Entry(signInFrame, textvariable=passwordString, width=30)
    password.pack()

    signInButton = Button(signInFrame, text='Confirm', command=lambda: signIn(username.get(), password.get(), signInFrame))
    signInButton.pack()

    backButton = Button(signInFrame, text='Back', command=lambda: initialFrame(signInFrame))
    backButton.pack()

def signUpFrame(currentFrame=None):
    if currentFrame != None:
        currentFrame.destroy()
    signUpFrame = Frame(window)
    signUpFrame.pack()

    label = Label(signUpFrame, text='Please enter your Telegram username and password')
    label.pack()

    usernameString = StringVar()
    usernameString.set('Username')
    username = Entry(signUpFrame, textvariable=usernameString, width=30)
    username.pack()

    passwordString = StringVar()
    passwordString.set('Password')
    password = Entry(signUpFrame, textvariable=passwordString, width=30)
    password.pack()

    password2String = StringVar()
    password2String.set('Please repeat the password')
    password2 = Entry(signUpFrame, textvariable=password2String, width=30)
    password2.pack()

    signUpButton = Button(signUpFrame, text='Confirm', command=lambda: signUp(username.get(), password.get(), password2.get(), signUpFrame))
    signUpButton.pack()

    backButton = Button(signUpFrame, text='Back', command=lambda: initialFrame(signUpFrame))
    backButton.pack()

def publishFrame(user, currentFrame=None):
    if currentFrame != None:
        currentFrame.destroy()

    publishFrame = Frame(window)
    publishFrame.pack()

    congrats = Label(publishFrame, text='Congratulations, you just created your account !')
    congrats.pack()

    instructions = Label(publishFrame, text='To use this bot, you will need to push a bundle of keys on the server. \n To do so, you need to copy the following command and send it to CryptItBot:')
    instructions.pack()

    commandToSend = '/publishKeyBundle ' + user.x3dh.publish()

    commandFrame = Frame(publishFrame, bg='White', borderwidth=2, relief=GROOVE)
    commandFrame.pack()

    command = Text(commandFrame, height=15, wrap=WORD, width=60)
    command.insert(1.0, commandToSend)
    command.pack()
    command.configure(bg=commandFrame.cget('bg'), relief="flat")

    window.clipboard_clear()
    window.clipboard_append(commandToSend)
    window.update()

    informations = Label(publishFrame, text='It has also been copied to your clipboard. Once sent, please press the "Continue" button.')
    informations.pack()

    continueButton = Button(publishFrame, text='Continue', command=lambda: mainFrame(user, publishFrame))
    continueButton.pack()

def mainFrame(user, currentFrame=None):
    if currentFrame != None:
        currentFrame.destroy()

    mainFrame = Frame(window)
    mainFrame.pack()
    newChatButton = Button(mainFrame, text='Start a new chat', command=lambda: newChatFrame(user, mainFrame))
    newChatButton.pack(side=LEFT)

    oldChatButton = Button(mainFrame, text='Continue a chat', command=lambda: choseContactFrame(user, mainFrame))
    oldChatButton.pack(side=LEFT)

    publishBundleButton = Button(mainFrame, text='Publish the key bundle', command=lambda: publishFrame(user, mainFrame))
    publishBundleButton.pack(side=LEFT)

def newChatFrame(user, currentFrame=None):
    if currentFrame != None:
        currentFrame.destroy()

    newChatFrame = Frame(window)
    newChatFrame.pack()
    Label(newChatFrame, text="Please enter the Telegram's username of the person you want to chat with:").pack()

    usernameString = StringVar()
    usernameString.set('Username')
    username = Entry(newChatFrame, textvariable=usernameString, width=30)
    username.pack()

    Label(newChatFrame, text="Now please select the person who sends the first message").pack()

    youButton = Button(newChatFrame, text='You', command=lambda: getKeyBundleFrame(username.get(), True, user, newChatFrame))
    youButton.pack(side=LEFT)

    oldChatButton = Button(newChatFrame, text='The other person', command=lambda: getKeyBundleFrame(username.get(), False, user, newChatFrame))
    oldChatButton.pack(side=LEFT)

    backButton = Button(newChatFrame, text='Back', command=lambda: mainFrame(user, newChatFrame))
    backButton.pack(side=BOTTOM)

def getKeyBundleFrame(username, initiator, user, currentFrame=None):
    if currentFrame != None:
        currentFrame.destroy()

    # TODO: check if the username doesn't already have a SK
    getKeyBundleFrame = Frame(window)
    getKeyBundleFrame.pack()
    Label(getKeyBundleFrame, text="You need to send this command to the bot (copied to your keyboard):").pack()

    getKeyBundleCommand = "/getKeyBundle " + username

    commandFrame = Frame(getKeyBundleFrame, bg='White', borderwidth=2, relief=GROOVE)
    commandFrame.pack()

    Label(commandFrame, text=getKeyBundleCommand).pack()

    window.clipboard_clear()
    window.clipboard_append(getKeyBundleCommand)
    window.update()

    Label(getKeyBundleFrame, text="Please paste the result bellow and press 'Continue'").pack()

    keyBundle = Text(getKeyBundleFrame, width=50, height=20, borderwidth=2, relief=GROOVE)
    keyBundle.pack()

    if initiator:
        continueButton = Button(getKeyBundleFrame, text='Continue', command=lambda: initiateX3DHFrame(username, keyBundle.get("1.0",END), user, getKeyBundleFrame))
        continueButton.pack()
    else:
        continueButton = Button(getKeyBundleFrame, text='Continue', command=lambda: respondToX3DHFrame(username, keyBundle.get("1.0",END), user, getKeyBundleFrame))
        continueButton.pack()

def initiateX3DHFrame(username, keyBundle, user, currentFrame=None):
    if currentFrame != None:
        currentFrame.destroy()

    initiateX3DHFrame = Frame(window)
    initiateX3DHFrame.pack()
    user.x3dh.storeKeyBundle(username, keyBundle)
    statusFrame = Frame(initiateX3DHFrame)
    statusFrame.pack(side=TOP)
    Label(statusFrame, text="Status of the key bundle:").pack(side=LEFT)
    if not user.x3dh.keyBundleStored(username):
        status = 'Not OK'

        backButton = Button(initiateX3DHFrame, text='Back', command=lambda: mainFrame(user, initiateX3DHFrame))
        backButton.pack()
    else:
        status = 'OK'
        Label(statusFrame, text=status).pack(side=RIGHT)

        helloMessageFrame = Frame(initiateX3DHFrame)
        helloMessageFrame.pack()
        Label(helloMessageFrame, text="You now need to send this message (copied to your keyboard):").pack(side=TOP)

        helloMessage = '/x3dhhello ' + username + ' ' + bytes(user.x3dh.initiateX3DH(username)).hex()
        # come back from hex to bytes : bytes(bytearray.fromhex(helloMessage))

        commandFrame = Frame(helloMessageFrame, bg='White', borderwidth=2, relief=GROOVE)
        commandFrame.pack()

        command = Text(commandFrame, height=10, wrap='char', width=60)
        command.insert(1.0, helloMessage)
        command.pack()
        command.configure(bg=commandFrame.cget('bg'), relief="flat")

        window.clipboard_clear()
        window.clipboard_append(helloMessage)
        window.update()

        # Starts double ratchet
        user.doubleRatchet.initiateDoubleRatchetSender(username, user.x3dh.keyBundles[username]['SK'], user.x3dh.keyBundles[username]['SPK'])

        continueButton = Button(initiateX3DHFrame, text='Continue', command=lambda: chatFrame(user, username, initiateX3DHFrame))
        continueButton.pack(side=BOTTOM)

def respondToX3DHFrame(username, keyBundle, user, currentFrame=None):
    if currentFrame != None:
        currentFrame.destroy()

    respondToX3DHFrame = Frame(window)
    respondToX3DHFrame.pack()

    user.x3dh.storeKeyBundle(username, keyBundle)
    statusFrame = Frame(respondToX3DHFrame)
    statusFrame.pack(side=TOP)
    Label(statusFrame, text="Status of the key bundle:").pack(side=LEFT)
    if not user.x3dh.keyBundleStored(username):
        status = 'Not OK'

        backButton = Button(respondToX3DHFrame, text='Back', command=lambda: mainFrame(user, respondToX3DHFrame))
        backButton.pack()
    else:
        status = 'OK'
        Label(statusFrame, text=status).pack(side=RIGHT)

        receiveHelloMessageFrame = Frame(respondToX3DHFrame)
        receiveHelloMessageFrame.pack()
        Label(receiveHelloMessageFrame, text="You now need to paste the message you received:").pack(side=TOP)

        commandFrame = Frame(receiveHelloMessageFrame, bg='White', borderwidth=2, relief=GROOVE)
        commandFrame.pack()

        command = Text(commandFrame, height=10, wrap='char', width=60)
        command.pack()
        command.configure(bg=commandFrame.cget('bg'), relief="flat")

        continueButton = Button(receiveHelloMessageFrame, text='Continue', command=lambda: displayX3DHFeedback(user, command.get("1.0",END), username, respondToX3DHFrame))
        continueButton.pack()

def displayX3DHFeedback(user, helloMessage, username, currentFrame=None):
    status, feedback = user.x3dh.receiveHelloMessage(bytes(bytearray.fromhex(helloMessage)), username)
    if status == 0:
        feedback += '\n\n You will now get back to the menu to start the procedure over again'
        showerror('Error',feedback)
        mainFrame(user, currentFrame)
    else:
        showinfo('Success', feedback)
        user.doubleRatchet.initiateDoubleRatchetReceiver(username, user.x3dh.keyBundles[username]['SK'], [user.x3dh.signedPreKeyPrivate, user.x3dh.signedPreKeyPublic])
        chatFrame(user, username, currentFrame)

def choseContactFrame(user, currentFrame=None):
    if currentFrame != None:
        currentFrame.destroy()
    choseContactFrame = Frame(window)
    choseContactFrame.pack()

    contactList = list(user.doubleRatchet.keyRing.keys())
    if len(contactList) > 0:
        contactListStringVar = StringVar()
        contactListStringVar.set(contactList)
        contactListBox = Listbox(choseContactFrame, listvariable=contactListStringVar)
        contactListBox.selection_set(0)
        contactListBox.pack()

        continueButton = Button(choseContactFrame, text='Continue', command=lambda: chatFrame(user, contactListBox.get(contactListBox.curselection()), choseContactFrame))
        continueButton.pack()

    backButton = Button(choseContactFrame, text='Back', command=lambda: mainFrame(user, choseContactFrame))
    backButton.pack()

def sendMessage(user, username, message, topTextContainer, bottomTextContainer):
    ad = json.dumps({
    'from': user.x3dh.name,
    'to': username})
    header, ciphertext = user.doubleRatchet.ratchetEncrypt(username, message.encode("utf8"), ad)
    topTextContainer.delete("1.0", END)
    bottomTextContainer.delete("1.0", END)
    bottomTextContainer.insert("1.0", header + '#' + ciphertext.hex())

    window.clipboard_clear()
    window.clipboard_append(header + '#' + ciphertext.hex())
    window.update()

def readMessage(user, username, message, textContainer):
    ad = json.dumps({
    'from': username,
    'to': user.x3dh.name})
    header, ciphertext = message.split('#')
    plaintext = user.doubleRatchet.ratchetDecrypt(username, bytes(bytearray.fromhex(ciphertext)), ad, header)
    print(plaintext)
    textContainer.insert("1.0", plaintext)

def chatFrame(user, username, currentFrame=None):
    if currentFrame != None:
        currentFrame.destroy()

    chatFrame = Frame(window)
    chatFrame.pack()

    p = PanedWindow(chatFrame, orient=VERTICAL)
    p.pack(side=TOP, expand=Y, fill=BOTH, pady=5, padx=5)
    title = 'Discussion with ' + username
    p.add(Label(p, text=title, anchor=CENTER))
    p2 = PanedWindow(p, orient=HORIZONTAL)
    p.add(p2)
    backButton = Button(p, text='Back', command=lambda: mainFrame(user, chatFrame))
    p.add(backButton)

    pRead = PanedWindow(p2, orient=VERTICAL)
    p2.add(pRead)
    pWrite = PanedWindow(p2, orient=VERTICAL)
    p2.add(pWrite)

    receivedMessagesText = Text(pRead, width=30, height=10, borderwidth=2, relief=GROOVE)
    decryptButton = Button(pRead, text='Decrypt', command=lambda: readMessage(user, username, receivedMessagesText.get("1.0",END), decryptedMessageText))
    decryptedMessageText = Text(pRead, width=30, height=10, borderwidth=2, relief=GROOVE)
    pRead.add(Label(pRead, text='Message to decrypt', anchor=CENTER))
    pRead.add(receivedMessagesText)
    pRead.add(decryptButton)
    pRead.add(Label(pRead, text='Decrypted message', anchor=CENTER))
    pRead.add(decryptedMessageText)

    toSendMessagesText = Text(pWrite, width=30, height=10, borderwidth=2, relief=GROOVE)
    encryptButton = Button(pWrite, text='Encrypt', command=lambda: sendMessage(user, username, toSendMessagesText.get("1.0",END), toSendMessagesText, encryptedMessageText))
    encryptedMessageText = Text(pWrite, width=30, height=10, borderwidth=2, relief=GROOVE)
    pWrite.add(Label(pWrite, text='Message to encrypt', anchor=CENTER))
    pWrite.add(toSendMessagesText)
    pWrite.add(encryptButton)
    pWrite.add(Label(pWrite, text='Encrypted message', anchor=CENTER))
    pWrite.add(encryptedMessageText)

window = Tk()
window.title('CryptItClient')
window.geometry("500x400+500+300")
initialFrame()
window.mainloop()
