from tkinter import *
from tkinter.messagebox import *
import tkinter.scrolledtext as st
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Protocol.KDF import HKDF
from Cryptodome.Hash import SHA256
import pickle
import os
import X3DH
import DoubleRatchet
import json

FOLDER = './Users/'     # Folder where we store encrypted user files
AES_NONCE_LEN = 16      # AES nonce length

class User(object):
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.x3dh = X3DH.X3DHClient(username)
        self.doubleRatchet = DoubleRatchet.DoubleRatchetClient()
        self.conversations = {}
        self.groups = {}

# Frame to chose between sign up and login
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

# Returns decrypted user stored in file starting with username
def loadUserFromFile(username, password):
    filename = FOLDER + username + '.txt'
    with open(filename, 'rb') as myFile:
        nonce = myFile.read(AES_NONCE_LEN)
        encryptedUser = myFile.read()
        key = HKDF(password, 32, b'\0'*32, SHA256)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decryptedUser = cipher.decrypt(encryptedUser)
        try:
            user = pickle.loads(decryptedUser)
        except Exception as e:
            return None
        return user

# Saves the encrypted user in a file and closes the program. Encryption: AES in
# Galois counter mode
def saveUserInFile(user):
    filename = FOLDER + user.username + '.txt'
    with open(filename, 'wb') as myFile:
        nonce = get_random_bytes(AES_NONCE_LEN)
        key = HKDF(user.password.encode('utf8'), 32, b'\0'*32, SHA256)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        encryptedUser = cipher.encrypt(pickle.dumps(user))
        myFile.write(nonce + encryptedUser)
        window.destroy()

# Returns True if a file 'username.txt' exists
def fileExists(username):
    for filename in os.listdir('./Users/'):
        if filename == username+'.txt':
            return True
    return False

# Calls mainFrame with user if password and username are correct
def signIn(username, password, currentFrame):
    if fileExists(username):
        user = loadUserFromFile(username, password.encode("utf8"))
        if user != None:
            window.protocol("WM_DELETE_WINDOW", lambda: saveUserInFile(user)) # Saves the user when window is closed
            print('[Account] \t' + username + ' logged in')
            mainFrame(user, currentFrame)
        else:
            showerror('Error','The password you entered is invalid')
    else:
        showerror('Error','The username you entered is invalid')

# Creates a user if username is not used, password are matching and are 16
# characters long
def signUp(username, password, password2, currentFrame):
    if len(password) < 8 or len(password) > 32:
        showerror('Error','Please enter a 8-32 characters long password')
    elif password != password2:
        showerror('Error','The passwords are not matching')
    elif fileExists(username):
        showerror('Error','The username you entered is already used')
    else:
        user = User(username, password)
        window.protocol("WM_DELETE_WINDOW", lambda: saveUserInFile(user))
        print('[Account] \t' + username + ' signed in')
        publishFrame(user, True, currentFrame)

# Frame to enter username and password
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

# Frame to enter username and password twice
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

# Changes the signed prekey, signature and OPK
def changeKeys(user, currentFrame):
    user.x3dh.changeKeys()
    publishFrame(user, False, currentFrame)

# Frame that gives the key bundle to publish. If newUser, displays a congratulations
# message and instructions
def publishFrame(user, newUser=True, currentFrame=None):
    if currentFrame != None:
        currentFrame.destroy()

    publishFrame = Frame(window)
    publishFrame.pack()

    if newUser:
        congrats = Label(publishFrame, text='Congratulations, you just created your account !')
        congrats.pack()

        instructions = Label(publishFrame, text='To use this bot, you will need to push a bundle of keys on the server. \n To do so, you need to copy the following command and send it to CryptItBot:')
        instructions.pack()

    commandToSend = '/publishKeyBundle ' + user.x3dh.publish()

    commandFrame = Frame(publishFrame, bg='White', borderwidth=2, relief=GROOVE)
    commandFrame.pack(pady=20)

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

    if not newUser:
        changeKeyButton = Button(publishFrame, text='Change keys', command=lambda: changeKeys(user, publishFrame))
        changeKeyButton.pack()

# Main frame of the program. From there you can initiate a new chat, continue a
# private chat or a group, manage groups and get access to your key bundle
def mainFrame(user, currentFrame=None):
    if currentFrame != None:
        currentFrame.destroy()

    mainFrame = Frame(window)
    mainFrame.pack()
    newChatButton = Button(mainFrame, text='Start a private chat', command=lambda: newChatFrame(user, mainFrame))
    newChatButton.pack(padx=10, pady=10)

    privateChatButton = Button(mainFrame, text='Private chat', command=lambda: choseContactFrame(user, mainFrame))
    privateChatButton.pack(padx=10, pady=10)

    groupChatButton = Button(mainFrame, text='Group chat', command=lambda: choseGroupFrame(user, mainFrame))
    groupChatButton.pack(padx=10, pady=10)

    manageGroupButton = Button(mainFrame, text='Manage groups', command=lambda: choseGroupToManageFrame(user, mainFrame))
    manageGroupButton.pack(padx=10, pady=10)

    publishBundleButton = Button(mainFrame, text='Publish the key bundle', command=lambda: publishFrame(user, False, mainFrame))
    publishBundleButton.pack(padx=10, pady=10)

# Frame to enter the username you want to start a chat with as well as indicate
# if you are the initiator or not
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

    otherPersonButton = Button(newChatFrame, text='The other person', command=lambda: getKeyBundleFrame(username.get(), False, user, newChatFrame))
    otherPersonButton.pack(side=LEFT)

    backButton = Button(newChatFrame, text='Back', command=lambda: mainFrame(user, newChatFrame))
    backButton.pack(side=BOTTOM)

# Frame to enter the key bundle given by the bot. If initiator = True, will call
# initiateX3DHFrame, else it will call respondToX3DHFrame
def getKeyBundleFrame(username, initiator, user, currentFrame=None):
    if currentFrame != None:
        currentFrame.destroy()

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

# Frame to show the X3DH hello message to send to the other user. The status of
# the key bundle is also displayed
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

        # Starts conversation
        user.conversations[username] = []

        continueButton = Button(initiateX3DHFrame, text='Continue', command=lambda: chatFrame(user, username, initiateX3DHFrame))
        continueButton.pack(side=BOTTOM)

# Frame to enter the received X3DH hello message. The status of the key bundle
# is also displayed
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

# Opens a pop up with the result of the X3DH. If it's a success, creates the
# conversation and calls chatFrame. If not, calls mainFrame
def displayX3DHFeedback(user, helloMessage, username, currentFrame=None):
    status, feedback = user.x3dh.receiveHelloMessage(bytes(bytearray.fromhex(helloMessage)), username)
    if status == 0:
        feedback += '\n\n You will now get back to the menu to start the procedure over again'
        showerror('Error',feedback)
        mainFrame(user, currentFrame)
    else:
        showinfo('Success', feedback)
        user.doubleRatchet.initiateDoubleRatchetReceiver(username, user.x3dh.keyBundles[username]['SK'], [user.x3dh.signedPreKeyPrivate, user.x3dh.signedPreKeyPublic])
        user.conversations[username] = []
        chatFrame(user, username, currentFrame)

# Frame to chose a contact to chat with
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
    else:
        label = Label(choseContactFrame, text="You haven't started any conversation yet", anchor=CENTER)
        label.pack()

    backButton = Button(choseContactFrame, text='Back', command=lambda: mainFrame(user, choseContactFrame))
    backButton.pack()

# Frame to chose a group to chat with
def choseGroupFrame(user, currentFrame=None):
    if currentFrame != None:
        currentFrame.destroy()
    choseGroupFrame = Frame(window)
    choseGroupFrame.pack()

    groupList = list(user.groups.keys())
    if len(groupList) > 0:
        groupListStringVar = StringVar()
        groupListStringVar.set(groupList)
        groupListBox = Listbox(choseGroupFrame, listvariable=groupListStringVar)
        groupListBox.selection_set(0)
        groupListBox.pack()

        continueButton = Button(choseGroupFrame, text='Continue', command=lambda: groupChatFrame(user, groupListBox.get(groupListBox.curselection()), choseGroupFrame))
        continueButton.pack()
    else:
        label = Label(choseGroupFrame, text="You haven't created a group yet", anchor=CENTER)
        label.pack()

    backButton = Button(choseGroupFrame, text='Back', command=lambda: mainFrame(user, choseGroupFrame))
    backButton.pack()

# Removes the message in writeText, adds it to conversationText and inside the
# conversation dictionary and encrypts it. Once encrypted, it is added to the
# user clipboard
def sendMessage(user, username, writeText, conversationText):
    message = writeText.get("1.0",END)
    writeText.delete("1.0",END)
    ad = json.dumps({
    'from': user.x3dh.name,
    'to': username})
    header, ciphertext = user.doubleRatchet.ratchetEncrypt(username, message.encode("utf8"), ad)

    conversationText.configure(state='normal')
    text = user.username + ': ' + message + '\n'
    conversationText.insert('end', text)
    conversationText.see("end")
    conversationText.configure(state='disabled')

    user.conversations[username].append([user.username, message])

    window.clipboard_clear()
    window.clipboard_append(header + '#' + ciphertext.hex())
    window.update()

# Removes the message in readText, decrypts it and adds the plaintext to
# conversationText and inside the conversation dictionary. If the message can't
# be decrypted, show an error pop up
def readMessage(user, username, readText, conversationText):
    message = readText.get("1.0",END)
    readText.delete("1.0",END)
    ad = json.dumps({
    'from': username,
    'to': user.x3dh.name})
    header, ciphertext = message.split('#')
    plaintext = user.doubleRatchet.ratchetDecrypt(username, bytes(bytearray.fromhex(ciphertext)), ad, header)
    if plaintext != None:
        plaintext = plaintext.decode("utf-8")
        user.conversations[username].append([username, plaintext])

        conversationText.configure(state='normal')
        text = username + ': ' + plaintext + '\n'
        conversationText.insert('end', text)
        conversationText.see("end")
        conversationText.configure(state='disabled')
    else:
        showerror('Error', 'The decryption failed')

# Frame with the conversation and one Text to add messages to encrypt and another
# one for the messages to decrypt
def chatFrame(user, username, currentFrame=None):
    if currentFrame != None:
        currentFrame.destroy()

    chatFrame = Frame(window)
    chatFrame.pack()

    p = PanedWindow(chatFrame, orient=HORIZONTAL)
    p.pack(side=TOP, expand=Y, fill=BOTH, pady=5, padx=5)

    pInput = PanedWindow(p, orient=VERTICAL)
    pChat = PanedWindow(p, orient=VERTICAL)

    title = 'Discussion with ' + username
    conversationText = st.ScrolledText(pChat, width=30, height=10, borderwidth=2, relief=GROOVE)

    toSendMessagesText = Text(pInput, width=30, height=10, borderwidth=2, relief=GROOVE)
    encryptButton = Button(pInput, text='Encrypt', command=lambda: sendMessage(user, username, toSendMessagesText, conversationText))
    receivedMessagesText = Text(pInput, width=30, height=10, borderwidth=2, relief=GROOVE)
    decryptButton = Button(pInput, text='Decrypt', command=lambda: readMessage(user, username, receivedMessagesText, conversationText))

    p.add(pInput)
    pInput.add(Label(pInput, text='Message to encrypt', anchor=CENTER))
    pInput.add(toSendMessagesText)
    pInput.add(encryptButton)
    pInput.add(Label(pInput, text='Message to decrypt', anchor=CENTER))
    pInput.add(receivedMessagesText)
    pInput.add(decryptButton)

    p.add(pChat)
    pChat.add(Label(pChat, text=title, anchor=CENTER))
    pChat.add(conversationText)

    conversationText.configure(state='normal')
    for sender, message in user.conversations[username]:
        text = sender + ': ' + message + '\n'
        conversationText.insert('end', text)
    conversationText.see("end")
    conversationText.configure(state='disabled')

    backButton = Button(chatFrame, text='Back', command=lambda: mainFrame(user, chatFrame))
    backButton.pack(side=BOTTOM)

# Adds a user to a group if inside the key ring and if confirmed by a pop up
def addUser(user, username, groupName, currentFrame):
    if username in list(user.doubleRatchet.keyRing.keys()):
        message = 'Are you sure that you want to add ' + username + ' in ' + groupName + '?'
        answer = askyesno(title='Confirmation', message=message)
        if answer:
            user.groups[groupName].append(username)
            manageGroupFrame(user, groupName, currentFrame)
    else:
        showerror('Error','You never initiated a conversation with this user')

# Removes a user from a group after confirmation
def removeUser(user, username, groupName, currentFrame):
    message = 'Are you sure that you want to remove ' + username + ' from ' + groupName + '?'
    answer = askyesno(title='Confirmation', message=message)
    if answer:
        user.groups[groupName].remove(username)
        manageGroupFrame(user, groupName, currentFrame)

# Changes the group name if not already used
def changeGroupName(user, newGroupname, oldGroupName, currentFrame):
    if newGroupname in list(user.groups.keys()):
        showerror('Error','You already have a group with this name')
    else:
        user.groups[newGroupname] = user.groups.pop(oldGroupName)
        user.conversations[newGroupname] = user.conversations.pop(oldGroupName)
    manageGroupFrame(user, newGroupname, currentFrame)

# Destroys group after confirmation
def destroyGroup(user, groupName, currentFrame):
    message = 'Are you sure that you want to destroy ' + groupName + '?'
    answer = askyesno(title='Confirmation', message=message)
    if answer:
        user.groups.pop(groupName)
        user.conversations.pop(groupName)
    mainFrame(user, currentFrame)

# Frame to manage groups. From here you can add user, remove them, rename and
# detroy the group
def manageGroupFrame(user, groupName, currentFrame=None):
    if currentFrame != None:
        currentFrame.destroy()

    manageGroupFrame = Frame(window)
    manageGroupFrame.pack()

    if not (groupName in list(user.groups.keys())):
        user.groups[groupName] = []
        user.conversations[groupName] = []
    title = 'Managment of: ' + groupName
    titleLabel = Label(manageGroupFrame, text=title)
    titleLabel.pack()

    pUserManagment = PanedWindow(manageGroupFrame, orient=VERTICAL)
    pUserManagment.pack(side=LEFT)

    userList = user.groups[groupName]
    userListStringVar = StringVar()
    userListStringVar.set(userList)
    userListBox = Listbox(pUserManagment, listvariable=userListStringVar)
    userListBox.selection_set(0)
    pUserManagment.add(userListBox)

    removeUserButton = Button(pUserManagment, text='Remove user', command=lambda: removeUser(user, userListBox.get(userListBox.curselection()), groupName, manageGroupFrame))
    pUserManagment.add(removeUserButton)

    pAddUser = PanedWindow(manageGroupFrame, orient=VERTICAL)
    pAddUser.pack(side=LEFT)

    userNameString = StringVar()
    userNameString.set('Username')
    userName = Entry(pAddUser, textvariable=userNameString, width=20)
    addUserButton = Button(pAddUser, text='Add user', command=lambda: addUser(user, userName.get(), groupName, manageGroupFrame))

    pAddUser.add(userName)
    pAddUser.add(addUserButton)

    pGroupManagment = PanedWindow(manageGroupFrame, orient=VERTICAL)
    pGroupManagment.pack(side=LEFT)

    groupNameString = StringVar()
    groupNameString.set('Group name')
    groupNameEntry = Entry(pGroupManagment, textvariable=groupNameString, width=20)
    changeGroupNameButton = Button(pGroupManagment, text='Change group name', command=lambda: changeGroupName(user, groupNameEntry.get(), groupName, manageGroupFrame))
    destroyGroupButton = Button(pGroupManagment, text='Destroy group', command=lambda: destroyGroup(user, groupName, manageGroupFrame))

    pGroupManagment.add(groupNameEntry)
    pGroupManagment.add(changeGroupNameButton)
    pGroupManagment.add(destroyGroupButton)

    backButton = Button(manageGroupFrame, text='Back', command=lambda: mainFrame(user, manageGroupFrame))
    backButton.pack(side=BOTTOM)

# Chose group to manage from a list or create one
def choseGroupToManageFrame(user, currentFrame=None):
    if currentFrame != None:
        currentFrame.destroy()

    choseGroupToManageFrame = Frame(window)
    choseGroupToManageFrame.pack()

    titleLabel = Label(choseGroupToManageFrame, text='Please first chose an existing group or create one:')
    titleLabel.pack()

    pNew = PanedWindow(choseGroupToManageFrame, orient=VERTICAL)
    pNew.pack(side=LEFT)
    pExisting = PanedWindow(choseGroupToManageFrame, orient=VERTICAL)
    pExisting.pack(side=LEFT)

    groupNameString = StringVar()
    groupNameString.set('Group name')
    groupName = Entry(pNew, textvariable=groupNameString, width=20)
    createGroupButton = Button(pNew, text='Create group', command=lambda: manageGroupFrame(user, groupName.get(), choseGroupToManageFrame))

    pNew.add(groupName)
    pNew.add(createGroupButton, height=20)

    groupsList = list(user.groups.keys())
    if len(groupsList) > 0:
        groupsListStringVar = StringVar()
        groupsListStringVar.set(groupsList)
        groupsListBox = Listbox(pExisting, listvariable=groupsListStringVar)
        groupsListBox.selection_set(0)
        pExisting.add(groupsListBox)

        continueButton = Button(pExisting, text='Continue', command=lambda: manageGroupFrame(user, groupsListBox.get(groupsListBox.curselection()), choseGroupToManageFrame))
        pExisting.add(continueButton)
    else:
        label = Label(pExisting, text="You haven't created a group yet", anchor=CENTER)
        pExisting.add(label)

    backButton = Button(choseGroupToManageFrame, text='Back', command=lambda: mainFrame(user, choseGroupToManageFrame))
    backButton.pack(side=BOTTOM)

# Removes the message in writeText, adds it to conversationText and inside the
# conversation dictionary and encrypts it for each member of the group. Once
# encrypted, paste the resulting command to send in the clipboard
def sendGroupMessage(user, groupName, writeText, conversationText):
    message = writeText.get("1.0",END)
    writeText.delete("1.0",END)

    conversationText.configure(state='normal')
    text = user.username + ': ' + message + '\n'
    conversationText.insert('end', text)
    conversationText.see("end")
    conversationText.configure(state='disabled')

    user.conversations[groupName].append([user.username, message])
    messageToSend = {}
    for username in user.groups[groupName]:
        ad = json.dumps({
        'from': user.x3dh.name,
        'to': username})
        header, ciphertext = user.doubleRatchet.ratchetEncrypt(username, message.encode("utf8"), ad)
        messageToSend[username] = header + '#' + ciphertext.hex()

    commandToSend = '/sendGroupMessage ' + groupName + ' ' + json.dumps(messageToSend)
    window.clipboard_clear()
    window.clipboard_append()
    window.update()

# Frame with the conversation and one Text to add messages to encrypt and another
# one for the messages to decrypt using given username key bundle
def groupChatFrame(user, groupName, currentFrame=None):
    if currentFrame != None:
        currentFrame.destroy()

    chatFrame = Frame(window)
    chatFrame.pack()

    p = PanedWindow(chatFrame, orient=HORIZONTAL)
    p.pack(side=TOP, expand=Y, fill=BOTH, pady=5, padx=5)

    pInput = PanedWindow(p, orient=VERTICAL)
    pChat = PanedWindow(p, orient=VERTICAL)

    title = 'Discussion with ' + groupName
    conversationText = st.ScrolledText(pChat, width=30, height=10, borderwidth=2, relief=GROOVE)

    toSendMessagesText = Text(pInput, width=30, height=10, borderwidth=2, relief=GROOVE)
    encryptButton = Button(pInput, text='Encrypt', command=lambda: sendGroupMessage(user, groupName, toSendMessagesText, conversationText))
    usernamesList = user.groups[groupName]
    stringVarUsername = StringVar()
    stringVarUsername.set(usernamesList[0])
    dropDownUsernames = OptionMenu(pInput, stringVarUsername, *usernamesList)
    receivedMessagesText = Text(pInput, width=30, height=10, borderwidth=2, relief=GROOVE)
    decryptButton = Button(pInput, text='Decrypt', command=lambda: readMessage(user, stringVarUsername.get(), receivedMessagesText, conversationText))

    p.add(pInput)
    pInput.add(Label(pInput, text='Message to encrypt', anchor=CENTER))
    pInput.add(toSendMessagesText)
    pInput.add(encryptButton)
    pInput.add(Label(pInput, text='Message to decrypt', anchor=CENTER))
    pInput.add(dropDownUsernames)
    pInput.add(receivedMessagesText)
    pInput.add(decryptButton)

    p.add(pChat)
    pChat.add(Label(pChat, text=title, anchor=CENTER))
    pChat.add(conversationText)

    conversationText.configure(state='normal')
    for sender, message in user.conversations[groupName]:
        text = sender + ': ' + message + '\n'
        conversationText.insert('end', text)
    conversationText.see("end")
    conversationText.configure(state='disabled')

    backButton = Button(chatFrame, text='Back', command=lambda: mainFrame(user, chatFrame))
    backButton.pack(side=BOTTOM)


window = Tk()
window.title('CryptItClient')
window.geometry("550x450+500+200")
initialFrame()
window.mainloop()
