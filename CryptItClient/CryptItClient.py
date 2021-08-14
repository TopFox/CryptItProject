from tkinter import *
from tkinter.messagebox import *
from X3DH import X3DH_Class
from X3DH import signature

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

def signIn(usernameTryingToSign, password, currentFrame):
    if True:
        print(usernameTryingToSign + ' logged in with password: ' + password)
        username = usernameTryingToSign
        mainFrame(currentFrame)
    else:
        showerror('Error','The user/password is invalid')

def signUp(usernameTryingToSign, password, password2, currentFrame):
    if password == password2:
        username = usernameTryingToSign
        print(username + " account's created with password : " + password)
        publishFrame(currentFrame)
    else:
        showerror('Error','Password not matching')

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

    label = Label(signUpFrame, text='Please enter your username and password')
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

def publishFrame(currentFrame=None):
    if currentFrame != None:
        currentFrame.destroy()

    publishFrame = Frame(window)
    publishFrame.pack()

    congrats = Label(publishFrame, text='Congratulations, you just created your account !')
    congrats.pack()

    instructions = Label(publishFrame, text='To use this bot, you will need to push a bundle of keys on the server. \n To do so, you need to copy the following command and send it to CryptItBot:')
    instructions.pack()

    commandToSend = '/publishKeyBundle ' + X3DHClient.publish()

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

    continueButton = Button(publishFrame, text='Continue', command=lambda: mainFrame(publishFrame))
    continueButton.pack()


def mainFrame(currentFrame=None):
    if currentFrame != None:
        currentFrame.destroy()

    mainFrame = Frame(window)
    mainFrame.pack()
    newChatButton = Button(mainFrame, text='Start a new chat', command=lambda: newChatFrame(mainFrame))
    newChatButton.pack(side=LEFT)

    oldChatButton = Button(mainFrame, text='Continue a chat', command=lambda: chatFrame(mainFrame))
    oldChatButton.pack(side=LEFT)

    publishBundleButton = Button(mainFrame, text='Publish the key bundle', command=lambda: publishFrame(mainFrame))
    publishBundleButton.pack(side=LEFT)

def newChatFrame(currentFrame=None):
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

    youButton = Button(newChatFrame, text='You', command=lambda: getKeyBundleFrame(username.get(), True, newChatFrame))
    youButton.pack(side=LEFT)

    oldChatButton = Button(newChatFrame, text='The other person', command=lambda: getKeyBundleFrame(username.get(), False, newChatFrame))
    oldChatButton.pack(side=LEFT)

    backButton = Button(newChatFrame, text='Back', command=lambda: mainFrame(newChatFrame))
    backButton.pack(side=BOTTOM)

def getKeyBundleFrame(username, initiator, currentFrame=None):
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
        continueButton = Button(getKeyBundleFrame, text='Continue', command=lambda: initiateX3DHFrame(username, keyBundle.get("1.0",END), getKeyBundleFrame))
        continueButton.pack()
    else:
        continueButton = Button(getKeyBundleFrame, text='Continue', command=lambda: respondToX3DHFrame(username, keyBundle.get("1.0",END), getKeyBundleFrame))
        continueButton.pack()

def initiateX3DHFrame(username, keyBundle, currentFrame=None):
    if currentFrame != None:
        currentFrame.destroy()

    initiateX3DHFrame = Frame(window)
    initiateX3DHFrame.pack()
    X3DHClient.storeKeyBundle(username, keyBundle)
    statusFrame = Frame(initiateX3DHFrame)
    statusFrame.pack(side=TOP)
    Label(statusFrame, text="Status of the key bundle:").pack(side=LEFT)
    if not X3DHClient.keyBundleStored(username):
        status = 'Not OK'

        backButton = Button(initiateX3DHFrame, text='Back', command=lambda: mainFrame(initiateX3DHFrame))
        backButton.pack()
    else:
        status = 'OK'
        Label(statusFrame, text=status).pack(side=RIGHT)

        helloMessageFrame = Frame(initiateX3DHFrame)
        helloMessageFrame.pack()
        Label(helloMessageFrame, text="You now need to send this message (copied to your keyboard):").pack(side=TOP)

        helloMessage = '/x3dhhello ' + username + ' ' + bytes(X3DHClient.initiateX3DH(username)).hex()
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

        # TODO: start double ratchet

        continueButton = Button(initiateX3DHFrame, text='Continue', command=lambda: chatFrame(initiateX3DHFrame))
        continueButton.pack(side=BOTTOM)

def respondToX3DHFrame(username, keyBundle, currentFrame=None):
    if currentFrame != None:
        currentFrame.destroy()

    respondToX3DHFrame = Frame(window)
    respondToX3DHFrame.pack()

    X3DHClient.storeKeyBundle(username, keyBundle)
    statusFrame = Frame(respondToX3DHFrame)
    statusFrame.pack(side=TOP)
    Label(statusFrame, text="Status of the key bundle:").pack(side=LEFT)
    if not X3DHClient.keyBundleStored(username):
        status = 'Not OK'

        backButton = Button(respondToX3DHFrame, text='Back', command=lambda: mainFrame(respondToX3DHFrame))
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

        continueButton = Button(receiveHelloMessageFrame, text='Continue', command=lambda: displayX3DHFeedback(command.get("1.0",END), username, respondToX3DHFrame))
        continueButton.pack()

def displayX3DHFeedback(helloMessage, username, currentFrame=None):
    status, feedback = X3DHClient.receiveHelloMessage(bytes(bytearray.fromhex(helloMessage)), username)
    if status == 0:
        feedback += '\n\n You will now get back to the menu to start the procedure over again'
        showerror('Error',feedback)
        mainFrame(currentFrame)
    else:
        showinfo('Success', feedback)
        chatFrame(currentFrame)

def chatFrame(currentFrame=None):
    if currentFrame != None:
        currentFrame.destroy()
    chatFrame = Frame(window)
    chatFrame.pack()

    backButton = Button(chatFrame, text='Back', command=lambda: mainFrame(chatFrame))
    backButton.pack()

window = Tk()
window.title('CryptItClient')
window.geometry("500x400+500+300")
username=''
X3DHClient = X3DH_Class.X3DH_Client('goupillerenard')
initialFrame()
window.mainloop()
