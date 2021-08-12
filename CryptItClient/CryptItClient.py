from tkinter import *
from tkinter.messagebox import *

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
        print(username + " account's created with password : " + password)
        publishFrame(currentFrame)
        username = usernameTryingToSign
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
    username = Entry(signInFrame, textvariable=usernameString, width=100)
    username.pack()

    passwordString = StringVar()
    passwordString.set('Password')
    password = Entry(signInFrame, textvariable=passwordString, width=100)
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
    username = Entry(signUpFrame, textvariable=usernameString, width=100)
    username.pack()

    passwordString = StringVar()
    passwordString.set('Password')
    password = Entry(signUpFrame, textvariable=passwordString, width=100)
    password.pack()

    password2String = StringVar()
    password2String.set('Please repeat the password')
    password2 = Entry(signUpFrame, textvariable=password2String, width=100)
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

    command = '/publishKeyBundle lalala'

    commandFrame = Frame(publishFrame, bg='White', borderwidth=2, relief=GROOVE)
    commandFrame.pack()

    Label(commandFrame, text=command).pack()

    window.clipboard_clear()
    window.clipboard_append(command)
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
    username = Entry(newChatFrame, textvariable=usernameString, width=100)
    username.pack()

    Label(newChatFrame, text="Now please select the person who sends the first message").pack()

    youButton = Button(newChatFrame, text='You', command=lambda: initiateX3DH(username.get()))
    youButton.pack(side=LEFT)

    oldChatButton = Button(newChatFrame, text='The other person', command=lambda: respondToX3DH(username.get()))
    oldChatButton.pack(side=LEFT)

    backButton = Button(newChatFrame, text='Back', command=lambda: mainFrame(newChatFrame))
    backButton.pack(side=BOTTOM)

def chatFrame(currentFrame=None):
    if currentFrame != None:
        currentFrame.destroy()
    chatFrame = Frame(window)
    chatFrame.pack()

    backButton = Button(chatFrame, text='Back', command=lambda: mainFrame(chatFrame))
    backButton.pack()

window = Tk()
window.title('CryptItClient')
window.geometry("300x200+500+300")
username=''
initialFrame()
window.mainloop()
