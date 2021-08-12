from tkinter import *

def initiateX3DHFrame(username, client, currentFrame=None):
    if currentFrame != None:
        currentFrame.destroy()

    initiateX3DHFrame = Frame(window)
    initiateX3DHFrame.pack()
    statusFrame = Frame(initiateX3DHFrame)
    statusFrame.pack(side=TOP)
    Label(statusFrame, text="Status of the key bundle:").pack(side=LEFT)
    if client.keyBundleStored(username):
        status = 'Ok'
    else:
        status = 'Not Ok'
    Label(statusFrame, text=status).pack(side=RIGHT)

    helloMessageFrame = Frame(initiateX3DHFrame)
    helloMessageFrame.pack(side=BOTTOM)
    Label(helloMessageFrame, text="You now need to send this message (copied to your keyboard):").pack(side=TOP)

    helloMessage = client.initiateX3DH(username)

    commandFrame = Frame(helloMessageFrame, bg='White', borderwidth=2, relief=GROOVE)
    commandFrame.pack()

    Label(commandFrame, text=helloMessage).pack()

    window.clipboard_clear()
    window.clipboard_append(helloMessage)
    window.update()

    # TODO: start double ratchet

    continueButton = Button(helloMessageFrame, text='Continue', command=lambda: chatFrame(initiateX3DHFrame))
    continueButton.pack()

def respondToX3DHFrame(username, currentFrame=None):
    if currentFrame != None:
        currentFrame.destroy()

    respondToX3DHFrame = Frame(window)
    respondToX3DHFrame.pack()

    continueButton = Button(respondToX3DHFrame, text='Continue', command=lambda: chatFrame(respondToX3DHFrame))
    continueButton.pack()
