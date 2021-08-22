from tkinter import *
from tkinter.messagebox import *

def chatFrame(user, username, currentFrame=None):
    if currentFrame != None:
        currentFrame.destroy()

    chatFrame = Frame(window)
    chatFrame.pack()

    p = PanedWindow(chatFrame, orient=HORIZONTAL)
    p.pack(side=TOP, expand=Y, fill=BOTH, pady=5, padx=5)

    pInput = PanedWindow(p, orient=VERTICAL)
    p.add(pInput)

    toSendMessagesText = Text(pInput, width=30, height=10, borderwidth=2, relief=GROOVE)
    encryptButton = Button(pInput, text='Encrypt', command=lambda: print('Salut')) #sendMessage(user, username, toSendMessagesText.get("1.0",END), toSendMessagesText, encryptedMessageText))
    pInput.add(Label(pInput, text='Message to encrypt', anchor=CENTER))
    pInput.add(toSendMessagesText)
    pInput.add(encryptButton)

    receivedMessagesText = Text(pInput, width=30, height=10, borderwidth=2, relief=GROOVE)
    decryptButton = Button(pInput, text='Decrypt', command=lambda: print('Hey')) #readMessage(user, username, receivedMessagesText.get("1.0",END)))
    pInput.add(Label(pInput, text='Message to decrypt', anchor=CENTER))
    pInput.add(receivedMessagesText)
    pInput.add(decryptButton)

    pChat = PanedWindow(p, orient=VERTICAL)
    p.add(pChat)
    title = 'Discussion with ' + username
    conversationText = Text(pChat, width=30, height=10, borderwidth=2, relief=GROOVE)
    pChat.add(Label(pChat, text=title, anchor=CENTER))
    pChat.add(conversationText)

    conversationText.configure(state='normal')
    for sender, message in conversations: #user.conversations[username]:
        text = sender + ': ' + message + '\n'
        conversationText.insert('end', text)
    conversationText.configure(state='disabled')

window = Tk()
window.title('CryptItClient')
window.geometry("500x400+500+300")
conversations = [['Arnaud', 'Hey'], ['Quentin', 'Salut, ça va'], ['Arnaud', 'Bien et toi ?']]
chatFrame('Arnaud', 'Quentin')
window.mainloop()
