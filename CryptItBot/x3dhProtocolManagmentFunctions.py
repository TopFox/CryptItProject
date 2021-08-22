import json

def getKeyBundle(update, context):
    numberOfArguments = len(context.args)
    commandIssuerId = update.effective_chat.id
    if numberOfArguments != 1:
        context.bot.send_message(chat_id=commandIssuerId, text="Please paste exactly the command you were given. For example: \n\n /getkeybundle username")
    else:
        username = context.args[0]
        if username in keyBundles.keys():
            keyBundle = keyBundles[username]
            keyBundle = {
            'IK': keyBundle['IK'],
            'SPK': keyBundle['SPK'],
            'SPK_sig': keyBundle['SPK_sig'],
            'OPK': keyBundle['OPKs'].pop()
            }
            message = "The key bundle you need to paste in CryptItClient: \n\n " + json.dumps(keyBundle)
            context.bot.send_message(chat_id=commandIssuerId, text=message)
        else:
            context.bot.send_message(chat_id=commandIssuerId, text="The username you entered is not in our database. Please check the spelling or ask the user to send me his key bundle")

# TODO: Write this function
def isCorrectKeyBundle(keyBundle):
    return True

def publishKeyBundle(update, context):
    numberOfArguments = len(context.args)
    commandIssuerId = update.effective_chat.id
    commandIssuerUsername = update.message.chat.username
    if numberOfArguments == 0:
        context.bot.send_message(chat_id=commandIssuerId, text="Please paste exactly the command you were given. For example: \n\n /publishkeybundle keybundle")
    else:
        keyBundle = ''.join(context.args)
        if isCorrectKeyBundle(keyBundle):
            keyBundles[commandIssuerUsername] = json.loads(keyBundle.rstrip())
            usersIds[commandIssuerUsername] = commandIssuerId
            context.bot.send_message(chat_id=commandIssuerId, text="Your key bundle was successfully published on the server")
        else:
            context.bot.send_message(chat_id=commandIssuerId, text="We couldn't recognize the key bundle, please paste exactly what was given to you")

def x3dhHello(update, context):
    numberOfArguments = len(context.args)
    if numberOfArguments < 2:
        context.bot.send_message(chat_id=update.effective_chat.id, text="Please enter the name of the username and the encrypted message you want to send. For example: \n\n /sendMessage username encryptedMessage")
    else:
        username = context.args[0]
        x3dhMessage = context.args[1]
        if username in usersIds.keys():
            receiverID = usersIds[username]
            message = "A user is trying to start a chat with you ! Once inside the main menu of CryptItClient, please press the 'Start a new chat' button and enter this username: " + update.message.chat.username + ". Once done, you can press the button 'The other person' and paste this text once asked:"
            context.bot.send_message(chat_id=receiverID, text=message)
            context.bot.send_message(chat_id=receiverID, text=x3dhMessage)
        else:
            context.bot.send_message(chat_id=update.effective_chat.id, text="The username you entered is not in our database. Please check the spelling or ask the user to start a conversation with me")


usersIds = {}
keyBundles = {}
