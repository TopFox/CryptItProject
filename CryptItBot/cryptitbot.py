from telegram.ext import CommandHandler, Updater, MessageHandler, CallbackQueryHandler, Filters
from telegram import InlineKeyboardButton, InlineKeyboardMarkup
import logging
import databaseManagement as dbm
import encryption as crpt

def start(update, context):
    context.bot.send_message(chat_id=update.effective_chat.id, text="Hi! I'm CryptItBot, you can use me to encrypt messages before sending them to many people")
    dbm.storeUser(id=update.message.chat.id, username=update.message.chat.username)

def helpCommand(update, context):
    context.bot.send_message(chat_id=update.effective_chat.id, text="Help message")

def createGroup(update, context):
    numberOfArguments = len(context.args)
    if numberOfArguments == 0:
        context.bot.send_message(chat_id=update.effective_chat.id, text="Please enter the name of the group. For example: \n\n /createGroup groupName")
    elif numberOfArguments > 1:
        context.bot.send_message(chat_id=update.effective_chat.id, text="Please enter a name for the group without spaces. For example: \n\n /createGroup groupName")
    else:
        groupName = context.args[0]
        if dbm.storeGroup(username=update.message.chat.username, groupName=groupName):
            message = "The group " + groupName + " was created !"
            context.bot.send_message(chat_id=update.effective_chat.id, text=message)
        else:
            context.bot.send_message(chat_id=update.effective_chat.id, text="The group name you specified is already used, please choose another one.")

def addMember(update, context):
    numberOfArguments = len(context.args)
    if numberOfArguments != 2:
        context.bot.send_message(chat_id=update.effective_chat.id, text="Please enter the name of the group and the username you want to add. For example: \n\n /addMember groupName username")
    else:
        groupName = context.args[0]
        username = context.args[1]
        if dbm.addUserToGroup(groupName=groupName, usernameToAdd=username):
            message = "The user " + usernameToAdd + " was successfully added to your group " + groupName
            context.bot.send_message(chat_id=update.effective_chat.id, text=message)
        else:
            context.bot.send_message(chat_id=update.effective_chat.id, text="The username you entered is not in our database. Please check the spelling or ask the user to start a conversation with me")

def decryptCallback(update, context):
    query = update.callback_query
    userID = query.message.chat.id

    if query.data == 'decrypt':
        encryptedMessage = query.message.text[55:]
        decryptedMessage = crpt.decryptMessage(encryptedMessage, userID)
        query.answer(text=decryptedMessage, show_alert=True)
    else:
        query.answer()

def sendMessage(update, context):
    numberOfArguments = len(context.args)
    if numberOfArguments < 2:
        context.bot.send_message(chat_id=update.effective_chat.id, text="Please enter the name of the username and the message you want to send. For example: \n\n /sendMessage username Hello my friend")
    else:
        username = context.args[0]
        message = ' '.join(context.args[1:])
        receiverID = dbm.retrieveUserId(username)
        if receiverID >= 0:
            encryptedMessage = crpt.encryptMessage(message, receiverID)
            keyboard = [[InlineKeyboardButton("Decrypt", callback_data='decrypt')]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            messageToShow = "You receieved a crypted message from " + update.message.chat.username + ": \n\n" + encryptedMessage
            context.bot.send_message(chat_id=receiverID, text=messageToShow, reply_markup=reply_markup)
        else:
            context.bot.send_message(chat_id=update.effective_chat.id, text="The username you entered is not in our database. Please check the spelling or ask the user to start a conversation with me")

def sendGroupMessage(update, context):
    numberOfArguments = len(context.args)
    userID = update.effective_chat.id
    if numberOfArguments < 2:
        context.bot.send_message(chat_id=userID, text="Please enter the name of the group and the message you want to send. For example: \n\n /sendGroupMessage groupName Hello my friends")
    else:
        groupName = context.args[0]
        message = ' '.join(context.args[1:])
        keyboard = [[InlineKeyboardButton("Decrypt", callback_data='decrypt')]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        groupID = dbm.retrieveGroupId(groupName)
        if groupID >= 0:
            members = dbm.retrieveGroupMembersChatIds(groupID)
            if len(members) >= 2:
                for member in members:
                    if member != userID:
                        encryptedMessage = crpt.encryptMessage(message, member)
                        messageToShow = "You receieved a crypted message from " + update.message.chat.username + " in the group " + groupName + ": \n\n" + encryptedMessage
                        context.bot.send_message(chat_id=member, text=messageToShow, reply_markup=reply_markup)
            else:
                context.bot.send_message(chat_id=userID, text="You are alone in this group. If you want to add members, use: \n\n /addMember groupName username")
        else:
            context.bot.send_message(chat_id=userID, text="Please enter the name of a group you are in. If you want to create a group, use: \n\n /createGroup groupName")

def debug(update, context):
    print(update)
    print(context)

def unknown(update, context):
    context.bot.send_message(chat_id=update.effective_chat.id, text="Sorry, I didn't understand that command.")

def main():
    updater = Updater(token='1946101482:AAGIQsEryZBoVRrvDFOBh8Qhv1x574P1N8E', use_context=True)
    dispatcher = updater.dispatcher
    logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)

    startHandler = CommandHandler('start', start)
    dispatcher.add_handler(startHandler)

    helpHandler = CommandHandler('help', helpCommand)
    dispatcher.add_handler(helpHandler)

    createGroupHandler = CommandHandler('createGroup', createGroup)
    dispatcher.add_handler(createGroupHandler)

    addMemberHandler = CommandHandler('addMember', addMember)
    dispatcher.add_handler(addMemberHandler)

    sendMessageHandler = CommandHandler('sendMessage', sendMessage)
    dispatcher.add_handler(sendMessageHandler)

    sendGroupMessageHandler = CommandHandler('sendGroupMessage', sendGroupMessage)
    dispatcher.add_handler(sendGroupMessageHandler)

    decryptHandler = CallbackQueryHandler(decryptCallback)
    dispatcher.add_handler(decryptHandler)

    debugHandler = MessageHandler(Filters.text & (~Filters.command), debug)
    dispatcher.add_handler(debugHandler)

    unknownHandler = MessageHandler(Filters.command, unknown)
    dispatcher.add_handler(unknownHandler)

    updater.start_polling()
    updater.idle()

if __name__ == '__main__':
    main()
