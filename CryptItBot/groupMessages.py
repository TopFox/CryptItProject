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

def sendGroupMessage(update, context):
    numberOfArguments = len(context.args)
    userID = update.effective_chat.id
    if numberOfArguments < 2:
        context.bot.send_message(chat_id=userID, text="Please enter the name of the group and the message you want to send. For example: \n\n /sendGroupMessage groupName Hello my friends")
    else:
        groupName = context.args[0]
        message = ' '.join(context.args[1:])
        groupID = dbm.retrieveGroupId(groupName)
        if groupID >= 0:
            members = dbm.retrieveGroupMembersChatIds(groupID)
            if len(members) >= 2:
                for member in members:
                    if member != userID:
                        encryptedMessage = crpt.encryptMessage(message, member)
                        messageToShow = "You receieved a crypted message from " + update.message.chat.username + " in the group " + groupName + ": \n\n" + encryptedMessage
                        context.bot.send_message(chat_id=member, text=messageToShow)
            else:
                context.bot.send_message(chat_id=userID, text="You are alone in this group. If you want to add members, use: \n\n /addMember groupName username")
        else:
            context.bot.send_message(chat_id=userID, text="Please enter the name of a group you are in. If you want to create a group, use: \n\n /createGroup groupName")
