from telegram.ext import CommandHandler, Updater, MessageHandler, CallbackQueryHandler, Filters
import logging
from protocol import getKeyBundle, publishKeyBundle, x3dhHello, sendGroupMessage

# Message displayed on command /start
def start(update, context):
    context.bot.send_message(chat_id=update.effective_chat.id, text="Hi! I'm CryptItBot, you can use me to encrypt messages before sending them to many people")

# Message displayed when an unkown command is sent
def unknown(update, context):
    context.bot.send_message(chat_id=update.effective_chat.id, text="Sorry, I didn't understand that command.")

def main():
    updater = Updater(token='1946101482:AAGIQsEryZBoVRrvDFOBh8Qhv1x574P1N8E', use_context=True) # Token of the bot
    dispatcher = updater.dispatcher
    logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO) # Logging system

    startHandler = CommandHandler('start', start)
    dispatcher.add_handler(startHandler)

    getKeyBundlepHandler = CommandHandler('getKeyBundle', getKeyBundle)
    dispatcher.add_handler(getKeyBundlepHandler)

    publishKeyBundlepHandler = CommandHandler('publishKeyBundle', publishKeyBundle)
    dispatcher.add_handler(publishKeyBundlepHandler)

    x3dhHelloHandler = CommandHandler('x3dhHello', x3dhHello)
    dispatcher.add_handler(x3dhHelloHandler)

    sendGroupMessageHandler = CommandHandler('sendGroupMessage', sendGroupMessage)
    dispatcher.add_handler(sendGroupMessageHandler)

    unknownHandler = MessageHandler(Filters.command, unknown)
    dispatcher.add_handler(unknownHandler)

    updater.start_polling()
    updater.idle()

if __name__ == '__main__':
    main()
