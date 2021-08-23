from telegram.ext import CommandHandler, Updater, MessageHandler, CallbackQueryHandler, Filters
import logging
from protocol import getKeyBundle, publishKeyBundle, x3dhHello, sendGroupMessage

def start(update, context):
    context.bot.send_message(chat_id=update.effective_chat.id, text="Hi! I'm CryptItBot, you can use me to encrypt messages before sending them to many people")

def helpCommand(update, context):
    context.bot.send_message(chat_id=update.effective_chat.id, text="Help message")

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

    getKeyBundlepHandler = CommandHandler('getKeyBundle', getKeyBundle)
    dispatcher.add_handler(getKeyBundlepHandler)

    publishKeyBundlepHandler = CommandHandler('publishKeyBundle', publishKeyBundle)
    dispatcher.add_handler(publishKeyBundlepHandler)

    x3dhHelloHandler = CommandHandler('x3dhHello', x3dhHello)
    dispatcher.add_handler(x3dhHelloHandler)

    sendGroupMessageHandler = CommandHandler('sendGroupMessage', sendGroupMessage)
    dispatcher.add_handler(sendGroupMessageHandler)

    debugHandler = MessageHandler(Filters.text & (~Filters.command), debug)
    dispatcher.add_handler(debugHandler)

    unknownHandler = MessageHandler(Filters.command, unknown)
    dispatcher.add_handler(unknownHandler)

    updater.start_polling()
    updater.idle()

if __name__ == '__main__':
    main()
