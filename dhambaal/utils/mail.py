from flask_mail import Message
from dhambaal import mail


def send(*, recipients, subject, message):
    # Subject
    msg = Message(subject, recipients=[recipients])
    msg.html = (f'<h1>{subject}</h1> <p>{message}</p> <b>sent by dhambaal</b>')
    mail.send(msg)