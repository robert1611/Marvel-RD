import os
from decouple import config
basedir = os.path.abspath(os.path.dirname(__file__))

#Give access to the project in ANY OS we find ourlselves in
#Allow outside files / folders to be added to the project
#from the base directory

class Config():
    """
        Set config variables for the flask app
        Using Environment variables where available otherwise
        create the config variable if not done already

    """
    SECRET_KEY = config('SECRET_KEY') or 'You will never guess'
    SQLALCHEMY_DATABASE_URI = config('DATABASE_URL') or 'sqlite:///' + os.path.join(basedir, 'app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False #Turn off update notifications from SQL ALCHEMY