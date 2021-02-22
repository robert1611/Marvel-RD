import os
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
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'You will never guess'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'postgresql://postgres:Robert1972@127.0.0.1:5432/marvel_api')
    #'postgresql://postgres:Robert1972@127.0.0.1:5432/marvel_api'
    print(SQLALCHEMY_DATABASE_URI)
    SQLALCHEMY_TRACK_MODIFICATIONS = False #Turn off update messages