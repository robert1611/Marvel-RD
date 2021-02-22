from marvel_api import app, db, login_manager, ma
from flask_login import UserMixin
import uuid
from datetime import datetime

#Adding Flask Security for Passwords
from  werkzeug.security import generate_password_hash, check_password_hash

import secrets

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(150), nullable = False, default='')
    password = db.Column(db.String, nullable = True, default = '')
    g_auth_verify = db.Column(db.Boolean, default = False)
    token = db.Column(db.String, default ='')
    date_created = db.Column(db.DateTime, nullable = False, default = datetime.utcnow)
    #character = db.Column(db.Integer, db.ForeignKey('marvel.id'), nullable = False)
    character = db.Column(db.Integer, nullable = True) 
    # email has to be specified, everything else can be empty
    # haven't entered token g_auth yet

    def __init__(self, username, password ='', g_auth_verify = False):
        
        self.id = self.set_id()
        self.username = username
        self.password = self.set_password(password)
        self.token = self.set_token(24)
        self.g_auth_verify = g_auth_verify

    def set_token(self,length):
        return secrets.token_hex(length)

    def set_id(self):
        return str(uuid.uuid4())

    def set_password(self, password):
        self.pw_hash = generate_password_hash(password)
        return self.pw_hash

    def __repr__(self):
        return f'User {self.username} has been added to the database'

class Marvel(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(150))
    description = db.Column(db.String(150))
    comics_appeared_in = db.Column(db.Integer)
    super_power = db.Column(db.String(150))
    date_created = db.Column(db.DateTime, nullable = False, default = datetime.utcnow)
    owner = db.Column(db.String, db.ForeignKey('user.token'), nullable = False)
    character = db.Column(db.String(150))

    def __init__(self, name, description, comics_appeared_in, super_power, owner, character):

        self.name = name
        self.description = description
        self.comics_appeared_in = comics_appeared_in
        self.super_power = super_power
        self.owner = owner
        self.character = character

    def set_id(self):
        return str(uuid.uuid4())
        
    def __repr__(self):
        return f'The following Marvel has been added {self.name}'
    
    def __str__(self):
        return f"{self.name}\n\nDescription:\n{self.description}\n\nSuperpowers:\n{self.super_power}"

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "comics_appeared_in": self.comics_appeared_in,
            "super_power": self.super_power,
            "date_created": self.date_created,
            "character": self.character
        }

#creation of API Schema via the Marshmallow Object

class MarvelSchema(ma.Schema):
    class Meta:
        fields = ['id','name','description','comics_appeared_in', 'super_power','date_created','character']

marvel_schema = MarvelSchema()
marvels_schema = MarvelSchema(many = True)  #marvelSchema gives you the ability to respond in JSON
