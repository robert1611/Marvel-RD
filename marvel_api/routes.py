from marvel_api import app, db, oauth
from flask import render_template, request, redirect, url_for, session, flash, jsonify
from flask_login import login_user, logout_user, current_user, login_required


from marvel_api.forms import UserLoginForm
from marvel_api.models import User, check_password_hash, Marvel, marvel_schema
from marvel_api.helpers import get_jwt, token_required, verify_owner

from decouple import config

import os

# Google OAUTH Routes and config info
google = oauth.register(
    name='google',
    client_id=config("GOOGLE_CLIENT_ID_TEST"),
    client_secret=config("GOOGLE_CLIENT_SECRET_TEST"),
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',  # This is only needed if using openId to fetch user info
    client_kwargs={'scope': 'openid email profile'},
)
print(config("GOOGLE_CLIENT_ID_TEST"))

@app.route('/')
def base():
    user = User.query.all()
    print(user)
    return render_template('home.html')

@app.route('/signup', methods = ['GET','POST'])
def signup():
    form = UserLoginForm()

    try:
        if request.method == 'POST' and form.validate_on_submit():
            email = form.email.data
            password = form.password.data
            print(email,password)

            user = User(email, password = password)

            db.session.add(user)
            db.session.commit()

            flash('Signup successful', 'signup-success')
            return redirect(url_for('signin'))

    except Exception as e:
        raise Exception('Invalid Form Data: Please Check your form') from e
    
    return render_template('signup.html', form=form)

@app.route('/signin', methods = ['GET','POST'])
def signin():
    form = UserLoginForm()

    
    if request.method == 'POST' and form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        print(email,password)

        logged_user = User.query.filter(User.username == email).first()
        if logged_user and check_password_hash(logged_user.password, password):
            login_user(logged_user)
            flash('You were successfully logged in: Via Email/Password', 'auth-success')
            return redirect(url_for('base'))
        else:
            flash('Your Email/Password is incorrect', 'auth-failed')
            return redirect(url_for('signin'))
    else:
        flash('Invalid form', 'invalid-form')

    

    return render_template('signin.html', form=form)

@app.route('/google-auth')
def google_auth():
    google = oauth.create_client('google')
    redirect_uri = url_for('authorize', _external = True)
    return google.authorize_redirect(redirect_uri)


@app.route('/authorize')
def authorize():
    google = oauth.create_client('google')
    token = google.authorize_access_token()
    response = google.get('userinfo')
    user_info = response.json()
    user = oauth.google.userinfo()
    session['profile'] = user_info

    user = User.query.filter_by(username = user_info['email']).first()
    if user:
        user.username = user_info['email']
        user.g_auth_verify = user_info['verified_email']

        db.session.add(user)
        db.session.commit()
        login_user(user)
        session.permanent = True
        return redirect(url_for('base'))

    else:
        g_email = user_info['email']
        g_verified = user_info['verified_email']

        user = User(
            username = g_email,
            g_auth_verify= g_verified
        )

        db.session.add(user)
        db.session.commit()
        session.permanent = True
        login_user(user)
        return redirect(url_for('base'))

    print(user_info)
    return redirect(url_for('base'))   


@app.route('/profile', methods = ['GET'])
@login_required
def profile():
    jwt = get_jwt(current_user)
    return render_template('profile.html', jwt = jwt)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    if session:
        for key in list(session.keys()):
            session.pop(key)
    flash('You were successfully logged out', 'auth-success')
    return redirect(url_for('base'))

#CREATE MARVEL ENDPOINT
@app.route('/marvel', methods = ['POST'])
@token_required
def create_marvel(current_user_token):
    print(current_user_token)
    name = request.json['name']
    description = request.json['description']
    comics_appeared_in = request.json['comics_appeared_in']
    super_power = request.json['super_power']
    date_created = request.json['date_created']
    character = request.json['character']
    user_id = current_user_token.token

    marvel = Marvel(name, description, comics_appeared_in, super_power, owner=user_id)

    db.session.add(marvel)
    db.session.commit()

    response = marvel_schema.dump(marvel)
    return jsonify (response)

# RETRIEVE ALL MARVEL ENDPOINT
@app.route('/marvel', methods = ['GET'])
@token_required
def get_marvels(current_user_token):
    try:
        owner, current_user_token = verify_owner(current_user_token)
    except:
        bad_res = verify_owner(current_user_token)
        return bad_res
    owner, current_user_token = verify_owner(current_user_token)
    marvel = Marvel.query.filter_by(user_id = owner.user_id).all()
    response = marvel_schema.dump(marvel)
    return jsonify(response)

# #RETRIEVE ONE MARVEL ENDPOINT
@app.route('/marvels/<id>', methods = ['GET'])
@token_required
def get_marvel(current_user_token, id):
    try:
        owner, current_user_token = verify_owner(current_user_token)
    except:
        bad_res = verify_owner(current_user_token)
        return bad_ress
    owner, current_user_token = verify_owner(current_user_token)
    marvel = Marvel.query.get(id)
    response = marvel_schema.dump(marvel)
    return jsonify(response)

# # UPDATE MARVEL ENDPOINT
@app.route('/marvels/<id>', methods = ['POST', 'PUT'])
@token_required
def update_marvel(current_user_token, id):
    try:
        owner, current_user_token = verify_owner(current_user_token)
    except:
        bad_res = verify_owner(current_user_token)
        return bad_res
    owner, current_user_token = verify_owner(current_user_token)
    marvel - Marvel.query.get(id) # Get Marvel Instance
    
    marvel.name = request.json['name']
    marvel.price = request.json['price']
    marvel.model = request.json['model']

    db.session.commit()
    response = marvel_schema.dump(marvel)
    return jsonify(response)

# # DELETE MARVEL ENPDPOINT
@app.route('/marvels/<id>', methods = ['DELETE'])
@token_required
def delete_marvel(current_user_token,id):
    try:
        owner, current_user_token = verify_owner(current_user_token)
    except:
        bad_res = verify_owner(current_user_token)
        return bad_res
    owner, current_user_token - verify_owner(current_user_token)
    marvel - Marvel.query.get(id) #Get marvel instance
    db.session.delete(marvel)
    db.session.commit()
    response = marvel_schema.dump(marvel)
    return jsonify(response)
