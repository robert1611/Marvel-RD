import os
from marvel_api import app, db, oauth
from flask import render_template, request, redirect, url_for, session, flash, jsonify
from flask_login import login_user, logout_user, current_user, login_required


from marvel_api.forms import UserLoginForm
from marvel_api.models import User, check_password_hash, Marvel, marvel_schema, marvels_schema
from marvel_api.helpers import get_jwt, token_required, verify_owner

# from decouple import config


# Google OAUTH Routes and config info
google = oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_CLIENT_ID_TEST"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET_TEST"),
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    # This is only needed if using openId to fetch user info
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',
    client_kwargs={'scope': 'openid profile'},
)
print(os.getenv("GOOGLE_CLIENT_ID_TEST"))


@app.route('/')
def base():
    # user = User.query.all()
    # print(user)
    return render_template('home.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = UserLoginForm()

    if request.method == 'POST' and form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        print('here', email, password)

        user = User(email, password=password)

        db.session.add(user)
        db.session.commit()

        # flash('Signup successful', 'signup-success')
        return redirect(url_for('signin'))

    # except Exception as e:
      #  raise Exception('Invalid Form Data: Please Check your form') from e

    return render_template('signup.html', form=form)


@app.route('/signin', methods=['GET', 'POST'])
def signin():
    form = UserLoginForm()

    if request.method == 'POST' and form.validate_on_submit():
        # 'here' = form.'here'.data
        email = form.email.data
        password = form.password.data
        print(email, password)

        logged_user = User.query.filter(User.username == email).first()
        if logged_user and check_password_hash(logged_user.password, password):
            login_user(logged_user)
            flash('You were successfully logged in: Via Email/Password',
                  'auth-success')
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
    redirect_uri = url_for('authorize', _external=True)
    return google.authorize_redirect(redirect_uri)


@app.route('/authorize')
def authorize():
    google = oauth.create_client('google')
    token = google.authorize_access_token()
    response = google.get('userinfo')
    user_info = response.json()
    user = oauth.google.userinfo()
    session['profile'] = user_info

    user = User.query.filter_by(username=user_info['email']).first()
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
            username=g_email,
            g_auth_verify=g_verified
        )

        db.session.add(user)
        db.session.commit()
        session.permanent = True
        login_user(user)
        return redirect(url_for('base'))

    print(user_info)
    return redirect(url_for('base'))


@app.route('/profile', methods=['GET'])
@login_required
def profile():
    jwt = get_jwt(current_user)
    return render_template('profile.html', jwt=jwt)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    if session:
        for key in list(session.keys()):
            session.pop(key)
    flash('You were successfully logged out', 'auth-success')
    return redirect(url_for('base'))

# CREATE MARVEL ENDPOINT


@app.route('/marvels', methods=['POST'])
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

    marvel = Marvel(name, description, comics_appeared_in,
                    super_power, owner=user_id, character=character)

    db.session.add(marvel)
    db.session.commit()

    response = marvel_schema.dump(marvel)
    return jsonify(response)

# RETRIEVE ALL MARVEL ENDPOINT


@app.route('/marvels', methods=['GET'])
@token_required
def get_marvels(current_user_token):
    current_user_token = request.headers['X-Access-Token']
    owner_id = verify_owner(current_user_token)
    print(f'owner_id={owner_id}')
    marvels = db.session.query(Marvel).filter(Marvel.owner == owner_id)
    print(marvels.count())
    response = marvels_schema.dump(marvels)
    return jsonify(response)

# #RETRIEVE ONE MARVEL ENDPOINT


@app.route('/marvels/<id>', methods=['GET'])
@token_required
def get_marvel(current_user_token, id):
    marvel = Marvel.query.get(id)
    response = marvel_schema.dump(marvel)
    return jsonify(response)


def _recommendation_1(current_user_token):
    try:
        user: User = verify_owner(current_user_token)
    except:
        return {'error': 'Invalid or expired authentication token'}
    # Later code can rely on the `user` variable containing the
    # currently authenticated user

# @app.route('/marvels', methods=['POST'])


@token_required
def _create_marvel(current_user_token):
    try:
        owner, current_user_token = verify_owner(current_user_token)
    except:
        return jsonify({'error': 'Invalid or expired authentication token'}), 403

    # owner, current_user_token = verify_owner(current_user_token) # does not have to be called again - already called on line 206

    # Instead of lines 197-202, consider _recommendation_1() above

    request_body = request.json
    marvel = Marvel(
        name=request_body['name'],
        description=request_body['description'],
        comics_appeared_in=request_body['comics_appeared_in'],
        super_power=request_body['super_power'],
        owner=owner
    )
    db.session.add(marvel)
    db.session.commit()
    response = marvel_schema.dump(marvel)
    return jsonify(response)


# # UPDATE MARVEL ENDPOINT
@app.route('/marvels/<id>', methods=['PUT', 'POST'])
@token_required
def update_marvel(current_user_token, id):
    marvel = Marvel.query.get(id)  # Get Marvel Instance

    if marvel is None:
        return jsonify({'error': 'Not found'}), 404

    marvel.name = request.json['name']
    marvel.description = request.json['description']
    marvel.comics_appeared_in = request.json['comics_appeared_in']
    marvel.super_power = request.json['super_power']
    marvel.date_created = request.json['date_created']
    # HACK ALERT: The semantics below is more suited to a PATCH request
    # per the RESTful API design patterns

    marvel.character = request.json.get('character') or marvel.character
    marvel.user_id = current_user_token.token

    db.session.commit()
    response = marvel_schema.dump(marvel)
    return jsonify(response)

# # DELETE MARVEL ENPDPOINT


@app.route('/marvels/<id>', methods=['DELETE'])
@token_required
def delete_marvel(current_user_token, id):
    marvel = db.session.query(Marvel).filter(Marvel.id == id,
                                             Marvel.owner == current_user_token.token).first()

    db.session.delete(marvel)
    db.session.commit()
    response = marvel_schema.dump(marvel)
    return jsonify(response)
#idToken: "eyJhbGciOiJSUzI1NiIsImtpZCI6IjBlYmMyZmI5N2QyNWE1MmQ5MjJhOGRkNTRiZmQ4MzhhOTk4MjE2MmIiLCJ0eXAiOiJKV1QifQ.eyJuYW1lIjoiUm9iZXJ0IER1cHJlZSIsInBpY3R1cmUiOiJodHRwczovL2xoNC5nb29nbGV1c2VyY29udGVudC5jb20vLVFuYWU4UG81X3BFL0FBQUFBQUFBQUFJL0FBQUFBQUFBQUFBL0FNWnV1Y2w2dFpfRUpYZDZhRmY1QWJsZHpwemJvNFhmRncvczk2LWMvcGhvdG8uanBnIiwiaXNzIjoiaHR0cHM6Ly9zZWN1cmV0b2tlbi5nb29nbGUuY29tL21hcnZlbC1jb2xsZWN0aW9uLWZyb250ZW5kLXJkIiwiYXVkIjoibWFydmVsLWNvbGxlY3Rpb24tZnJvbnRlbmQtcmQiLCJhdXRoX3RpbWUiOjE2MTQwMDEwNjEsInVzZXJfaWQiOiJ6TThBa1NPT3MwVUUyREZrNUlIV0F4cllWR2wxIiwic3ViIjoiek04QWtTT09zMFVFMkRGazVJSFdBeHJZVkdsMSIsImlhdCI6MTYxNDAwMTA2MSwiZXhwIjoxNjE0MDA0NjYxLCJlbWFpbCI6InJvYmVydDE2MTFAZ21haWwuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImZpcmViYXNlIjp7ImlkZW50aXRpZXMiOnsiZ29vZ2xlLmNvbSI6WyIxMTA4ODc2NzA1MDY1OTYxMjEwMTQiXSwiZW1haWwiOlsicm9iZXJ0MTYxMUBnbWFpbC5jb20iXX0sInNpZ25faW5fcHJvdmlkZXIiOiJnb29nbGUuY29tIn19.hraQkEu6qBp4oOLv3TLHfYBx5X5kas_tGI7w6gZjsaRrsNkrCBjUl-qMLoeoLD4W6RIW-KHayCIRk0-RPVHyPWNjkrOs2T-mF5E5jWjPoaqLEJQxSM8i2P4N9XqEGoVicPvrTxQoCLbgLim6ZcBnOUix9AQC7RI8iFoH2_oLS7zyNsBJsxRnyQplOkHeQbzOCnpSXx5HSrOVm2NiBVmiQOi1RUQAnVzC6h6OjvG-7siw3h2CwVKKiMKvlsrt46Q8xr0YXWvaDHpiK0GNfEqHYNOEKzxEYLIwjWZW3dL2BPk8DBF7OMgc9h5iUIl0_vfZuPAK3WddxQ36d-0w5fAKGg"
#eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJvd25lciI6IjliMjgzZjkzOTMzNWUyNTcyNTA4OTRlNGY2OGIyNTg5NGMxZWIzNDA3YWMyOTQ3ZiIsImFjY2Vzc190aW1lIjoiXCIyMDIxLTAyLTIyIDEzOjM1OjI2LjE1OTcyMFwiIn0.HWmvvF_n4zSzV1M2UIYNSa1H7qIsww5xdk0auODZ2As
