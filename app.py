from flask import Flask, render_template, request, jsonify,redirect, url_for, flash, make_response, session
import requests
import re
# import secrets
from googletrans import Translator
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, date, time, timedelta
from sqlalchemy import select, func, desc
from model import Translation, User
from forms import LoginForm, RegisterForm
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_oauthlib.client import OAuth
from flask_mail import Mail, Message
import os
import uuid
from itsdangerous import URLSafeTimedSerializer

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///translations.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
# app.secret_key = secrets.token_hex(16)  # Utilisez la clé générée ici
app.secret_key = '3494118c38f157b365844553f6ea1d78'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=0.24)

# Configuration de Flask-Mail
app.config['MAIL_SERVER'] = 'smtp-shopraphia.alwaysdata.net'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'shopraphia@alwaysdata.net'
app.config['MAIL_PASSWORD'] = '@laptop12'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

mail = Mail(app)
serializer = URLSafeTimedSerializer(app.secret_key)

oauth = OAuth(app)
# 
db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

google = oauth.remote_app(
    'google',
    consumer_key='17857114237-hpk5opqe9saff15bj6ofdkev9n3d8qi7.apps.googleusercontent.com',
    consumer_secret='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',
    request_token_params={
        'scope': 'email',
    },
    base_url='https://www.googleapis.com/oauth2/v1/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
)

facebook = oauth.remote_app(
    'facebook',
    consumer_key='451656697480861',
    consumer_secret='b3a6cfb75e697e4fb40206e437812985',
    request_token_params={'scope': 'email'},
    base_url='https://graph.facebook.com/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='/oauth/access_token',
    authorize_url='https://www.facebook.com/dialog/oauth',
)

users_db = {}

# exit()
# Page d'accueil
@app.route('/',  endpoint='home')
# @login_required
def home():
    
    form = LoginForm()
    formRegister = RegisterForm()

    username = session.get('username')

    if username:
        return render_template('index.html', formLogin = form, formRegister = formRegister, FK_b05SbbY=username)
    else : 
        return render_template('index.html', formLogin = form, formRegister = formRegister, FK_b05SbbY=False)

@app.route('/<key>',  endpoint='homeSpecific')
# @login_required
def homeSpecific(key):
    form = LoginForm()
    formRegister = RegisterForm()

    username = session.get('username')

    key = getCodeBy(key)

    if username:
        return render_template('specific.html', formLogin = form, formRegister = formRegister, FK_b05SbbY=username, KEY = key)
    else : 
        return render_template('specific.html', formLogin = form, formRegister = formRegister, FK_b05SbbY=False, KEY = key)

# @app.route('/reset-password-request',  endpoint='request_password')
# def templinitPassword():
#     form = LoginForm()
#     formRegister = RegisterForm()

#     username = session.get('username')

#     return render_template('set-password.html')

@app.route('/reset-password',  endpoint='reset_password')
# @login_required
def initPassword():

    token = request.args.get('token')
    email = ""
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=3600)
    except:
        return jsonify({'success': False, 'message': 'The password reset link is invalid or has expired.'}), 400
    
    if request.method == 'POST':
        data = request.get_json()
        new_password = data.get('password')
        confirm_password = data.get('confirm_password')
        if new_password == confirm_password:

            # Vous devez ajouter la logique pour mettre à jour le mot de passe de l'utilisateur ici.
            user = User.query.filter_by(email=email).first()
            user.set_password(new_password)
            db.session.commit()
            return jsonify({'success': True, 'message': 'Votre mot de passe été initialié.'})
        else:
            return jsonify({'success': False, 'message': 'Mot de passe different!'})
    
    return render_template('set-password.html')
    

# Route pour la traduction
@app.route('/translate', methods=['POST'])
def translate():
    data = request.json
    text_to_translate = data['text']
    translated_text = translate_text(text_to_translate)

    save_translation(text_to_translate, 'fr', 'mg', translated_text)

    return jsonify({'translated_text': translated_text})

@app.route('/getLast-history', methods=['GET'])
def getLastHistory():
    # all_history = get_translation_history()
    all_history = get_last_translation_history()

    # Convertir les objets de modèle SQLAlchemy en dictionnaires pour la sérialisation JSON
    history_json = [{'text_origin': item.text_origin, 'langue_origin': item.langue_origin, 'langue_target': item.langue_target,'translated_text': item.translated_text, 'translated_at': item.translated_at} for item in all_history]
    # print(history_json)
    return jsonify({'historique': history_json})

@app.route('/getAll-history-byDate', methods=['GET'])
def getAllHistoryByDate():

    key = request.args.get('key')

    # Utilisez la méthode de découpe de chaîne pour extraire les parties de la date
    year = key[:4]
    month = key[4:6]
    day = key[6:]

    # Reconstituez la date avec les parties séparées par des tirets
    formatted_date_str = f"{year}-{month}-{day}"

    # Faites une requête pour récupérer les traductions groupées par date
    translations_for_date = Translation.query.filter(func.DATE(Translation.translated_at) == formatted_date_str).all()

    # Convertir les objets de modèle SQLAlchemy en dictionnaires pour la sérialisation JSON
    history_json = [{'text_origin': item.text_origin, 'langue_origin': item.langue_origin, 'langue_target': item.langue_target,'translated_text': item.translated_text, 'translated_at': item.translated_at} for item in translations_for_date]
    # print(history_json)
    return jsonify({'historique': history_json})

@app.route('/getAllGroupedByDate', methods=['GET'])
def getAllGroupedHistory():
    # Faites une requête pour récupérer les traductions groupées par date
    translations_grouped_by_date = db.session.query(Translation.text_origin, func.DATE(Translation.translated_at), func.count()).group_by(func.DATE(Translation.translated_at)).order_by(desc(Translation.translated_at)).all()

    # Convertir les objets de modèle SQLAlchemy en dictionnaires pour la sérialisation JSON
    translations_grouped_by_date_dicts = [{'text_origin': row[0], 'date': row[1], 'key': row[1].replace("-",""), 'count': row[2]} for row in translations_grouped_by_date]

    # print(translations_grouped_by_date)
    return jsonify(translations_grouped_by_date_dicts)

def translate_text(text, src='fr', dest='mg'):
    # Appel à l'API de traduction (à implémenter)
    translator = Translator()
    translated = translator.translate(text, src=src, dest=dest)
    return translated.text

def save_translation(text_origin, langue_origin, langue_target, translated_text):
    translation = Translation(text_origin=text_origin, langue_origin=langue_origin, langue_target=langue_target, translated_text=translated_text)
    db.session.add(translation)
    db.session.commit()

def get_translation_history():
    return Translation.query.all()

def get_last_translation_history():
    # Obtenez la date d'aujourd'hui
    today_date = date.today()

    # Faites une requête pour récupérer les traductions réalisées aujourd'hui
    translations_today = Translation.query.filter(Translation.translated_at >= today_date).all()

    return translations_today

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if request.method == 'POST':
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            session['username'] = user.username

            return redirect(url_for('home'))
        else : 
            message = "Le mot de passe que vous avez entré n'est pas correct!"
            link ="/"
            return render_template('error.html', message=message, link = link)
    else:
        return redirect(url_for('home'))
    
    # return redirect(url_for('home'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    # form = LoginForm()
    formRegister = RegisterForm()
    # if formRegister.validate_on_submit():
    if request.method == 'POST':

        if formRegister.password.data == formRegister.confirm_password.data :
            hashed_password = generate_password_hash(formRegister.password.data, method='sha256')
            new_user = User(username=formRegister.username.data, email=formRegister.email.data, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            session['username'] = new_user.username
            return redirect(url_for('home'))
           
        else : 
            message = "Le mot de passe que vous avez créé n'est pas identiques!"
            link ="/"
            return render_template('error.html', message=message, link = link)
        
    # return render_template('index.html', formLogin=form, formRegister=formRegister, FK_b05SbbY=session.get('username'))

@app.route('/login/g')
def loginGoogle():
    return google.authorize(callback=url_for('authorizedGoogle', _external=True))

@app.route('/login/g/authorized')
def authorizedGoogle():
    resp = google.authorized_response()
    if resp is None or resp.get('access_token') is None:
        return 'Accès refusé: raison=%s erreur=%s' % (
            request.args['error_reason'],
            request.args['error_description']
        )
    
    session['google_token'] = (resp['access_token'], '')
    user_info = google.get('userinfo')
    session['username'] = user_info.data['name']

    # Traitez les informations de l'utilisateur comme bon vous semble
    return 'Vous êtes connecté en tant que: ' + user_info.data['email']

@app.route('/login/fb')
def loginFb():
    return facebook.authorize(callback=url_for('authorizedFb', _external=True))

@app.route('/login/fb/authorized')
def authorizedFb():
    resp = facebook.authorized_response()
    if resp is None or 'access_token' not in resp:
        return 'Access denied: reason={}, error={}'.format(
            request.args['error_reason'],
            request.args['error_description']
        )
    
    session['facebook_token'] = (resp['access_token'], '')
    me = facebook.get('/me')
    session['username'] = me.data['name']
    return 'Logged in as {}! <a href="/logout">Logout</a>'.format(me.data['name'])



@app.route('/logout')
# @login_required
def logout():

    logout_user()
    session["username"] = False
    return redirect(url_for('home'))

@app.route('/all-users')
def getAllUser():

    all_users = User.query.all()
    history_json = [{'id': item.id,'username': item.username, 'email': item.email, 'password': item.password} for item in all_users]
    # print(history_json)
    return jsonify(history_json)

def getCodeBy(str):
    # Remplacer la partie '-e07712edd737' par une chaîne vide
    modified_string = re.sub(r'-e07712edd737', '', str)

    # Remplacer les caractères non-chiffres par une chaîne vide
    result = re.sub(r'\D', '', modified_string)
    return result

@app.route('/send-reset-email', methods=['POST'])
def send_reset_email():
    data = request.get_json()
    email = data.get('email')
    
    # Vérifiez si l'email est valide dans votre base de données
    user = User.query.filter_by(email=email).first()
    # user = True  # Remplacer par la vérification réelle

    if not user:
        return jsonify({'success': False, 'message': 'Email not found'}), 404

    token = serializer.dumps(email, salt='password-reset-salt')
    link = url_for('reset_password', token=token, _external=True)
    
    msg = Message('Réinitialisation du mot de passe', sender='shopraphia@alwaysdata.net', recipients=[email])
    msg.body = f'Cliquez sur le lien pour réinitialiser votre mot de passe {link}'
    mail.send(msg)

    return jsonify({'success': True, 'message': 'E-mail de réinitialisation du mot de passe envoyé'})


if __name__ == '__main__':
    app.run(debug=True)
