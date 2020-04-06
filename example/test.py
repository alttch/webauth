import sys
sys.path.insert(0, '..')

import webauth
import sqlalchemy
import jinja2
from flask import Flask, redirect, request
from pyaltt2.config import load_yaml
from pyaltt2.db import Database
from pyaltt2.mail import SMTP

tldr = jinja2.FileSystemLoader(searchpath='./templates/')
tenv = jinja2.Environment(loader=tldr)

config = load_yaml('config.yml')

app = Flask(__name__)

db = Database('postgresql://test:123@localhost/test')

webauth.init(app, db=db, config=config, smtp=SMTP(host='10.90.1.8'))
webauth.user_unconfirmed_expires = 10
webauth.register_handler(
    'exception.provider_exists',
    lambda: serve_tpl('error',
                      message='This account is already in use by another user',
                      next_uri='/dashboard'))
webauth.register_handler(
    'exception.provider_failed', lambda: serve_tpl(
        'error', message='Provider registration failed', next_uri='/dashboard'))


def serve_tpl(tpl_file, **kwargs):
    tpl = tenv.get_template(f'{tpl_file}.j2')
    d = {
        'authenticated': webauth.is_authenticated(),
        'uid': webauth.get_user_id(),
        'confirmed': webauth.is_confirmed(),
        'picture': webauth.get_user_picture()
    }
    d.update(kwargs)
    return tpl.render(d)


@app.route('/')
def index():
    return serve_tpl('index')


@app.route('/login', methods=['POST'])
def login():
    email = request.form.get('email')
    password = request.form.get('password')
    try:
        webauth.login(email, password)
        return redirect('/dashboard')
    except webauth.AccessDenied:
        return serve_tpl('error', message='Access denied', next_uri='/')


@app.route('/resend-confirm')
def resend_confirm():
    webauth.resend_email_confirm(next_action_uri='/dashboard')
    return redirect('/dashboard')


@app.route('/dashboard')
def dashboard():
    if webauth.is_authenticated():
        return serve_tpl('dashboard',
                         providers=webauth.get_user_providers(),
                         email=webauth.get_user_email())
    else:
        return redirect('/')


@app.route('/remind', methods=['POST'])
def remind():
    email = request.form.get('email')
    try:
        webauth.send_reset_password(email, next_action_uri='/dashboard')
        return redirect('/')
    except LookupError:
        return serve_tpl('error', message='user does not exists', next_uri='/')


@app.route('/register', methods=['POST'])
def register():
    email = request.form.get('email')
    password = request.form.get('password')
    webauth.set_next('/dashboard')
    try:
        return webauth.register(email,
                                password,
                                confirmed=False,
                                next_action_uri='/dashboard')
    except webauth.ResourceAlreadyExists:
        return serve_tpl('error',
                         message='This email is already registered',
                         next_uri='/')


@app.route('/delete-provider')
def delete_provider():
    provider = request.args.get('provider')
    sub = request.args.get('sub')
    try:
        webauth.delete_user_provider(provider=provider, sub=sub)
        return redirect('/dashboard')
    except webauth.ResourceBusy:
        return serve_tpl('error',
                         message='Last provider can not be deleted',
                         next_uri='/dashboard')
    except webauth.AccessDenied:
        return serve_tpl('error', message='Access denied', next_uri='/')


@app.route('/delete-account')
def delete_account():
    try:
        return webauth.delete_user()
    except webauth.AccessDenied:
        return serve_tpl('error', message='Access denied', next_uri='/')


@app.route('/oauth-login/<provider>')
def oauth_login(provider):
    webauth.set_next('/dashboard')
    return redirect(f'/auth/{provider}/login')
