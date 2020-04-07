import sys
sys.path.insert(0, '..')

import webauth
import os
import sqlalchemy
import jinja2
from flask import Flask, redirect, request
from pyaltt2.config import load_yaml
from pyaltt2.db import Database
from pyaltt2.mail import SMTP
import logging

webauth.logger = logging.getLogger('gunicorn.error')

tldr = jinja2.FileSystemLoader(searchpath='./templates/')
tenv = jinja2.Environment(loader=tldr)

config = load_yaml(os.getenv('WEBAUTH_CONFIG', 'config.yml'))

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


@app.route('/new-email-set-ok')
def new_email_set_ok():
    webauth.clear_confirmed_session()
    return serve_tpl('ok',
                     message='New email address is set',
                     next_uri='/dashboard')

@app.route('/remind-ok')
def remind_ok():
    webauth.clear_confirmed_session()
    return serve_tpl('ok',
                     message='Please check your email for the info',
                     next_uri='/')

@app.route('/old-email-remove-ok')
def old_email_remove_ok():
    return serve_tpl(
        'ok',
        message=
        'Completed. Now check your new email address for the confirmation link',
        next_uri='/dashboard')


@app.route('/set-password', methods=['GET', 'POST'])
def set_password():
    if webauth.is_authenticated():
        if request.method == 'GET':
            return serve_tpl('set-password',
                             confirmed_session=webauth.is_confirmed_session())
        else:
            try:
                if not webauth.is_confirmed_session():
                    webauth.check_user_password(request.form.get('oldpass'),
                                                allow_empty=True)
            except webauth.AccessDenied:
                return serve_tpl('error',
                                 message='old password is not valid',
                                 next_uri='/set-password')
            webauth.set_user_password(request.form.get('password'))
            webauth.clear_confirmed_session()
            return redirect('/dashboard')
    else:
        return redirect('/')


@app.route('/set-email', methods=['GET', 'POST'])
def set_email():
    if webauth.is_authenticated():
        if request.method == 'GET':
            return serve_tpl('set-email', email=webauth.get_user_email())
        else:
            email = request.form.get('email')
            if email == webauth.get_user_email():
                return redirect('/dashboard')
            try:
                webauth.change_user_email(
                    email,
                    next_action_uri_oldaddr='/old-email-remove-ok',
                    next_action_uri='/new-email-set-ok'
                    if webauth.get_user_email() else '/set-password')
                return redirect('/dashboard')
            except webauth.ResourceAlreadyExists:
                return serve_tpl('error', message='E-mail is already in system')
    else:
        return redirect('/')


@app.route('/remind', methods=['POST'])
def remind():
    email = request.form.get('email')
    try:
        webauth.send_account_remind(email, next_action_uri='/set-password')
        return redirect('/remind-ok')
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
