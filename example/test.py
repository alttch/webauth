import sys
sys.path.insert(0, '..')

import webauth
import sqlalchemy
import pyaltt2.db
import jinja2
from flask import Flask, redirect, request
from pyaltt2.config import load_yaml

tldr = jinja2.FileSystemLoader(searchpath='./templates/')
tenv = jinja2.Environment(loader=tldr)

config = load_yaml('config.yml')

app = Flask(__name__)

pyaltt2.db.create_engine('postgresql://test:123@localhost/test')

webauth.init(app, dbconn_func=pyaltt2.db.get_db, config=config)
webauth.register_handler(
    'exception.provider_exists',
    lambda: serve_tpl('error',
                      message='This account is already in use by another user',
                      next='/dashboard'))
webauth.register_handler(
    'exception.provider_failed', lambda: serve_tpl(
        'error', message='Provider registration failed', next='/dashboard'))


def serve_tpl(tpl_file, **kwargs):
    tpl = tenv.get_template(f'{tpl_file}.j2')
    d = {
        'authenticated': webauth.is_authenticated(),
        'uid': webauth.get_user_id()
    }
    d.update(kwargs)
    return tpl.render(d)


@app.route('/')
def index():
    return serve_tpl('index')


@app.route('/dashboard')
def dashboard():
    if webauth.is_authenticated():
        return serve_tpl('dashboard', providers=webauth.get_user_providers())
    else:
        return redirect('/')


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
                         next='/dashboard')
    except webauth.AccessDenied:
        return serve_tpl('error', message='Access denied', next='/')


@app.route('/delete-account')
def delete_account():
    try:
        return webauth.delete_user()
    except webauth.AccessDenied:
        return serve_tpl('error', message='Access denied', next='/')


@app.route('/oauth-login/<provider>')
def oauth_login(provider):
    webauth.set_next('/dashboard')
    return redirect(f'/auth/{provider}/login')
