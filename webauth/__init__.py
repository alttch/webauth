__author__ = 'Altertech, https://www.altertech.com/'
__copyright__ = 'Copyright (C) 2020 Altertech'
__license__ = 'MIT'
__version__ = '0.0.17'

# TODO: 2fa

from flask import redirect, session, url_for, Response, request
from authlib.flask.client import OAuth
from pyaltt2.config import config_value
from pyaltt2.crypto import gen_random_str
from pyaltt2.res import ResourceStorage
from pyaltt2.db import KVStorage
from types import SimpleNamespace
from functools import partial
from hashlib import sha256
import loginpass
import logging
import datetime
import sqlalchemy

email_sender = 'webauth-test@lab.altt.ch'
"""
Default email sender (From: field)
"""
email_tpl = {
    'email.confirm': {
        'subject': 'Please confirm your email address',
        'text': 'Please click on the link {action_link} '
                'to confirm your email address',
        'html': '<html><body>Please click <a href="{action_link}">here</a>'
                ' to confirm your email address</body></html>',
        'expires': 86400
    },
    'email.change': {
        'subject': 'Please allow email address change',
        'text': 'Please click on the link {action_link} '
                'to allow email address change',
        'html': '<html><body>Please click <a href="{action_link}">here</a>'
                ' to allow email address change</body></html>',
        'expires': 86400
    },
    'account.remind': {
        'subject':
            'Password reset',
        'text':
            'Please click on the link {action_link} to reset your password',
        'html':
            '<html><body>Please click <a href="{action_link}">here</a>' +
            ' to reset your password</body></html>',
        'expires':
            86400
    }
}
"""
E-mail templates. Each template contains fields

* subject: message subject
* text: text message (should contain {action_link} variable)
* html: HTML message (should contain {action_link} variable)
* expires: confirm action link expiration in seconds or datetime.timedelta

Templates

* email.confirm: email confirmation
* email.change: change email - change old emal confirmation on email change
* password.reset: password reset
"""

handlers = {}

_d = SimpleNamespace()

allow_registration = True
"""
Allow new user registration
"""

user_unconfirmed_expires = 86400
"""
Default expiration time (seconds or datetime.timedelta) for the unconfirmed
users
"""

real_ip_header = None
"""
Real IP header, if front-end server is used (e.g. X-Real-IP)
"""

log_user_events = True
"""
Log user events, if False, events are logged only to DEBUG log
"""

rs = ResourceStorage(mod='webauth')

rq = partial(rs.get, resource_subdir='sql', ext='sql')

logger = logging.getLogger('webauth')
"""
Override logger e.g. to "gunicorn.error" to use with gunicorn
"""

_provider_mod = {
    'battlenet': loginpass.BattleNet,
    'twitter': loginpass.Twitter,
    'facebook': loginpass.Facebook,
    'google': loginpass.Google,
    'github': loginpass.GitHub,
    'dropbox': loginpass.Dropbox,
    'instagram': loginpass.Instagram,
    'reddit': loginpass.Reddit,
    'gitlab': loginpass.Gitlab,
    'slack': loginpass.Slack,
    'discord': loginpass.Discord,
    'stackoverflow': loginpass.StackOverflow,
    'bitbucket': loginpass.Bitbucket,
    'strava': loginpass.Strava,
    'spotify': loginpass.Spotify,
    'yandex': loginpass.Yandex,
    'twitch': loginpass.Twitch,
    'vk': loginpass.VK
}


class AccessDenied(Exception):
    """
    Exception class: access is denied
    """
    pass


class ResourceAlreadyExists(Exception):
    """
    Exception class: resource already exists
    """
    pass


class ResourceBusy(Exception):
    """
    Exception class: resource is busy (ca not be removed or replaced)
    """
    pass


def http_real_ip():
    return request.headers.get(
        real_ip_header,
        request.remote_addr) if real_ip_header else request.remote_addr


def register_handler(event, handler):
    """
    Register event handler

    Events:

    * account.register: new user registration (user_id=user_id)
    * account.login: login (user_id=user_id)
    * account.remind: password reset request (user_id=user_id)
    * account.delete: user account deletion (user_id=user_id)
    * account.logout: logout event
    * action.confirm: called on confirmation action (key, value)
    * exception.provider_exists: attempt to register with oauth provider
      which's already assigned to another user
    * exception.provider_failed: oauth provider registration failure
    * exception.registration_denied: account registration attempt when
      allow_registration is False

    For handlers: account.logout, action.confirm, exception.provider_exists,
    exception.provider_failed, exception.registration_denied,
    exception.confirm_nokey if not None value is returned, it's returned by web
    method as-is
    """
    logger.debug(f'registered event handler for {event}: {handler}')
    handlers[event] = handler


def _call_handler(event, **kwargs):
    h = handlers.get(event)
    if h:
        logger.debug(f'calling event handler for {event} with {kwargs}')
        return h(**kwargs)


def _log_user_event(event, user_id=None):
    if not user_id:
        user_id = get_user_id()
    ip = http_real_ip()
    logstr = f'{ip}  USER: {user_id}  EVENT: {event}'
    if log_user_events:
        logger.info(logstr)
        _d.db.query('user.log.event',
                    id=user_id,
                    event=event,
                    ip=ip,
                    d=datetime.datetime.now())
    else:
        logger.debug(logstr)


def _format_prefix(base_prefix):
    x_prefix = base_prefix.replace('/', '_')
    if x_prefix.startswith('_'):
        x_prefix = x_prefix[1:]
    dot_prefix = x_prefix
    if x_prefix:
        x_prefix += '_'
        dot_prefix += '.'
    return x_prefix, dot_prefix


def check_user_password(password, allow_empty=False):
    """
    Check password for the current user

    Args:
        password: user password
        allow_empty: any password is considered as valid if no password is set
    Returns:
        True if password match
    Raises:
        webauth.AccessDenied: password doesn't match or user is not logged in
    """
    if password is None:
        password = ''
    user_id = get_user_id()
    if user_id:
        try:
            _d.db.query('user.password.check.orempty'
                        if allow_empty else 'user.password.check',
                        _cr=True,
                        id=user_id,
                        password=sha256(password.encode()).hexdigest())
            return True
        except LookupError:
            logger.warning(f'user password check failed for {user_id}')
    raise AccessDenied


def set_user_password(password):
    """
    Set user password

    Args:
        password: password to set
    Raises:
        LookupError: user not found
        webauth.AccessDenied: user is not logged in
    """
    user_id = get_user_id()
    if user_id:
        _d.db.query('user.password.set',
                    _cr=True,
                    id=user_id,
                    password=sha256(password.encode()).hexdigest())
        _log_user_event('password.change')
    else:
        raise AccessDenied


def regenerate_user_api_key():
    """
    Generate new API key for user

    Returns:
        new API key
    Raises:
        LookupError: user not found
        webauth.AccessDenied: user is not logged in
    """
    user_id = get_user_id()
    if user_id:
        k = gen_random_str()
        _d.db.query('user.api_key.set', _cr=True, id=user_id, api_key=k)
        _log_user_event('api_key.change')
        return k
    else:
        raise AccessDenied


def change_user_email(email, next_action_uri_oldaddr=None,
                      next_action_uri=None):
    """
    E-mail change action

    Change email of current user. If user already has email set, he must
    do two confirmations: firstly getting letter to the old, then to the new
    address

    Args:
        email: new user's email address
        next_action_uri_oldaddr: redirect URI after old address ownership is
            confirmed
        next_action_uri: redirect URI after new address ownership is confirmed


    Raises:
        webauth.AccessDenied: if user is not logged in
        webauth.ResourceAlreadyExists: email is already in system
    """
    user_id = get_user_id()
    if user_id:
        try:
            _d.db.qlookup('user.select.id', email=email)
            raise ResourceAlreadyExists
        except LookupError:
            old_email = get_user_email()
            _log_user_event(f'email.change:{old_email}:{email}')
            if old_email and is_confirmed():
                _send_email_change_old_addr(user_id, old_email, email,
                                            next_action_uri_oldaddr,
                                            next_action_uri)
            else:
                confirm_email_ownership(user_id=user_id,
                                        email=email,
                                        next_action_uri=next_action_uri)
    else:
        raise AccessDenied


def get_user_providers():
    """
    Get list of user oauth2 providers

    Returns: list of dicts [{provider: infodict}, ...]

    Raises:
        AccessDenied: if user is not logged in
    """
    user_id = get_user_id()
    if user_id:
        return _d.db.qlist('user.provider.list', id=user_id)
    else:
        raise AccessDenied


def delete_user_provider(provider, sub):
    """
    Delete user provider

    Args:
        provider: provider name
        sub: OAuth2 sub

    Raises:
        webauth.AccessDenied: if user is not logged in
        webauth.ResourceBusy: if only one sign-in method is left
        LookupError: provider not found
    """
    user_id = get_user_id()
    if user_id:
        _log_user_event(f'provider.delete:{provider}')
        if not get_user_email() and _d.db.query('user.provider.count.except',
                                                id=user_id,
                                                provider=provider,
                                                sub=sub).fetchone().c < 1:
            raise ResourceBusy
        else:
            _d.db.query('user.provider.delete',
                        _cr=True,
                        id=user_id,
                        provider=provider,
                        sub=sub)
    else:
        raise AccessDenied


def delete_user():
    """
    Delete current user account and logout

    Returns:
        logout response (can be served as-is)
    Raises:
        webauth.AccessDenied: if user is not logged in
        LookupError: user not found
    """
    user_id = get_user_id()
    if user_id:
        _log_user_event('account.delete')
        _call_handler('account.delete', user_id=user_id)
        _d.db.query('user.delete', _cr=True, id=user_id)
        return logout()
    else:
        raise AccessDenied


def get_user_id():
    """
    Get ID of current logged in user
    """
    return session.get(f'{_d.x_prefix}user_id')


def get_user_picture():
    """
    Get picture of current logged in user (OAuth login only)
    """
    return session.get(f'{_d.x_prefix}user_picture')


def get_user_name():
    """
    Get name of current logged in user (OAuth login only)
    """
    return session.get(f'{_d.x_prefix}user_name')


def is_authenticated():
    """
    True if user is logged in
    """
    return get_user_id() is not None


def is_confirmed():
    """
    Is user confirmed (logged in via OAuth2 or E-Mail is confirmed)
    """
    return session.get(f'{_d.x_prefix}user_confirmed', False)


def is_confirmed_session():
    """
    Is session confirmed (user just verified it via email)

    App can use confirmed session e.g. to allow changing password without an
    old one
    """
    return session.get(f'{_d.x_prefix}user_confirmed_session', False)


def stop_confirmed_session():
    """
    Clear confirmed session

    The confirmed session should be cleared as soon as no longer required
    """
    try:
        del session[f'{_d.x_prefix}user_confirmed_session']
    except:
        pass


def _get_oauth_user_name(user_info, provider):
    name = user_info.name
    if not name and provider == 'github':
        name = user_info.preferred_username
    return name


def _handle_user_auth(user_info, provider):
    user_id = get_user_id()
    try:
        user = _d.db.qlookup('user.oauth.get',
                             sub=user_info.sub,
                             provider=provider)
        if user_id and user['id'] != user_id:
            raise ResourceAlreadyExists
        else:
            user_id = user['id']
            _d.db.query('user.provider.update.name',
                        id=user_id,
                        provider=provider,
                        sub=user_info.sub,
                        name=_get_oauth_user_name(user_info, provider))
    except LookupError:
        if not user_id:
            if allow_registration:
                user_id = _d.db.qcreate('user.create.empty',
                                        api_key=gen_random_str(),
                                        d_created=datetime.datetime.now())
            else:
                raise AccessDenied
        _d.db.query('user.provider.create',
                    id=user_id,
                    provider=provider,
                    sub=user_info.sub,
                    name=_get_oauth_user_name(user_info, provider))
        _log_user_event('account.register', user_id=user_id)
        _call_handler('account.register', user_id=user_id, user_info=user_info)
    return user_id


def set_next(uri):
    """
    Set next URI

    the URI will be used once, after login/logout

    Usually used after OAuth login
    """
    session[f'{_d.x_prefix}next'] = uri


def get_next(default=None):
    return session.get(f'{_d.x_prefix}next', default=default)


def clear_next():
    """
    Clear next URI

    Usually is not called by app
    """
    try:
        del session[f'{_d.x_prefix}next']
    except:
        pass


def _next_uri():
    uri = get_next(default=_d.root_uri)
    clear_next()
    return uri


def logout():
    """
    Logout current user session
    """
    result = None
    if get_user_id():
        result = _call_handler('account.logout')
        _log_user_event('account.logout')
        for i in ('id', 'picture', 'name', 'confirmed', 'confirmed_session'):
            try:
                del session[f'{_d.x_prefix}user_{i}']
            except KeyError:
                pass
    return redirect(_next_uri()) if result is None else result


def touch(user_id):
    _d.db.query('user.touch', id=user_id, d=datetime.datetime.now())


def _send_email_change_old_addr(user_id,
                                email,
                                new_email,
                                next_action_uri_oldaddr=None,
                                next_action_uri=None):
    tpl = email_tpl['email.change']
    link = generate_confirm_action(method='email.change',
                                   user_id=user_id,
                                   email=email,
                                   new_email=new_email,
                                   next_action_uri=next_action_uri,
                                   expires=tpl['expires'],
                                   next_uri=next_action_uri_oldaddr)
    _d.smtp.sendmail(email_sender,
                     email,
                     subject=tpl['subject'],
                     text=tpl['text'].format(action_link=link),
                     html=tpl['html'].format(action_link=link))


def _send_reset_email(user_id, email, next_action_uri=None):
    tpl = email_tpl['account.remind']
    link = generate_confirm_action(method='account.remind',
                                   user_id=user_id,
                                   email=email,
                                   expires=tpl['expires'],
                                   next_uri=next_action_uri)
    _d.smtp.sendmail(email_sender,
                     email,
                     subject=tpl['subject'],
                     text=tpl['text'].format(action_link=link),
                     html=tpl['html'].format(action_link=link))


def confirm_email_ownership(email,
                            user_id=None,
                            next_action_uri=None,
                            method='email.confirm',
                            tpl_id='email.confirm'):
    """
    Confirm email address ownership

    Args:
        email: email address to confirm
        user_id: user id (if None, current user id is used)
        next_action_uri: redirect URI after email confirmation
        method: confirm action method (default: "email.confirm", confirms and
            sets email to user's account)
        tpl_id: email template ID
    """
    if user_id is None: user_id = get_user_id()
    tpl = email_tpl[tpl_id]
    link = generate_confirm_action(method=method,
                                   user_id=user_id,
                                   email=email,
                                   expires=tpl['expires'],
                                   next_uri=next_action_uri)
    _d.smtp.sendmail(email_sender,
                     email,
                     subject=tpl['subject'],
                     text=tpl['text'].format(action_link=link),
                     html=tpl['html'].format(action_link=link))


def register(email,
             password,
             confirmed=True,
             next_action_uri=None,
             _invoke_handler=True):
    """
    Register new user in traditional way

    Args:
        email: user email
        password: user password
        confirmed: if no, email confirmation is required (sent automatically)
        next_action_uri: redirect URi after email confirmation
    Raises:
        webauth.ResourceAlreadyExists: email already registered
    """
    if allow_registration:
        try:
            user_id = _d.db.qcreate('user.create',
                                    email=email,
                                    password=sha256(
                                        password.encode()).hexdigest(),
                                    api_key=gen_random_str(),
                                    d_created=datetime.datetime.now(),
                                    confirmed=confirmed)
        except sqlalchemy.exc.IntegrityError as e:
            raise ResourceAlreadyExists(e)
        session[f'{_d.x_prefix}user_id'] = user_id
        session[f'{_d.x_prefix}user_confirmed'] = confirmed
        _log_user_event('account.register', user_id=user_id)
        if _invoke_handler:
            _call_handler('account.register', user_id=user_id)
        if not confirmed:
            confirm_email_ownership(user_id=user_id,
                                    email=email,
                                    next_action_uri=next_action_uri)

        return redirect(_next_uri())
    else:
        raise AccessDenied


def get_user_email():
    """
    Get email address of current user
    """
    try:
        return _d.db.qlookup('user.get.email',
                             id=session[f'{_d.x_prefix}user_id'])['email']
    except LookupError:
        return None


def get_user_api_key():
    """
    Get API key of current user

    Raises:
        webauth.AccessDenied: if user no longer exists in database
    """
    try:
        return _d.db.qlookup('user.get.api_key',
                             id=session[f'{_d.x_prefix}user_id'])['api_key']
    except LookupError:
        raise AccessDenied


def get_user_by_api_key(api_key):
    return _d.db.qlookup('user.select.byapi_key', api_key=api_key)


def resend_email_confirm(next_action_uri=None):
    """
    Re-send confirmation for the user email address

    Args:
        next_action_uri: redirect URI after email confirmation
    """
    confirm_email_ownership(email=get_user_email(),
                            next_action_uri=next_action_uri)


def send_account_remind(email, next_action_uri=None):
    """
    Send password reset link to user

    Password reset link is just a link which allows user to log in
    automatically

    Args:
        next_action_uri: usually redirects to password change form
    Raises:
        LookupError: user not found
    """
    user_id = _d.db.qlookup('user.select.id', email=email)['id']
    _call_handler('account.remind', user_id=user_id)
    _log_user_event(f'account.remind:{email}', user_id=user_id)
    _send_reset_email(user_id=user_id,
                      email=email,
                      next_action_uri=next_action_uri)


def login(email, password):
    """
    Login user in traditional way

    Args:
        email: user email
        password: user password
    Raises:
        webauth.AccessDenied: invalid credentials
    """
    try:
        user = _d.db.qlookup('user.select.id.bypassword',
                             email=email,
                             password=sha256(password.encode()).hexdigest())
        touch(user['id'])
        session[f'{_d.x_prefix}user_id'] = user['id']
        session[f'{_d.x_prefix}user_confirmed'] = user['confirmed']
        _call_handler('account.login', user_id=user['id'])
        _log_user_event('account.login')
    except LookupError:
        raise AccessDenied


def generate_confirm_action(method, expires=None, next_uri=None, **kwargs):
    """
    Generates confirmation action

    The method should be defined in confirm_actions dict

    Args:
        method: confirmation methid id
        expires: expiration time (seconds or datetime.timedelta)
        next_uri: redirect URI after action is executed
        kwargs: passed to method as-is

    Returns:
        confirmation URL
    """
    d = {'method': method, 'kw': kwargs}
    if next_uri:
        d['next'] = next_uri
    key = _d.kv.put(value=d, expires=expires)
    return url_for(f'{_d.dot_prefix}confirm', key=key, _external=True)


def handle_confirm(key):
    try:
        value = _d.kv.get(key, delete=True)
    except LookupError:
        response = _call_handler('exception.confirm_nokey', key=key)
        return response if response else Response('No such confirmation link',
                                                  status=404)
    confirm_actions[value['method']](**value.get('kw', {}))
    response = _call_handler('action.confirm', key=key, value=value)
    return response if response else redirect(value.get('next', _d.root_uri))


def _confirm_user(user_id, email, _log=True):
    _d.db.query('user.confirm.email',
                _cr=True,
                id=user_id,
                email=email,
                d=datetime.datetime.now())
    session[f'{_d.x_prefix}user_id'] = user_id
    session[f'{_d.x_prefix}user_confirmed'] = True
    session[f'{_d.x_prefix}user_confirmed_session'] = True
    if _log: _log_user_event(f'email.confirm:{email}')


def _remind_account(user_id, email):
    _confirm_user(user_id, email, _log=False)
    _log_user_event(f'account.remind:{email}')


def _change_email(user_id, email, new_email, next_action_uri):
    _log_user_event('email.change:confirmed', user_id=user_id)
    confirm_email_ownership(user_id=user_id,
                            email=new_email,
                            next_action_uri=next_action_uri)


def init(app,
         db,
         config,
         base_prefix='/auth',
         root_uri='/',
         providers=['google', 'facebook', 'github'],
         smtp=None,
         fix_ssl=True):
    """
    Initalize framework

    Args:
        app: Flask app
        db: pyaltt2.db.Database object
        config: configuration dict
        base_prefix: base prefix for auth urls
        root_uri: default next uri
        providers: oauth2 providers list
        smtp: pyaltt2.mail.SMTP object, required if email confirmations are
        used
        fix_ssl: force SSL everywhere (True by default)
    """

    if not app.config.get('SECRET_KEY'):
        app.config['SECRET_KEY'] = gen_random_str()

    _d.x_prefix, _d.dot_prefix = _format_prefix(base_prefix)
    _d.db = db.clone(rq_func=rq)
    _d.kv = KVStorage(db=db, table_name='webauth_kv')
    _d.root_uri = root_uri
    _d.smtp = smtp

    if fix_ssl:
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1)

    def init_db():
        from sqlalchemy import (MetaData, Table, Column, BigInteger, VARCHAR,
                                JSON, CHAR, DateTime, ForeignKey, Index,
                                Boolean, Numeric)
        meta = MetaData()
        user = Table(
            'webauth_user', meta,
            Column('id', BigInteger(), primary_key=True, autoincrement=True),
            Column('email', VARCHAR(255), nullable=True, unique=True),
            Column('password', CHAR(64), nullable=True),
            Column('api_key', CHAR(32), nullable=True, unique=True),
            Index('webauth_user_api_key', 'api_key'),
            Column('d_created', DateTime(timezone=True), nullable=False),
            Column('d_active', DateTime(timezone=True), nullable=True),
            Column('confirmed', Boolean, nullable=False, server_default='0'),
            Column('otp', Numeric(1, 0), nullable=False, server_default='0'),
            Column('otp_secret', CHAR(16), nullable=True))
        user_auth = Table(
            f'webauth_user_auth', meta,
            Column('id', BigInteger(), primary_key=True, autoincrement=True),
            Column('user_id',
                   BigInteger(),
                   ForeignKey('webauth_user.id', ondelete='CASCADE'),
                   nullable=False), Index('webauth_user_auth_user_id',
                                          'user_id'),
            Column('provider', VARCHAR(15), nullable=False),
            Column('sub', VARCHAR(255), nullable=False),
            Column('name', VARCHAR(255), nullable=True),
            Index('webauth_user_auth_sub_provider',
                  'sub',
                  'provider',
                  unique=True))
        user_log = Table(
            f'webauth_user_log', meta,
            Column('id', BigInteger(), primary_key=True, autoincrement=True),
            Column('user_id', BigInteger(), nullable=False),
            Index('webauth_user_log_user_id', 'user_id'),
            Column('d', DateTime(timezone=True), nullable=False),
            Column('event', VARCHAR(1024), nullable=False),
            Column('ip', VARCHAR(45), nullable=False))
        meta.create_all(db.connect())

    def handle_authorize(remote, token, user_info):
        if user_info:
            try:
                provider = remote if isinstance(remote, str) else remote.name
                user_id = _handle_user_auth(user_info, provider=provider)
                touch(user_id)
                session[f'{_d.x_prefix}user_id'] = user_id
                session[f'{_d.x_prefix}user_picture'] = user_info.picture
                session[f'{_d.x_prefix}user_name'] = _get_oauth_user_name(
                    user_info, provider)
                session[f'{_d.x_prefix}user_confirmed'] = True
                _call_handler('account.login', user_id=user_id)
                _log_user_event(f'account.login:{provider}')
                return redirect(_next_uri())
            except ResourceAlreadyExists:
                response = _call_handler('exception.provider_exists')
                return response if response else Response(
                    'oauth provider is already ' +
                    'registered for another account',
                    status=409)
            except AccessDenied:
                response = _call_handler('exception.registration_denied')
                return response if response else Response(
                    'account registration is disabled', status=403)
            # session.permanent = True
        else:
            response = _call_handler('exception.provider_failed')
            return response if response else Response('forbidden', status=403)

    def google_login():
        redirect_uri = url_for(f'{_d.dot_prefix}google.auth', _external=True)
        return oauth.google.authorize_redirect(redirect_uri)

    def google_auth():
        token = oauth.google.authorize_access_token()
        user_info = oauth.google.parse_id_token(token)
        return handle_authorize('google', token, user_info)

    for k in config:
        app.config[k.upper().replace('-', '_')] = config_value(config=config,
                                                               config_path=k)
    oauth = OAuth(app)
    app.add_url_rule(f'{base_prefix}/logout',
                     f'{_d.dot_prefix}.logout',
                     logout,
                     methods=['GET'])
    app.add_url_rule(f'{base_prefix}/confirm/<key>',
                     f'{_d.dot_prefix}confirm',
                     handle_confirm,
                     methods=['GET'])
    for p in providers:
        if p == 'google':
            oauth.register(
                'google',
                server_metadata_url=
                'https://accounts.google.com/.well-known/openid-configuration',
                client_kwargs={'scope': 'openid profile'},
            )
            app.add_url_rule(f'{base_prefix}/google/login',
                             f'{_d.dot_prefix}google.login',
                             google_login,
                             methods=['GET'])
            app.add_url_rule(f'{base_prefix}/google/auth',
                             f'{_d.dot_prefix}google.auth',
                             google_auth,
                             methods=['GET'])
        else:
            blueprint = loginpass.create_flask_blueprint(
                _provider_mod[p], oauth, handle_authorize)
            app.register_blueprint(blueprint, url_prefix=f'{base_prefix}/{p}')
    init_db()
    return


def cleanup():
    """
    Clear expired confirmation actions and remove expired non-confirmed users
    """
    _d.kv.cleanup()
    _d.db.query(
        'user.delete.unconfirmed',
        d=datetime.datetime.now() -
        datetime.timedelta(seconds=user_unconfirmed_expires) if isinstance(
            user_unconfirmed_expires, int) else user_unconfirmed_expires)


confirm_actions = {
    'email.confirm': _confirm_user,
    'email.change': _change_email,
    'account.remind': _remind_account
}
"""
Confirm action methods. By default, contains confirm action handlers for
confirm.email, reset.password and change.email
"""
