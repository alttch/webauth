__author__ = 'Altertech, http://www.altertech.com/'
__copyright__ = 'Copyright (C) 2020 Altertech'
__license__ = 'MIT'
__version__ = '0.0.1'

# TODO: docs

from flask import redirect, session, url_for, Response
from authlib.flask.client import OAuth
from pyaltt2.config import config_value
from pyaltt2.crypto import gen_random_str
from pyaltt2.res import ResourceStorage
import pyaltt2.json as json
from types import SimpleNamespace
from sqlalchemy import text as sql
from functools import partial
import loginpass


class AccessDenied(Exception):
    pass


class ResourceAlreadyExists(Exception):
    pass


class ResourceBusy(Exception):
    pass


handlers = {}

_d = SimpleNamespace()

allow_registration = True

rs = ResourceStorage(mod='webauth')

rq = partial(rs.get, resource_subdir='sql', ext='sql')

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


def register_handler(event, handler):
    """
    Register event handler

    Events:
        register: new user registration (user_id=user_id)
        delete: user account deletion (user_id=user_id)
        logout: logout event

        exception.provider_exists: attempt to register with oauth provider
            which's already assigned to another user
        exception.provider_failed: oauth provider registration failure
        exception.registration_denied: account registration attempt when
            allow_registration is False

    For handlers: exception.provider_exists, exception.provider_failed,
    exception.registration_denied, logout, if not None value is returned, it's
    returned by web method as-is
    """
    handlers[event] = handler


def _call_handler(event, **kwargs):
    h = handlers.get(event)
    return h(**kwargs) if h else None


def _format_prefix(base_prefix):
    x_prefix = base_prefix.replace('/', '_')
    if x_prefix.startswith('_'):
        x_prefix = x_prefix[1:]
    dot_prefix = x_prefix
    if x_prefix:
        x_prefix += '_'
        dot_prefix += '.'
    return x_prefix, dot_prefix


def set_user_password(password):
    """
    Set user password

    Args:
        password: password to set
    Raises:
        LookupError: user not found
        webauth.AccessDenied: user is not logged in
    """
    from hashlib import sha256
    user_id = get_user_id()
    if user_id:
        if not _db.dbconn_func().execute(
                sql(rq('user.password.set')),
                id=user_id,
                password=sha256(password).hexdigest()).rowcount:
            raise LookupError
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
        return [
            dict(row)
            for row in _d.dbconn_func().execute(sql(rq('user.provider.list')),
                                                id=user_id).fetchall()
        ]
    else:
        raise AccessDenied


def delete_user_provider(provider, sub):
    """
    Delete user provider

    Raises:
        webauth.AccessDenied: if user is not logged in
        webauth.ResourceBusy: if only one sign-in method is left
        LookupError: provider not found
    """
    user_id = get_user_id()
    if user_id:
        if _d.dbconn_func().execute(sql(rq('user.provider.count.except')),
                                    id=user_id,
                                    provider=provider,
                                    sub=sub).fetchone().c < 1:
            raise ResourceBusy
        else:
            if not _d.dbconn_func().execute(sql(rq('user.provider.delete')),
                                            id=user_id,
                                            provider=provider,
                                            sub=sub).rowcount:
                raise LookupError
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
        _call_handler('delete', user_id=user_id)
        if not _d.dbconn_func().execute(sql(rq('user.delete')),
                                        id=user_id).rowcount:
            raise LookupError
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
    Get picture of current logged in user
    """
    return session.get(f'{_d.x_prefix}user_picture')


def is_authenticated():
    """
    True if user is logged in
    """
    return get_user_id() is not None


def _handle_user_auth(user_info, provider):
    user_id = get_user_id()
    from pprint import pprint
    pprint(user_info)
    result = _d.dbconn_func().execute(sql(rq('user.oauth.get')),
                                      sub=user_info.sub,
                                      provider=provider).fetchone()
    if result is None:
        if not user_id:
            if allow_registration:
                user_id = _d.dbconn_func().execute(sql(
                    rq('user.create.empty'))).fetchone().id
            else:
                raise AccessDenied
        _d.dbconn_func().execute(sql(rq('user.provider.create')),
                                 id=user_id,
                                 provider=provider,
                                 sub=user_info.sub,
                                 name=user_info.name)
        _call_handler('register', user_id=user_id, user_info=user_info)
    else:
        if user_id and result.id != user_id:
            raise ResourceAlreadyExists
        else:
            user_id = result.id
    return user_id


def set_next(uri):
    """
    Set next URI

    the URI will be used once, after login/logout
    """
    session[f'{_d.x_prefix}next'] = uri


def get_next(default=None):
    return session.get(f'{_d.x_prefix}next', default=default)


def clear_next():
    try:
        del session[f'{_d.x_prefix}next']
    except:
        pass


def _next_uri():
    uri = get_next(default=_d.root_uri)
    clear_next()
    return uri


def logout():
    result = _call_handler('logout')
    for i in ('id', 'picture'):
        try:
            del session[f'{_d.x_prefix}user_{i}']
        except KeyError:
            pass
    return redirect(_next_uri()) if result is None else result


def init(app,
         dbconn_func,
         config,
         base_prefix='/auth',
         root_uri='/',
         providers=['google', 'facebook', 'github'],
         fix_ssl=True):

    if not app.config.get('SECRET_KEY'):
        app.config['SECRET_KEY'] = gen_random_str()

    _d.x_prefix, _d.dot_prefix = _format_prefix(base_prefix)
    _d.dbconn_func = dbconn_func
    _d.root_uri = root_uri

    if fix_ssl:
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1)

    def init_db():
        from sqlalchemy import (MetaData, Table, Column, BigInteger, VARCHAR,
                                JSON, CHAR, DateTime, ForeignKey, Index)
        meta = MetaData()
        user = Table(
            'webauth_user', meta,
            Column('id', BigInteger(), primary_key=True, autoincrement=True),
            Column('email', VARCHAR(255), nullable=True),
            Column('password', VARCHAR(64), nullable=True))
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
        meta.create_all(dbconn_func())

    # TODO
    # register with email (+ confirmation)
    # login with email
    # reset password with email
    # check password API method

    def handle_authorize(remote, token, user_info):
        if user_info:
            try:
                session[f'{_d.x_prefix}user_id'] = _handle_user_auth(
                    user_info,
                    provider=remote if isinstance(remote, str) else remote.name)
                session[f'{_d.x_prefix}user_picture'] = user_info.picture
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
