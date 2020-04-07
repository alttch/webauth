#!/usr/bin/env pytest -x

import pytest
import time
import os
import re
import signal
import logging
import email
from poplib import POP3
from pyaltt2.db import Database
from pyaltt2.config import load_yaml
from types import SimpleNamespace
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.common.exceptions import NoSuchElementException

pidfile = '/tmp/webauth-server-test.pid'
logfile = '/tmp/webauth-server-test.log'

db = Database('postgresql://test:123@localhost/test')

config = load_yaml('test-data.yml')

_d = SimpleNamespace()

for t in [
        'webauth_kv', 'webauth_user_log', 'webauth_user_auth', 'webauth_user'
]:
    try:
        db.execute(f'drop table {t}')
    except:
        pass


def login_pop3(login=None, wait_mail=None):
    if login is None:
        login = config['pop3']['login'][0]
    c = 0
    while True:
        pop3 = POP3(host=config['pop3']['host'])
        pop3.user(login)
        pop3.pass_(config['pop3']['password'])
        if not wait_mail or len(pop3.list()[1]):
            break
        c += 0.5
        pop3.quit()
        time.sleep(0.5)
        if c > wait_mail:
            raise TimeoutError
    return pop3


def get_pop3_mail(login=None):
    pop3 = login_pop3(login=login, wait_mail=5)
    msg = email.message_from_string('\n'.join(
        [x.decode() for x in pop3.retr(1)[1]]))
    pop3.dele(1)
    pop3.quit()
    return msg


def get_pop3_link(login=None):
    payload = str(get_pop3_mail(login=login).get_payload()[0])
    logging.info(payload)
    return re.search('(?P<url>https?://[^ ]+)', payload).group('url')


def clear_pop3(login=None):
    pop3 = login_pop3(login=login)
    for i in range(len(pop3.list()[1])):
        pop3.dele(i + 1)
    pop3.quit()


def click(elem):
    _d.driver.find_element_by_id(elem).click()
    if elem.endswith('-github'):
        try:
            time.sleep(0.1)
            click('js-oauth-authorize-btn')
            time.sleep(0.5)
        except NoSuchElementException:
            pass


def fill(elem, value):
    _d.driver.find_element_by_id(elem).send_keys(value)


def fill_register(email, password):
    click('do_reg')
    fill('email_reg', email)
    fill('password', password)
    fill('password2', password)
    click('reg_submit')


def login(email, password):
    fill('email', email)
    fill('pass', password)
    click('login_submit')
    assert _d.driver.current_url == 'https://webauth-test.lab.altt.ch/dashboard'


def logout():
    click('logout')
    assert _d.driver.current_url == 'https://webauth-test.lab.altt.ch/'


@pytest.fixture(scope='session', autouse=True)
def init():
    try:
        os.unlink(logfile)
    except:
        pass
    if os.system('WEBAUTH_CONFIG=test.yml '
                 'gunicorn -D -b 0.0.0.0:8449 --log-level DEBUG '
                 f'--pid {pidfile} --log-file {logfile} server:app'):
        raise RuntimeError('failed to start server')
    c = 0
    time.sleep(1)
    options = Options()
    if os.getenv('HEADLESS_TEST'):
        options.headless = True
    _d.driver = webdriver.Firefox(options=options)
    while not os.path.isfile(pidfile):
        c += 1
        time.sleep(0.1)
        if c > 50: raise TimeoutError
    d = _d.driver
    # github login
    if not os.getenv('SKIP_OAUTH'):
        clear_pop3()
        d.get('https://github.com/login')
        fill('login_field', config['github']['login'])
        fill('password', config['github']['password'])
        d.find_element_by_class_name('btn-primary').click()
        try:
            otp = d.find_element_by_id('otp')
            msg = get_pop3_mail()
            code = msg.get_payload().split('Verification code: ')[1].split(
                '\n')[0]
            otp.send_keys(code)
            d.find_element_by_class_name('btn-primary').click()
        except NoSuchElementException:
            pass
    yield
    _d.driver.quit()
    with open(pidfile) as fh:
        pid = int(fh.read().strip())
    os.kill(pid, signal.SIGKILL)
    try:
        os.unlink(pidfile)
    except:
        pass


def test001_oauth_login():
    if os.getenv('SKIP_OAUTH'): return
    d = _d.driver
    d.get('https://webauth-test.lab.altt.ch/')
    click('login-github')
    click('delete-provider-github')
    assert 'ERROR' in d.title
    click('next')
    # add email
    clear_pop3()
    click('set-email')
    fill('email', config['email'][0])
    click('submit_change')
    d.get(get_pop3_link())
    assert d.current_url == 'https://webauth-test.lab.altt.ch/set-password'
    fill('password', '111')
    fill('password2', '111')
    click('submit_change')
    assert d.current_url == 'https://webauth-test.lab.altt.ch/dashboard'
    # check both login by email and oauth
    logout()
    click('login-github')
    assert d.current_url == 'https://webauth-test.lab.altt.ch/dashboard'
    logout()
    login(config['email'][0], '111')
    # cleanup
    click('delete-provider-github')
    assert d.current_url == 'https://webauth-test.lab.altt.ch/dashboard'
    click('delete-account')
    assert d.current_url == 'https://webauth-test.lab.altt.ch/'


def test002_register_login_logout():
    d = _d.driver
    d.get('https://webauth-test.lab.altt.ch/')
    # register
    clear_pop3()
    fill_register(config['email'][0], '123')
    assert d.current_url == 'https://webauth-test.lab.altt.ch/dashboard'
    assert d.find_element_by_id('resend-confirm') is not None
    clear_pop3()
    click('resend-confirm')
    d.get(get_pop3_link())
    assert d.current_url == 'https://webauth-test.lab.altt.ch/dashboard'
    with pytest.raises(NoSuchElementException):
        d.find_element_by_id('resend-confirm')
    # logout
    logout()
    d.get('https://webauth-test.lab.altt.ch/dashboard')
    assert d.current_url == 'https://webauth-test.lab.altt.ch/'
    # login
    login(config['email'][0], '123')
    logout()
    # lost password
    clear_pop3()
    fill('email', config['email'][0])
    fill('pass', '111')
    click('login_submit')
    assert 'ERROR' in d.title
    click('next')
    click('do_forgot')
    fill('email_remind', config['email'][0])
    click('remind_submit')
    d.get(get_pop3_link())
    assert d.current_url == 'https://webauth-test.lab.altt.ch/set-password'
    fill('password', '111')
    fill('password2', '111')
    click('submit_change')
    assert d.current_url == 'https://webauth-test.lab.altt.ch/dashboard'
    logout()
    # login again
    login(config['email'][0], '111')
    logout()
    # duplicate email
    fill_register(config['email'][0], 'qwerty')
    assert d.current_url == 'https://webauth-test.lab.altt.ch/register'
    assert 'ERROR' in d.title
    click('next')
    # login again
    login(config['email'][0], '111')
    # set password
    click('set-password')
    assert d.current_url == 'https://webauth-test.lab.altt.ch/set-password'
    # fill wrong old password
    fill('oldpass', 'xyz')
    fill('password', '123')
    fill('password2', '123')
    click('submit_change')
    assert 'ERROR' in d.title
    click('next')
    # correctly change password
    fill('oldpass', '111')
    fill('password', '123')
    fill('password2', '123')
    click('submit_change')
    # login again
    assert d.current_url == 'https://webauth-test.lab.altt.ch/dashboard'
    logout()
    login(config['email'][0], '123')
    # change email
    clear_pop3()
    clear_pop3(login=config['pop3']['login'][1])
    click('set-email')
    fill('email', config['email'][1])
    click('submit_change')
    d.get(get_pop3_link())
    d.get(get_pop3_link(login=config['pop3']['login'][1]))
    # login with new email
    logout()
    login(config['email'][1], '123')
    # add oauth
    if not os.getenv('SKIP_OAUTH'):
        click('connect-github')
        logout()
        click('login-github')
        assert d.current_url == 'https://webauth-test.lab.altt.ch/dashboard'
        click('delete-provider-github')
        assert d.current_url == 'https://webauth-test.lab.altt.ch/dashboard'
        with pytest.raises(NoSuchElementException):
            d.find_element_by_id('delete-provider-github')
    # cleanup
    click('delete-account')


def test003_oauth_mixed():
    if os.getenv('SKIP_OAUTH'): return
    d = _d.driver
    d.get('https://webauth-test.lab.altt.ch/')
    # register with github
    click('login-github')
    assert d.current_url == 'https://webauth-test.lab.altt.ch/dashboard'
    logout()
    # register
    clear_pop3()
    fill_register(config['email'][0], '123')
    assert d.current_url == 'https://webauth-test.lab.altt.ch/dashboard'
    click('connect-github')
    assert 'ERROR' in d.title
    click('next')
    click('delete-account')
