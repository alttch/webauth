#!/usr/bin/env pytest

# TODO
# test login
# test logout
# test duplicate email
# test add oauth
# test delete oauth (including last one)
# test add email with oauth login
# test change email

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
    # options.headless = True
    _d.driver = webdriver.Firefox(options=options)
    while not os.path.isfile(pidfile):
        c += 1
        time.sleep(0.1)
        if c > 50: raise TimeoutError
    d = _d.driver
    # github login
    # d.get('https://github.com/login')
    # d.find_element_by_id('login_field').send_keys(config['github']['login'])
    # d.find_element_by_id('password').send_keys(config['github']['password'])
    # d.find_element_by_class_name('btn-primary').click()
    yield
    _d.driver.quit()
    with open(pidfile) as fh:
        pid = int(fh.read().strip())
    os.kill(pid, signal.SIGKILL)
    try:
        os.unlink(pidfile)
    except:
        pass


def _login_pop3(login=None, wait_mail=None):
    pop3 = POP3(host=config['pop3']['host'])
    if login is None:
        login = config['pop3']['login'][0]
    pop3.user(login)
    pop3.pass_(config['pop3']['password'])
    if wait_mail:
        for i in range(wait_mail * 10):
            if len(pop3.list()[1]):
                break
            time.sleep(0.1)
        else:
            raise TimeoutError
    return pop3


def _get_pop3_mail(login=None):
    pop3 = _login_pop3(login=login, wait_mail=5)
    msg = email.message_from_string('\n'.join(
        [x.decode() for x in pop3.retr(1)[1]]))
    pop3.dele(1)
    pop3.quit()
    return msg


def _get_pop3_link(login=None):
    payload = str(_get_pop3_mail(login=login).get_payload()[0])
    return re.search('(?P<url>https?://[^\s]+)', payload).group('url')


def _clear_pop3(login=None):
    pop3 = _login_pop3(login=login)
    for i in range(len(pop3.list()[1])):
        pop3.dele(i + 1)
    pop3.quit()


def _test001_oauth_login():
    d = _d.driver
    d.get('https://webauth-test.lab.altt.ch/')
    d.find_element_by_id('login-github').click()
    d.find_element_by_id('delete-account').click()
    assert d.current_url == 'https://webauth-test.lab.altt.ch/'


def test002_register():
    _clear_pop3()
    d = _d.driver
    d.get('https://webauth-test.lab.altt.ch/')
    d.find_element_by_id('do_reg').click()
    d.find_element_by_id('email_reg').send_keys(config['email'][0])
    d.find_element_by_id('password').send_keys('123')
    d.find_element_by_id('password2').send_keys('123')
    d.find_element_by_id('reg_submit').click()
    assert d.current_url == 'https://webauth-test.lab.altt.ch/dashboard'
    assert d.find_element_by_id('resend-confirm') is not None
    _clear_pop3()
    d.find_element_by_id('resend-confirm').click()
    d.get(_get_pop3_link())
    assert d.current_url == 'https://webauth-test.lab.altt.ch/dashboard'
    with pytest.raises(NoSuchElementException):
        d.find_element_by_id('resend-confirm')
    d.find_element_by_id('delete-account').click()
