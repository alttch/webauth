#!/usr/bin/env pytest

import pytest
import time
import os
import signal
import logging
from pyaltt2.db import Database
from types import SimpleNamespace
from selenium import webdriver
from selenium.webdriver.firefox.options import Options

pidfile = '/tmp/webauth-server-test.pid'
logfile = '/tmp/webauth-server-test.log'

db = Database('postgresql://test:123@localhost/test')

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
    if os.system('gunicorn -D -b 0.0.0.0:8449 --log-level DEBUG '
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
    yield
    _d.driver.quit()
    with open(pidfile) as fh:
        pid = int(fh.read().strip())
    os.kill(pid, signal.SIGKILL)
    try:
        os.unlink(pidfile)
    except:
        pass


def test1():
    _d.driver.get('https://webauth-test.lab.altt.ch/')
    time.sleep(2)
