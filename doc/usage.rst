Typical usage
*************

Framework initialization
========================

WebaAuth uses database and SMTP wrappers from `pyaltt2
<https://github.com/alttch/pyaltt2>`_ common functions library.

Currently WebAuth is tested with PostgreSQL only.

Code example
------------

.. code:: python

   # configuration dict may contain app key and MUST contain OAuth2 providers IDs and secrets.

   config = {
      'secret-key': 'somesecretkey', # app key, auto-generated if not specified
      'github-client-id': 'FILL THIS',
      'github-client-secret': 'FILL THIS'
      # ....
   }

   # create flask app
   from flask import Flask
   app = Flask(__name__)

   # create database
   from pyaltt2.db import Database, SMTP
   db = Database('postgresql://test:123@localhost/test')
   smtp = SMTP(host='localhost')
   webauth.init(app, db=db, config=config, smtp=smtp)

Mapped URIs
-----------

After initialization, the following URIs are mapped to Flask app:

* **/auth/<provider>/login** redirects to OAuth provider
* **/auth/<provider>/auth** should be set at OAuth provider as callback
* **/auth/logout** clears session data (performs user logout)
* **/auth/confirm** special service URI, used for e-mail confirmation links

*auth* prefix can be changed at framework initialization.

Database
--------

The following tables are automatically created:

* **webauth_user** contains minimal user info, should be used as a base table
  for your application.

* **webauth_user_auth** contains OAuth providers data.

* **webauth_user_log** contains user event logs. Event logs are kept even after
  user account is deleted and should be cleaned up manually if required.

Table names can not be changed/customized.

Registration, authentication
============================

Registration with E-Mail and password
-------------------------------------

.. note::

   To keep the whole things lightweight, WebAuth doesn't have password policies
   and doesn't validate email addresses. This should be performed by your
   application.

.. code:: python

   @app.route('/register', methods=['POST'])
   def register():
       email = request.form.get('email')
       password = request.form.get('password')
       try:
            webauth.register(email, password, confirmed=False,
               next_action_uri='/dashboard')
            # user is registered, redirecting to user area
            # after clicking confirmation link in e-mail - redirect to
            # /dashboard
            return redirect('/user-area')
       except webauth.ResourceAlreadyExists:
            # return Flask error or some error page
            return Response('This email is already registered', status=409)

Authentication with E-Mail and password
---------------------------------------

.. code:: python

   @app.route('/login', methods=['POST'])
   def login():
       email = request.form.get('email')
       password = request.form.get('password')
       try:
           webauth.login(email, password)
           return redirect('/user-area')
       except webauth.AccessDenied:
            # return Flask error or some error page
           return Response('Access denied', status=403)

Registration/authentication with OAuth
--------------------------------------

.. code:: python

   @app.route('/oauth-login/<provider>')
   def oauth_login(provider):
       webauth.set_next('/user-area')
       # WebAuth method will automatically login user or create new account if
       # user doesn't exist
       return redirect(f'/auth/{provider}/login')

Authenticated user
==================

Methods
-------

The following framework methods may be called to determine user authentication
status:

.. code:: python

   # True, if user is authenticated in any way
   webauth.is_authenticated()
   
   # True, if account is confirmed (has confirmed e-mail or is logged in via
   # OAuth provider)
   webauth.is_confirmed()

   # Get authenticated user ID
   webauth.get_user_id()

   # Get user picture (only if logged in via OAuth provider)
   webauth.get_user_picture()

Confirmed session
-----------------

Confirmed session is started when user confirms E-Mail address ownership (e.g.
when remind password procedure is performed. When working with confirmed
session, some verifications may be omitted, e.g. user should not enter old
password to specify a new one. Confirmed session SHOULD be stopped as soon as
no longer required.

E.g. password change procedure:

.. code:: python

   @app.route('/set-password', methods=['GET', 'POST'])
   def set_password():
       if webauth.is_authenticated():
           if request.method == 'GET':
               return '<SOME HTML>'
           else:
               try:
                   # if this is not password recovery procedure - check current
                   # password
                   if not webauth.is_confirmed_session():
                       webauth.check_user_password(request.form.get('oldpass'),
                                                   allow_empty=True)
               except webauth.AccessDenied:
                   return Response('old password is not valid', status=400)
               webauth.set_user_password(request.form.get('password'))
               webauth.stop_confirmed_session()
               return redirect('/user-area')
       else:
           return redirect('/')

Recovering lost password
------------------------

The following method sends auto-login link to user's e-mail. Usually next URI
is password change page.

.. note::

   When user clicks on e-mail account recovery link, his email is also
   automatically confirmed

.. code:: python

   @app.route('/remind', methods=['POST'])
   def remind():
       email = request.form.get('email')
       try:
           webauth.send_account_remind(email, next_action_uri='/set-password')
           return 'Check your e-mail for instructions'
       except LookupError:
           return Response('user does not exists', status=404)

Re-sending lost E-Mail confirmation link
----------------------------------------

.. code:: python

   @app.route('/resend-confirm')
   def resend_confirm():
       webauth.resend_email_confirm(next_action_uri='/user-area')
       return redirect('/user-area')

E-Mail change
=============

.. code:: python

   @app.route('/set-email', methods=['GET', 'POST'])
   def set_email():
       if webauth.is_authenticated():
           if request.method == 'GET':
               return '<SOME HTML>'
           else:
               email = request.form.get('email')
               if email == webauth.get_user_email():
                   return redirect('/dashboard')
               try:
                   webauth.change_user_email(
                       email,
                       # this URI will be displayed when user re-confirms
                       # ownership of the old email address
                       next_action_uri_oldaddr='/old-email-remove-ok',
                       # this URI will be displayed with new email address
                       # is confirmed
                       # usually if no email is set currently, user should
                       # be prompted to define password
                       next_action_uri='/new-email-set-ok'
                       if webauth.get_user_email() else '/set-password')
                   return redirect('/user-area')
               except webauth.ResourceAlreadyExists:
                   return Response('E-mail is already in system', status=409)
       else:
           return redirect('/')

If user currently has e-mail address set and confirmed, framework always sends
e-mail change confirmation link to the current registered address. After
address ownership is re-confirmed, confirmation email is automatically send to
the new one.

E-Mail address is changed when last confirmation link is clicked.

Adding more OAuth providers to user account
===========================================

The logic is very simple:

* When user IS NOT logged in, URI */auth/<provider>/login* (default) creates
  new user account.

* When user IS logged in, URI */auth/<provider>/login* (default) appends new
  OAuth2 authentication method to his account.

Working with API keys
=====================

The framework automatically generates 32-character random API keys for all
registered users. It's completely up to you use them or not.

Using API key
-------------

Consider you have API call, the call URL is requested without an open session.
Use the following code to authenticate user:

.. code:: python

   @app.route('/api/somecall')
   def some_api_call():
      try:
         user = webauth.get_user_by_api_key(request.headers.get('X-API-Key'))
         # user dict contains all fields from webauth_user table, except
         # password and otp_secret
      except LookupError
         abort(403)
      result = do_something(user_id=user['id'])
      return result

Displaying API key to user
--------------------------

When you consider the user session environment as safe (e.g. re-check user
password), use *webauth.get_user_api_key()* method to obtain current API key of
the logged in user.

Regenerating API KEY
--------------------

API key can be regenerated at any time when user is logged in. Use method
*webauth.regenerate_api_key()*. The method returns new generated API key as
well the key is automatically updated in the database.

Other nuts and bolts
====================

Read :doc:`framework module documentation<methods>` for the additional
customization and methods.
