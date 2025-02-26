import time
from flask import redirect, request, session, url_for
from hashlib import sha256
from urllib.parse import urlparse, urlunparse
from urllib.parse import urlencode

from scrimmage import app

def _verify_token(email, t, token):
  if app.debug:
    return True, None
  if abs(time.time() - int(t)) > 5:
    return False, "Token is too old."
  h = sha256()
  h.update((email + t + app.config['AUTH_KEY']).encode('utf-8'))
  if h.hexdigest() != token:
    return False, "Token does not match."
  if email[-8:].lower() != '@mit.edu':
    return False, "Not an @mit.edu email"
  return True, None

def _create_redirect(**kwargs):
  url_parts = list(urlparse(app.config['AUTH_URL_BASE']))
  return_url = url_for('login_return', _external=True)
  params = { 'return_url': return_url }
  params.update(kwargs)
  url_parts[4] = urlencode(params)
  return urlunparse(url_parts)


@app.route('/login')
def login():
  if 'next' in request.args:
    return redirect(_create_redirect(next=request.args['next']))
  else:
    return redirect(_create_redirect())


@app.route('/login/return')
def login_return():
  success, err_msg = _verify_token(request.args['email'],
                                  request.args['time'],
                                  request.args['token'])

  if not success:
    return "Login was unsuccessful: " + err_msg, 400

  session['kerberos'] = request.args['email'][:-8]
  session['real_kerberos'] = session['kerberos']
  return redirect(request.args['next'] if 'next' in request.args else url_for('index'))


@app.route('/logout')
def logout():
  session.pop('kerberos', None)
  session.pop('real_kerberos', None)
  return redirect(url_for('index'))
