from flask import abort, session, g, Response, request, redirect, url_for
from functools import wraps

from scrimmage import app, db
from scrimmage.models import User
from scrimmage.settings import settings

import humanize
from pytz import timezone
import datetime

# Add your kerberos_id to the list of ADMINS --> then run localhost:8000/setadmin/<kerberos_id> to login as admin
ADMINS = {'henriquepitta', 'npastrana'}

def is_admin(kerberos):
  return kerberos in ADMINS or kerberos in [kerb.lower().strip() for kerb in settings['extra_admins'].split(',')]

def _check_sponsor_auth(username, password):
  """This function is called to check if a username /
  password combination is valid.
  """
  return username.lower() == 'sponsor' and password == settings['sponsor_portal_password']


@app.before_request
def set_up_g():
  """Sets up the following:
    g.is_logged_in
    g.is_admin
    g.kerberos
    g.real_kerberos
    g.team
  """
  g.settings = settings
  g.is_logged_in = False
  g.is_admin = False
  g.is_sponsor = False
  g.team = None
  g.kerberos = None
  g.real_kerberos = None

  if request.authorization:
    auth = request.authorization
    g.is_sponsor = _check_sponsor_auth(auth.username, auth.password)

  if 'kerberos' not in session:
    return

  g.is_logged_in = True
  g.kerberos = session['kerberos']
  g.real_kerberos = session['real_kerberos']
  g.is_admin = is_admin(session['real_kerberos'])
  user = User.query.filter(User.kerberos == g.kerberos).one_or_none()
  if user is not None:
    g.team = user.team


@app.context_processor
def flash():
  return dict(flash=session.pop('flash', None), flash_level=session.pop('flash_level', None))


@app.template_filter('naturaltime')
def naturaltime(d):
  return humanize.naturaltime(datetime.datetime.now(timezone('America/New_York')) - d.replace(tzinfo=timezone('UTC')))


def set_flash(message, level=''):
  session['flash'] = message
  session['flash_level'] = level


def login_required(f):
  @wraps(f)
  def decorated_function(*args, **kwargs):
    if not g.is_logged_in:
      return redirect(url_for('login', next=request.url))
    return f(*args, **kwargs)
  return decorated_function


def team_required(f):
  @wraps(f)
  def decorated_function(*args, **kwargs):
    if g.team is None:
      abort(404)
    return f(*args, **kwargs)
  return decorated_function


def admin_required(f):
  @wraps(f)
  def decorated_function(*args, **kwargs):
    if not g.is_admin:
      abort(404)
    return f(*args, **kwargs)
  return decorated_function


def _authenticate():
  """Sends a 401 response that enables basic auth"""
  return Response(
    'Could not verify your access level for that URL.\n'
    'You have to login with proper credentials', 401,
    {'WWW-Authenticate': 'Basic realm="Login Required"'}
  )


def sponsor_or_admin_required(f):
  @wraps(f)
  def decorated(*args, **kwargs):
    if not g.is_admin and not g.is_sponsor:
      return _authenticate()
    return f(*args, **kwargs)
  return decorated


def sponsor_or_team_required(f):
  @wraps(f)
  def decorated(*args, **kwargs):
    if g.team is None and not g.is_sponsor:
      return _authenticate()
    return f(*args, **kwargs)
  return decorated
