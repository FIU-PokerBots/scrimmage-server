import time
from flask import redirect, request, session, url_for, render_template, flash
from hashlib import sha256
from urllib.parse import urlparse, urlunparse
from urllib.parse import urlencode
import smtplib
from scrimmage.decorators import set_flash

from scrimmage import app, db
from scrimmage.models import User


def generate_token(email, secret_key):
  timestamp = str(int(time.time()))  # Current time in seconds
  data = email + timestamp + secret_key
  token = sha256(data.encode('utf-8')).hexdigest()
  return token, timestamp


def _verify_token(email, timestamp, token):
  if app.debug:
    return True, None
  # Check if the token is too old (e.g., older than 5 seconds)
  if abs(time.time() - int(timestamp)) > 600: # Token expires in 10 minutes
    return False, "Token is too old."
  
  # Recreate the token using the email, timestamp, and secret key
  h = sha256()
  h.update((email + timestamp + app.config['AUTH_KEY']).encode('utf-8'))
  if h.hexdigest() != token:
    return False, "Token does not match."
  
  # Ensure the email ends with '@fiu.edu'
  if email[-8:].lower() != '@fiu.edu':
    return False, "Not an @fiu.edu email"
  
  return True, None


# def _create_redirect(**kwargs):
#   url_parts = list(urlparse(app.config['AUTH_URL_BASE']))
#   return_url = url_for('login_return', _external=True)
#   params = { 'return_url': return_url }
#   params.update(kwargs)
#   url_parts[4] = urlencode(params)
#   return urlunparse(url_parts)


@app.route('/login', methods=['GET', 'POST'])
def login():
  if request.method == 'POST':
    email = request.form['email']
    password = request.form['password']
    kerberos = email.split('@')[0] # Extract kerberos from the email
    user = User.query.filter_by(kerberos=kerberos).first() # Find the user with the associated kerberos

    if user and user.check_password(password):  # Verify password
      session['kerberos'] = kerberos
      session['real_kerberos'] = kerberos
      set_flash('You have successfully logged in!', level='success')
      return redirect(url_for('index'))  # Login successful
    else:
      set_flash('Invalid email or password.', level='warning')
      return redirect(url_for('login'))
  return render_template('auth_login.html')

@app.route('/first_time_login', methods=['GET'])
def first_time_login():
  return render_template('auth_login_email.html')  # This is the current email input page

@app.route('/login/return')
def login_return():
  success, err_msg = _verify_token(request.args['email'], request.args['time'], request.args['token'])

  if not success:
    return "Login was unsuccessful: " + err_msg, 400

  session['kerberos'] = request.args['email'][:-8]
  session['real_kerberos'] = session['kerberos']
  return redirect(request.args['next'] if 'next' in request.args else url_for('index'))


@app.route('/send_verification_email', methods=['POST'])
def send_verification_email():
  email = request.form['email']
  if not email.endswith('@fiu.edu'):
    set_flash('Please use a valid @fiu.edu email address.', level='warning')
    return render_template('auth_login_email.html')  # Pass the email back to pre-fill the form

  # Generate a verification token
  secret_key = app.config['SECRET_KEY']
  token, timestamp = generate_token(email, secret_key)

  # Create the verification link
  verification_link = url_for('verify_email', email=email, token=token, timestamp=timestamp, _external=True)

  # Send the email
  send_email(email, verification_link)

  set_flash('A verification email has been sent to your FIU email address.', level='success')
  return redirect(url_for('create_account'))


def send_email(to_email, verification_link):
  sender_email = "fiupokerbots@gmail.com"
  sender_password = "nadz zznp nspr csga"
  subject = "Verify Your FIU Email"
  body = f"Click the link to verify your email: {verification_link}"

  try:
    print('Sending email...')
    with smtplib.SMTP('smtp.gmail.com', 587) as server:
      server.starttls()
      server.login(sender_email, sender_password)
      message = f"Subject: {subject}\n\n{body}"
      server.sendmail(sender_email, to_email, message)
    print('Email sent successfully.')
  except Exception as e:
    set_flash('Failed to send verification email. Please try again later.', level='warning')
    print(f"Error sending email: {e}")


@app.route('/verify_email/<token>')
def verify_email(token):
  email = request.args.get('email')
  timestamp = request.args.get('timestamp')

  if not email or not token or not timestamp:
    set_flash('Invalid verification link.', level='warning')
    return redirect(url_for('login'))

  success, error_message = _verify_token(email, timestamp, token)

  if not success:
    print(f"Failed to verify email: {error_message}")
    set_flash(error_message, level='warning')
    return redirect(url_for('login'))

  # Mark the email as verified
  print(f"Email {email} verified successfully")
  session['verified_email'] = email
  set_flash('Email verified successfully! Please create your account.', level='success')
  return redirect(url_for('create_account'))


@app.route('/create_account', methods=['GET', 'POST'])
def create_account():
  if 'verified_email' not in session:
    print('No verified email found. Redirecting to login.')
    set_flash("Please verify your email.", level='warning')

  if request.method == 'POST':
    print('Creating account...')
    password = request.form['password']
    confirm_password = request.form['confirm_password']

    # Validate password length
    if len(password) < 8:
      set_flash('Password must be at least 8 characters long.', level='warning')
      return redirect(url_for('create_account'))

    # Validate password confirmation
    if password != confirm_password:
      set_flash('Passwords do not match.', level='warning')
      return redirect(url_for('create_account'))

    # Extract kerberos from the verified email
    email = session['verified_email']
    kerberos = email.split('@')[0]  # Extract kerberos from email

    # Check if the user already exists
    existing_user = User.query.filter_by(kerberos=kerberos).first()
    if existing_user:
      set_flash('An account with this email already exists.', level='warning')
      return redirect(url_for('create_account'))

    # Create the new user
    team = None  # Replace with logic to assign a team if necessary
    new_user = User(kerberos=kerberos, team=team, password=password)
    db.session.add(new_user)
    db.session.commit()

    # Log the user in
    session['kerberos'] = kerberos
    session['real_kerberos'] = kerberos

    set_flash('Account created successfully! You are now logged in.')
    return redirect(url_for('index'))

  return render_template('create_account.html')


@app.route('/logout')
def logout():
  session.pop('kerberos', None)
  session.pop('real_kerberos', None)
  return redirect(url_for('index'))
