from flask import redirect, request, session, url_for, render_template, make_response
from scrimmage.decorators import set_flash
from scrimmage.models import User
from scrimmage import app, bcrypt, db
from scrimmage.helpers import _verify_token, send_email, generate_token

@app.route('/login')
def login():
  return render_template('auth/login_options.html')

@app.route('/first_time_login', methods=['GET'])
def first_time_login():
  return render_template('auth/login_email.html')  # This is the current email input page

@app.route('/existing_account_login', methods=['GET', 'POST'])
def existing_account_login():
  if request.method == 'POST':
    email = request.form['email']
    password = request.form['password']

    user = User.query.filter_by(email=email).first()

    if user and bcrypt.check_password_hash(user.password, password):
      session['kerberos'] = email.split('@')[0]
      session['real_kerberos'] = session['kerberos']
      set_flash('You have successfully logged in!', level='success')
      return redirect(url_for('index'))
    else:
      set_flash('Invalid email or password.', level='warning')
      return redirect(url_for('existing_account_login'))

  return render_template('auth/existing_account_login.html')

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
    return render_template('auth/login_email.html')  # Pass the email back to pre-fill the form

  if User.query.filter_by(email=email).first():
    set_flash('This email is already associated with a user', level='warning')
    return render_template('auth/login_email.html')

  # Generate a verification token
  secret_key = app.config['SECRET_KEY']
  token, timestamp = generate_token(email, secret_key)

  # Create the verification link
  verification_link = url_for('verify_email', email=email, token=token, timestamp=timestamp, _external=True)
  try:
    send_email(email, verification_link)
  except Exception as e:
    set_flash('Failed to send verification email. Please try again later.', level='warning')
    print(e)
  print(verification_link)

  set_flash('A verification email has been sent to your FIU email address.', level='success')
  return redirect(url_for('login'))

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
  if request.method == 'POST':
    password = request.form['password']
    confirm_password = request.form['confirm_password']
    email = session['verified_email']

    if len(password) < 8:
      set_flash('Password must be at least 8 characters long.', level='warning')
      return redirect(url_for('create_account'))

    if password != confirm_password:
      set_flash('Passwords do not match.', level='warning')
      return redirect(url_for('create_account'))

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    user = User(email, hashed_password)
    db.session.add(user)
    db.session.commit()
    
    kerberos = email.split('@')[0]  # Extract kerberos from email
    session['kerberos'] = kerberos
    session['real_kerberos'] = kerberos

    set_flash('Account created successfully! You are now logged in.')
    return redirect(url_for('index'))

  return render_template('auth/create_account.html')


@app.route('/logout')
def logout():
  resp = make_response(redirect(url_for('index')))
  resp.set_cookie('session', '', expires=0)
  return resp
