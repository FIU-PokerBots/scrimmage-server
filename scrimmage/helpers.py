import requests
import boto3
from botocore.client import Config
from scrimmage import app
from urllib.parse import urlparse, urlunparse
from urllib.parse import urlencode
from hashlib import sha256
import time
import smtplib
from flask import url_for

# LOCAL_STORAGE_PATH = os.path.join(os.path.dirname(__file__), '..', 'local_storage')

def _get_s3_context():
  if app.debug: # Development Mode --> MinIO S3
    return boto3.client(
      's3',
      endpoint_url=app.config['S3_ENDPOINT_URL'],
      aws_access_key_id=app.config['AWS_ACCESS_KEY_ID'],
      aws_secret_access_key=app.config['AWS_SECRET_ACCESS_KEY'],
      config=Config(signature_version='s3v4')
    )
  else: # Production Mode --> AWS S3
    return boto3.client(
      's3',
      region_name=app.config['S3_REGION'],
      aws_access_key_id=app.config['AWS_ACCESS_KEY_ID'],
      aws_secret_access_key=app.config['AWS_SECRET_ACCESS_KEY'],
      config=Config(signature_version='s3v4')
    )


def get_s3_object(key):
  client = _get_s3_context()
  return client.get_object(Bucket=app.config['S3_BUCKET'], Key=key)['Body']


def put_s3_object(key, body):
  client = _get_s3_context()
  client.put_object(Body=body, Bucket=app.config['S3_BUCKET'], Key=key)


def get_student_info(kerberos):
  r = requests.get(app.config['USER_INFO_URL_BASE'], params={'user': kerberos})

  if r.status_code != 200:
    return None, None, None

  data = r.json()
  return data['name'], data['class_year'], data['department']


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


def _create_redirect(**kwargs):
  url_parts = list(urlparse(app.config['AUTH_URL_BASE']))
  return_url = url_for('login_return', _external=True)
  params = { 'return_url': return_url }
  params.update(kwargs)
  url_parts[4] = urlencode(params)
  return urlunparse(url_parts)


def send_email(to_email, verification_link):
  sender_email = "fiupokerbots@gmail.com"
  sender_password = "nadz zznp nspr csga"
  subject = "Verify Your FIU Email"
  body = f"Click the link to verify your email: {verification_link}"

  print('Sending email...')

  with smtplib.SMTP('smtp.gmail.com', 587) as server:
    server.starttls()
    server.login(sender_email, sender_password)
    message = f"Subject: {subject}\n\n{body}"
    server.sendmail(sender_email, to_email, message)
  print('Email sent successfully.')