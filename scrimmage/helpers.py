import requests
import boto3
from botocore.client import Config

from scrimmage import app

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
