import os

# Note, it's very important that keys read from the environment have the same name as in the config

class Config(object):
  SQLALCHEMY_DATABASE_URI = 'sqlite://:memory:'
  SQLALCHEMY_TRACK_MODIFICATIONS = False
  AUTH_URL_BASE = 'https://pokerbots.scripts.mit.edu:444/scrimmage/auth.php'
  USER_INFO_URL_BASE = 'https://pokerbots.scripts.mit.edu/scrimmage/info.py'
  MAX_CONTENT_LENGTH = 100 * 1024 * 1024

class ProdConfig(Config):
  ENV = 'production'
  SQLALCHEMY_DATABASE_URI = os.getenv('SQLALCHEMY_DATABASE_URI', None)
  CELERY_BROKER_URL = os.getenv('CELERY_BROKER_URL', None)
  SECRET_KEY = os.getenv('SECRET_KEY', None)
  AUTH_KEY = os.getenv('AUTH_KEY', None)
  AWS_ACCESS_KEY_ID = os.getenv('AWS_ACCESS_KEY_ID', None)
  AWS_SECRET_ACCESS_KEY = os.getenv('AWS_SECRET_ACCESS_KEY', None)
  S3_REGION = os.getenv('S3_REGION', None)
  S3_BUCKET = os.getenv('S3_BUCKET', None)
  PREFERRED_URL_SCHEME = 'https'

class DevConfig(Config):
  ENV = 'development'
  DEBUG = True
  SQLALCHEMY_DATABASE_URI = 'postgresql://postgres:newpassword@localhost:5432/pbots'
  SQLALCHEMY_TRACK_MODIFICATIONS = True
  SECRET_KEY = 'SUPER SECRET KEY'
  PREFERRED_URL_SCHEME = 'http'
  S3_BUCKET = 'pokerbots-dev'
  CELERY_BROKER_URL = 'pyamqp://guest@localhost//'
  
  AWS_ACCESS_KEY_ID = 'minioadmin'
  AWS_SECRET_ACCESS_KEY = 'minioadmin'
  S3_REGION = 'us-east-1'
  S3_ENDPOINT_URL = 'http://localhost:9000'
