import os
from celery import Celery
from flask import Flask, jsonify, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_sslify import SSLify
from flask_migrate import Migrate
import platform
import sys

# Set Flask app environment variable
os.environ['FLASK_APP'] = 'scrimmage'

# Initialize Flask app
app = Flask(__name__)

# Load configuration
config_object_str = 'scrimmage.config.ProdConfig' if os.environ.get('PRODUCTION', False) else 'scrimmage.config.DevConfig'
app.config.from_object(config_object_str)

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
sslify = SSLify(app)

# Set up Kerberos login for admin access --> need to change implementation for deployment
@app.route('/setadmin/<kerberos>')
def setadmin(kerberos):
    session['kerberos'] = kerberos
    session['real_kerberos'] = kerberos
    return redirect(url_for('admin_index'))

# Custom health check endpoint
@app.route('/check')
def health_check():
    try:
        # Test database connection
        db.engine.execute('SELECT 1')
        return jsonify({"status": "healthy"}), 200
    except Exception as e:
        return jsonify({"status": "unhealthy", "error": str(e)}), 500

# Custom environment dump endpoint
@app.route('/environment')
def environment_dump():
    def safe_serialize(obj):
        try:
            return str(obj)
        except Exception:
            return None

    # Gather environment information
    env_info = {
        "python_version": sys.version,
        "platform": platform.platform(),
        "environment_variables": {k: safe_serialize(v) for k, v in os.environ.items()},
        "app_config": {k: safe_serialize(v) for k, v in app.config.items() if not k.startswith('_')}
    }
    return jsonify(env_info)

# Celery setup
def make_celery(flask_app):
    celery = Celery(flask_app.import_name, broker=flask_app.config['CELERY_BROKER_URL'])
    celery.conf.update(flask_app.config)
    TaskBase = celery.Task

    class ContextTask(TaskBase):
        abstract = True

        def __call__(self, *args, **kwargs):
            with flask_app.app_context():
                return TaskBase.__call__(self, *args, **kwargs)

    celery.Task = ContextTask
    return celery

celery_app = make_celery(app)

# Import routes and tasks
import scrimmage.user
import scrimmage.admin
import scrimmage.sponsor
import scrimmage.tasks


# import os
# os.environ['FLASK_APP'] = 'scrimmage'
# from celery import Celery
# from flask import Flask
# from flask_sqlalchemy import SQLAlchemy
# from flask_sslify import SSLify
# from healthcheck import HealthCheck, EnvironmentDump
# from flask_migrate import Migrate

# app = Flask(__name__)
# config_object_str = 'scrimmage.config.ProdConfig' if os.environ.get('PRODUCTION', False) else 'scrimmage.config.DevConfig'
# app.config.from_object(config_object_str)
# db = SQLAlchemy(app)
# migrate = Migrate(app, db)
# sslify = SSLify(app)

# health = HealthCheck(app, "/check")
# envdump = EnvironmentDump(app, "/environment")

# def make_celery(flask_app):
#     celery = Celery(flask_app.import_name, broker=flask_app.config['CELERY_BROKER_URL'])
#     celery.conf.update(flask_app.config)
#     TaskBase = celery.Task
#     class ContextTask(TaskBase):
#         abstract = True
#         def __call__(self, *args, **kwargs):
#             with flask_app.app_context():
#                 return TaskBase.__call__(self, *args, **kwargs)
#     celery.Task = ContextTask
#     return celery


# celery_app = make_celery(app)

# import scrimmage.user
# import scrimmage.admin
# import scrimmage.sponsor
# import scrimmage.tasks
