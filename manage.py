from flask.cli import FlaskGroup
from scrimmage import app, db

# Create FlaskGroup instance
cli = FlaskGroup(app)

if __name__ == '__main__':
    cli()
