from dotenv import load_dotenv
from flask.cli import FlaskGroup
from scrimmage import app, db

load_dotenv()

# Create FlaskGroup instance
cli = FlaskGroup(app)

if __name__ == '__main__':
    cli()
