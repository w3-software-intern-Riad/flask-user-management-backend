from flask import Flask, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
from dotenv import load_dotenv
import os
from config import Config
from models import db
from api import api_bp

load_dotenv()

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)

# Register the Blueprint
app.register_blueprint(api_bp, url_prefix='/api')

# JWT error handlers
@jwt.unauthorized_loader
def unauthorized_response(callback):
    return jsonify({
        'message': 'Missing Authorization Header'
    }), 401

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({
        'message': 'The token has expired'
    }), 401

if __name__ == '__main__':
    app.run(debug=True)
