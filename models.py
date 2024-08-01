from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Enum
from enum import Enum as PyEnum
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class RoleEnum(PyEnum):
    ADMIN = 'admin'
    USER = 'user'

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    firstname = db.Column(db.String(80), nullable=False)
    lastname = db.Column(db.String(80), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(Enum(RoleEnum), default=RoleEnum.USER)
    created_at = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())
    updated_at = db.Column(db.DateTime, nullable=True, default=None, onupdate=db.func.current_timestamp())
    active = db.Column(db.Boolean, default=True)

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)
