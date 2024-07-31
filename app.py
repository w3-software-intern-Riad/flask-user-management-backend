from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy import Enum
from enum import Enum as PyEnum
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required
from datetime import timedelta  # Import timedelta for token expiry

app = Flask(__name__)

# Configure the PostgreSQL database connection
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:p%40stgress@localhost:5433/users'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'my_jwt_secret_key'  # Change this to a strong secret key

db = SQLAlchemy(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)  # Initialize JWTManager with the Flask app

class RoleEnum(PyEnum):
    ADMIN = 'admin'
    USER = 'user'

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    firstname = db.Column(db.String(80), nullable=False)
    lastname = db.Column(db.String(80), nullable=False)
    password = db.Column(db.String(255), nullable=False)  # Increased length
    email = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(Enum(RoleEnum), default=RoleEnum.USER)
    created_at = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())
    updated_at = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())
    active = db.Column(db.Boolean, default=True)

with app.app_context():
    db.create_all()

@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.json

        # Check if all required fields are provided
        required_fields = ['username', 'firstname', 'lastname', 'password', 'email']
        if not all(field in data for field in required_fields):
            return jsonify({"message": "Missing required fields"}), 400

        # Check if user already exists
        if User.query.filter_by(email=data['email']).first():
            return jsonify({"message": "User already exists"}), 400

        # Create new user
        new_user = User(
            username=data['username'],
            firstname=data['firstname'],
            lastname=data['lastname'],
            password=generate_password_hash(data['password']),  # Hash the password
            email=data['email'],
            role=RoleEnum.USER
        )

        # Add to database
        db.session.add(new_user)
        db.session.commit()

        return jsonify({"message": "User created successfully"}), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({"message": "An error occurred", "error": str(e)}), 500

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.json

        # Check if all required fields are provided
        required_fields = ['email', 'password']
        if not all(field in data for field in required_fields):
            return jsonify({"message": "Missing required fields"}), 400

        # Check if user exists
        user = User.query.filter_by(email=data['email']).first()
        if not user or not check_password_hash(user.password, data['password']):
            return jsonify({"message": "Invalid email or password"}), 401

        # Create JWT token
        expires = timedelta(hours=1460)  # Set token to expire in 1 hour
        access_token = create_access_token(identity=user.id)

        return jsonify(access_token=access_token), 200

    except Exception as e:
        return jsonify({"message": "An error occurred", "error": str(e)}), 500
    


@app.route('/update_user', methods=['PUT'])
@jwt_required()
def update_user():
    try:
        data = request.json
        user_id = get_jwt_identity()  # Get the current user's ID from the JWT

        user = User.query.get(user_id)
        if not user:
            return jsonify({"message": "User not found"}), 404

        # Validate input data
        if 'username' in data:
            user.username = data['username']
        if 'firstname' in data:
            user.firstname = data['firstname']
        if 'lastname' in data:
            user.lastname = data['lastname']
        if 'password' in data:
            user.password = generate_password_hash(data['password'])  # Hash the new password
        if 'email' in data:
            if User.query.filter_by(email=data['email']).first() and data['email'] != user.email:
                return jsonify({"message": "Email already in use"}), 400
            user.email = data['email']
      
        if 'active' in data:
            user.active = data['active']

        db.session.commit()
        return jsonify({"message": "User updated successfully"}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"message": "An error occurred", "error": str(e)}), 500   


@app.route('/admin/register', methods=['POST'])
def admin_register():
    try:
        data = request.json

        # Check if all required fields are provided
        required_fields = ['username', 'firstname', 'lastname', 'password', 'email']
        if not all(field in data for field in required_fields):
            return jsonify({"message": "Missing required fields"}), 400

        # Check if user already exists
        if User.query.filter_by(email=data['email']).first():
            return jsonify({"message": "User already exists"}), 400

        # Determine role
        role = RoleEnum.ADMIN 

        # Create new user
        new_user = User(
            username=data['username'],
            firstname=data['firstname'],
            lastname=data['lastname'],
            password=generate_password_hash(data['password']),  # Hash the password
            email=data['email'],
            role=role
        )

        # Add to database
        db.session.add(new_user)
        db.session.commit()

        return jsonify({"message": "Admin created successfully"}), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({"message": "An error occurred", "error": str(e)}), 500  

@app.route('/admin/create_admin/', methods=['PUT'])
@jwt_required()
def create_admin():
    try:
        data = request.json
        target_user_id = request.args.get('user_id')  # Get user_id from query parameters
        current_user_id = get_jwt_identity()  # Get the current user's ID from the JWT

        # Check if the current user is an admin
        current_user = User.query.get(current_user_id)
        if not current_user or current_user.role != RoleEnum.ADMIN:
            return jsonify({"message": "You are not authorized to perform this action"}), 403

        # Find the target user by ID
        user = User.query.get(target_user_id)
        if not user:
            return jsonify({"message": "User not found"}), 404

        # Validate and update input data
        if 'username' in data:
            user.username = data['username']
        if 'firstname' in data:
            user.firstname = data['firstname']
        if 'lastname' in data:
            user.lastname = data['lastname']
        if 'password' in data:
            user.password = generate_password_hash(data['password'])  # Hash the new password
        if 'email' in data:
            if User.query.filter_by(email=data['email']).first() and data['email'] != user.email:
                return jsonify({"message": "Email already in use"}), 400
            user.email = data['email']
        if 'role' in data:
            if data['role'] in RoleEnum.__members__:
                user.role = RoleEnum[data['role']]
            else:
                return jsonify({"message": "Invalid role"}), 400
        if 'active' in data:
            user.active = data['active']

        db.session.commit()
        return jsonify({"message": "User updated successfully"}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"message": "An error occurred", "error": str(e)}), 500


@app.route('/reset_password', methods=['PATCH'])
@jwt_required()
def reset_password():
    try:
        data = request.json
        current_user_id = get_jwt_identity()  # Get the current user's ID from the JWT

        # Check if the request contains a new password
        if 'new_password' not in data:
            return jsonify({"message": "New password is required"}), 400

        # Find the current user
        user = User.query.get(current_user_id)
        if not user:
            return jsonify({"message": "User not found"}), 404

        # Validate and update the password
        new_password = data['new_password']
        user.password = generate_password_hash(new_password)  # Hash the new password

        db.session.commit()
        return jsonify({"message": "Password updated successfully"}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"message": "An error occurred", "error": str(e)}), 500        

if __name__ == '__main__':
    app.run(debug=True)
