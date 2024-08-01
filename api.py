from flask import Blueprint, request, jsonify
from flask_restx import Api, Resource, fields, Namespace
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import jwt_required, create_access_token, get_jwt_identity
from datetime import timedelta
from models import db, User, RoleEnum

api_bp = Blueprint('api', __name__)

# Initialize API with proper authorization
authorizations = {
    'Bearer Auth': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'Authorization'
    },
}

api = Api(
    api_bp,
    version='1.0',
    title='User Management API',
    description='A simple User Management API',
    doc='/swagger',
    authorizations=authorizations,
    security='Bearer Auth'
)

# Define models
user_model = api.model('User', {
    'username': fields.String(required=True, description='The user\'s username'),
    'firstname': fields.String(required=True, description='The user\'s first name'),
    'lastname': fields.String(required=True, description='The user\'s last name'),
    'password': fields.String(required=True, description='The user\'s password'),
    'email': fields.String(required=True, description='The user\'s email address'),
    'role': fields.String(description='The user\'s role'),
    'active': fields.Boolean(description='The user\'s active status')
})

login_model = api.model('Login', {
    'email': fields.String(required=True, description='The user\'s email address'),
    'password': fields.String(required=True, description='The user\'s password'),
})

update_user_model = api.model('UpdateUser', {
    'username': fields.String(description='The user\'s username'),
    'firstname': fields.String(description='The user\'s first name'),
    'lastname': fields.String(description='The user\'s last name'),
    'password': fields.String(description='The user\'s password'),
    'email': fields.String(description='The user\'s email address'),
    'active': fields.Boolean(description='The user\'s active status')
})

reset_password_model = api.model('ResetPassword', {
    'new_password': fields.String(required=True, description='The new password')
})

# Register endpoint
@api.route('/register')
class Register(Resource):
    @api.doc(security=None)
    @api.expect(user_model)
    def post(self):
        try:
            data = request.json

            # Check if all required fields are provided
            required_fields = ['username', 'firstname', 'lastname', 'password', 'email']
            if not all(field in data for field in required_fields):
                return {'message': 'Missing required fields'}, 400

            # Check if user already exists
            if User.query.filter_by(email=data['email']).first():
                return {'message': 'User already exists'}, 400

            # Create new user
            new_user = User(
                username=data['username'],
                firstname=data['firstname'],
                lastname=data['lastname'],
                password=generate_password_hash(data['password']),
                email=data['email'],
                role=RoleEnum.USER
            )

            # Add to database
            db.session.add(new_user)
            db.session.commit()

            return {'message': 'User created successfully'}, 201

        except Exception as e:
            db.session.rollback()
            return {'message': 'An error occurred', 'error': str(e)}, 500

# Login endpoint
@api.route('/login')
class Login(Resource):
    @api.doc(security=None)
    @api.expect(login_model)
    def post(self):
        try:
            data = request.json

            # Check if all required fields are provided
            required_fields = ['email', 'password']
            if not all(field in data for field in required_fields):
                return {'message': 'Missing required fields'}, 400

            # Check if user exists
            user = User.query.filter_by(email=data['email']).first()
            if not user or not check_password_hash(user.password, data['password']):
                return {'message': 'Invalid email or password'}, 401

            # Create JWT token
            expires = timedelta(hours=1)
            access_token = create_access_token(identity=user.id, expires_delta=expires)

            return {'access_token': access_token}, 200

        except Exception as e:
            return {'message': 'An error occurred', 'error': str(e)}, 500

# Update user endpoint
@api.route('/user')
class UpdateUser(Resource):
    @api.doc(security='Bearer Auth')
    @jwt_required()
    @api.expect(update_user_model)
    def put(self):
        try:
            data = request.json
            user_id = get_jwt_identity()

            user = User.query.get(user_id)
            if not user:
                return {'message': 'User not found'}, 404

            # Validate input data
            if 'username' in data:
                user.username = data['username']
            if 'firstname' in data:
                user.firstname = data['firstname']
            if 'lastname' in data:
                user.lastname = data['lastname']
            if 'password' in data:
                user.password = generate_password_hash(data['password'])
            if 'email' in data:
                if User.query.filter_by(email=data['email']).first() and data['email'] != user.email:
                    return {'message': 'Email already in use'}, 400
                user.email = data['email']
            if 'active' in data:
                user.active = data['active']

            db.session.commit()
            return {'message': 'User updated successfully'}, 200

        except Exception as e:
            db.session.rollback()
            return {'message': 'An error occurred', 'error': str(e)}, 500


# Reset password endpoint
@api.route('/reset_password')
class ResetPassword(Resource):
    @api.doc(security='Bearer Auth')
    @jwt_required()
    @api.expect(reset_password_model)
    def patch(self):
        try:
            data = request.json
            current_user_id = get_jwt_identity()

            if 'new_password' not in data:
                return {'message': 'New password is required'}, 400

            user = User.query.get(current_user_id)
            if not user:
                return {'message': 'User not found'}, 404

            user.password = generate_password_hash(data['new_password'])

            db.session.commit()
            return {'message': 'Password updated successfully'}, 200

        except Exception as e:
            db.session.rollback()
            return {'message': 'An error occurred', 'error': str(e)}, 500

# Delete account endpoint
@api.route('/account')
class DeleteAccount(Resource):
    @api.doc(security='Bearer Auth')
    @jwt_required()
    def delete(self):
        try:
            current_user_id = get_jwt_identity()

            user = User.query.get(current_user_id)
            if not user:
                return {'message': 'User not found'}, 404

            db.session.delete(user)
            db.session.commit()

            return {'message': 'Account deleted successfully'}, 200

        except Exception as e:
            db.session.rollback()
            return {'message': 'An error occurred', 'error': str(e)}, 500

# Admin namespace
admin_ns = Namespace('admin', description='Admin operations')
api.add_namespace(admin_ns)

@admin_ns.route('/register')
class AdminRegister(Resource):
    @api.doc(security=None)
    @api.expect(user_model)
    def post(self):
        try:
            data = request.json

            required_fields = ['username', 'firstname', 'lastname', 'password', 'email']
            if not all(field in data for field in required_fields):
                return {'message': 'Missing required fields'}, 400

            if User.query.filter_by(email=data['email']).first():
                return {'message': 'User already exists'}, 400

            new_user = User(
                username=data['username'],
                firstname=data['firstname'],
                lastname=data['lastname'],
                password=generate_password_hash(data['password']),
                email=data['email'],
                role=RoleEnum.ADMIN
            )

            db.session.add(new_user)
            db.session.commit()

            return {'message': 'Admin created successfully'}, 201

        except Exception as e:
            db.session.rollback()
            return {'message': 'An error occurred', 'error': str(e)}, 500

@admin_ns.route('/promote/<int:user_id>')
class PromoteUser(Resource):
    @api.doc(security='Bearer Auth')
    @jwt_required()
    @api.expect(update_user_model)
    def put(self, user_id):
        try:
            data = request.json
            current_user_id = get_jwt_identity()

            current_user = User.query.get(current_user_id)
            if not current_user or current_user.role != RoleEnum.ADMIN:
                return {'message': 'You are not authorized to perform this action'}, 403

            user = User.query.get(user_id)
            if not user:
                return {'message': 'User not found'}, 404

            if 'role' in data:
                if data['role'] in RoleEnum.__members__:
                    user.role = RoleEnum[data['role']]
                else:
                    return {'message': 'Invalid role'}, 400

            db.session.commit()
            return {'message': 'User promoted successfully'}, 200

        except Exception as e:
            db.session.rollback()
            return {'message': 'An error occurred', 'error': str(e)}, 500

@admin_ns.route('/delete_user/<int:user_id>')
class DeleteUser(Resource):
    @api.doc(security='Bearer Auth')
    @jwt_required()
    def delete(self, user_id):
        try:
            current_user_id = get_jwt_identity()

            current_user = User.query.get(current_user_id)
            if not current_user or current_user.role != RoleEnum.ADMIN:
                return {'message': 'You are not authorized to perform this action'}, 403

            user = User.query.get(user_id)
            if not user:
                return {'message': 'User not found'}, 404

            if user.role == RoleEnum.ADMIN:
                return {'message': 'You cannot delete another admin\'s profile'}, 403

            db.session.delete(user)
            db.session.commit()

            return {'message': 'User deleted successfully'}, 200

        except Exception as e:
            db.session.rollback()
            return {'message': 'An error occurred', 'error': str(e)}, 500
