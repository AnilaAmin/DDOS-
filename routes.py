from flask import request, jsonify
from app import jwt
from models import User
  
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()

    if not user or user.password != password:
        return jsonify({'error': 'Invalid username or password'}), 401

    access_token = create_access_token(identity=user.id)
    return jsonify(access_token=access_token), 200

@jwt.user_loader_callback_loader
def user_loader_callback(identity):
    user = User.query.get(identity)
    return user
@app.route('/dashboard')
@jwt.jwt_required()
def dashboard():
    # Access the user's ID from the JWT token
    user_id = get_jwt_identity()
    # Use the user's ID to retrieve their data from the database
    user_data = User.query.get(user_id)
    return jsonify(user_data.to_dict()), 200