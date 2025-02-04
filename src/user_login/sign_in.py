########################### Sign in Sign Out ###################################################

import os
from src.utils.aws_data import *
from src.user_login.email_verification import *
from datetime import datetime

from flask_jwt_extended import create_access_token

# API Endpoints

# 3. Sign In

@app.route('/api/sign-in', methods=['POST'])
def sign_in():
    try:
        # Parse input data
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')

        # Validate input
        if not all([email, password]):
            return jsonify({"message": "Email and password are required"}), 400

        # Verify user credentials
        user_data = load_user_data(email)  # Replace with your function to load user details
        if not user_data or not bcrypt.check_password_hash(user_data["password"], password):
            return jsonify({"message": "Invalid email or password"}), 401

        # Create JWT token
        token = create_access_token(identity=email)  # `identity` will be stored as the `sub` claim

        # Return the token
        return jsonify({
            "message": "Sign in successful",
            "token": token
        }), 200

    except Exception as e:
        print(f"Error during sign-in: {e}")
        return jsonify({"message": "Internal server error"}), 500
