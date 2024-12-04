########################### Sign in Sign Out ###################################################


from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
import random
import boto3
import json
from datetime import datetime

# Flask app initialization
app = Flask(__name__)
bcrypt = Bcrypt(app)

# Email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your_email@gmail.com'
app.config['MAIL_PASSWORD'] = 'your_email_password'

mail = Mail(app)

# AWS S3 setup
s3 = boto3.client('s3')
S3_BUCKET_NAME = "boston-harbor-data"

# Helper functions
def upload_to_s3(data, filename):
    s3.put_object(Bucket=S3_BUCKET_NAME, Key=filename, Body=json.dumps(data))
    return f"s3://{S3_BUCKET_NAME}/{filename}"

def download_from_s3(filename):
    try:
        response = s3.get_object(Bucket=S3_BUCKET_NAME, Key=filename)
        return json.loads(response['Body'].read().decode('utf-8'))
    except Exception as e:
        return None

# API Endpoints
# 1. Email Verification
@app.route('/email-verification', methods=['POST'])
def email_verification():
    try:
        email = request.json.get('email')
        if not email:
            return jsonify({"message": "Email is required"}), 400

        # Generate a 6-digit verification code
        verification_code = random.randint(100000, 999999)
        
        # Send the email with the verification code
        msg = Message("Your Verification Code", recipients=[email])
        msg.body = f"Your verification code is: {verification_code}"
        mail.send(msg)

        # Save the verification code in S3
        data = {"email": email, "verification_code": verification_code, "timestamp": str(datetime.now())}
        upload_to_s3(data, f"verification_codes/{email}.json")

        return jsonify({"message": "Verification code sent successfully"}), 200
    except Exception as e:
        return jsonify({"message": f"Error occurred: {str(e)}"}), 500

# 2. Sign Up
@app.route('/sign-up', methods=['POST'])
def sign_up():
    try:
        email = request.json.get('email')
        password = request.json.get('password')
        confirm_password = request.json.get('confirm_password')
        verification_code = request.json.get('verification_code')

        if not all([email, password, confirm_password, verification_code]):
            return jsonify({"message": "All fields are required"}), 400

        if password != confirm_password:
            return jsonify({"message": "Passwords do not match"}), 400

        # Fetch and validate verification code from S3
        verification_data = download_from_s3(f"verification_codes/{email}.json")
        if not verification_data or str(verification_data["verification_code"]) != str(verification_code):
            return jsonify({"message": "Invalid verification code"}), 400

        # Hash the password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Save user data in S3
        user_data = {"email": email, "password": hashed_password}
        upload_to_s3(user_data, f"users/{email}.json")

        return jsonify({"message": "Sign up successful"}), 201
    except Exception as e:
        return jsonify({"message": f"Error occurred: {str(e)}"}), 500

# 3. Sign In
@app.route('/sign-in', methods=['POST'])
def sign_in():
    try:
        email = request.json.get('email')
        password = request.json.get('password')

        if not all([email, password]):
            return jsonify({"message": "Email and password are required"}), 400

        # Fetch user data from S3
        user_data = download_from_s3(f"users/{email}.json")
        if not user_data or not bcrypt.check_password_hash(user_data["password"], password):
            return jsonify({"message": "Invalid email or password"}), 401

        return jsonify({"message": "Sign in successful"}), 200
    except Exception as e:
        return jsonify({"message": f"Error occurred: {str(e)}"}), 500

# 4. Forgot Password
@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    try:
        email = request.json.get('email')
        if not email:
            return jsonify({"message": "Email is required"}), 400

        # Generate a 6-digit reset code
        reset_code = random.randint(100000, 999999)

        # Send the reset code via email
        msg = Message("Password Reset Code", recipients=[email])
        msg.body = f"Your password reset code is: {reset_code}"
        mail.send(msg)

        # Save the reset code in S3
        data = {"email": email, "reset_code": reset_code, "timestamp": str(datetime.now())}
        upload_to_s3(data, f"password_resets/{email}.json")

        return jsonify({"message": "Password reset code sent successfully"}), 200
    except Exception as e:
        return jsonify({"message": f"Error occurred: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(debug=True)
