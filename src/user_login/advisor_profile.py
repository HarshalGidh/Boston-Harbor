from src.utils.aws_data import *
from src.utils.app_config import *
from src.user_login.email_verification import *
import requests

# ------------------------- With Bearer ------------------------------

# v-2 

from flask import Flask, request, jsonify, send_from_directory, url_for
from flask_jwt_extended import jwt_required, get_jwt_identity, JWTManager
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message
import base64

PROFILE_PHOTOS_DIR = "local_data/profile_photos"

# ✅ GET/POST Advisor Profile Endpoint
@app.route('/api/advisor_profile', methods=['POST', 'GET'])
@jwt_required()  # Requires a valid JWT
def advisor_profile():
    try:
        email = get_jwt_identity()  # Extract email from JWT Token
        user_data = load_user_data(email)
        if not user_data:
            return jsonify({"message": "User not found"}), 404

        url = request.args.get('url', 'http://wealth-management.mresult.net')
        print(f"URL : {url}")

        # ✅ Handle GET Request (Retrieve Profile)
        if request.method == 'GET':
            # ✅ Fetch client data count (With Auth Token)
            client_data_url = f'{url}/api/get-all-client-data'
            token = request.headers.get("Authorization")  # Extract token from headers
            
            headers = {"Authorization": token}  # Attach token to request
            response = requests.get(client_data_url, headers=headers)  # Make Authenticated Request

            client_count = 0
            if response.status_code == 200:
                client_list = response.json().get('data', [])
                client_count = len(client_list)

            # ✅ Generate URL for profile photo
            filename = f"{email}_profile.jpeg"
            profile_photo_url = url_for('serve_profile_photo', filename=filename, _external=True)

            profile_data = {
                "email": user_data["email"],
                "first_name": user_data["first_name"],
                "last_name": user_data["last_name"],
                "client_count": client_count,
                "profile_photo_url": profile_photo_url
            }

            return jsonify({"message": "Profile retrieved successfully", "profile": profile_data}), 200

        # ✅ Handle POST Request (Upload Profile Photo)
        if request.method == 'POST':
            data = request.get_json()
            if not data or 'profile_photo' not in data:
                return jsonify({"message": "Profile photo is missing"}), 400

            # ✅ Decode the base64 image
            profile_photo = data['profile_photo']
            file_extension = "jpg"
            if profile_photo.startswith("data:image/"):
                file_extension = profile_photo.split(";")[0].split("/")[-1]

            image_data = profile_photo.split(",")[1]
            image_bytes = base64.b64decode(image_data)

            # ✅ Save the file
            filename = f"{email}_profile.{file_extension}"
            file_path = os.path.join(PROFILE_PHOTOS_DIR, filename)
            with open(file_path, "wb") as f:
                f.write(image_bytes)

            # ✅ Generate profile photo URL
            profile_photo_url = url_for('serve_profile_photo', filename=filename, _external=True)

            # ✅ Update user data
            user_data["profile_photo_url"] = profile_photo_url
            save_user_data(email, user_data)

            return jsonify({"message": "Profile photo uploaded successfully", "profile_photo_url": profile_photo_url}), 200

    except Exception as e:
        print(f"Error processing request: {e}")
        return jsonify({"message": "Internal server error"}), 500

# ✅ Serve Profile Photo
@app.route('/api/profile_photos/<filename>', methods=['GET'])
def serve_profile_photo(filename):
    try:
        return send_from_directory(PROFILE_PHOTOS_DIR, filename)
    except Exception as e:
        print(f"Error serving profile photo: {e}")
        return jsonify({"message": "Error retrieving profile photo"}), 500


# -------------------------------------------

#  Change Password for Profile

@app.route('/api/change_password', methods=['POST'])
def change_password():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"message": "Invalid JSON"}), 400

        email = data.get('email')
        old_password = data.get('old_password')
        new_password = data.get('new_password')
        confirm_password = data.get('confirm_password')

        if not all([email, old_password, new_password, confirm_password]):
            return jsonify({"message": "All fields are required"}), 400

        # Check if new password matches the confirm password
        if new_password != confirm_password:
            return jsonify({"message": "Passwords do not match"}), 400

        # Load user data
        if USE_AWS:
            # filename = f"{signUp_user_folder}/{email}.json"
            filename = f"{signUp_user_folder}{email}.json"
            user_data = load_from_aws(filename)
        else:
            filepath = os.path.join(LOCAL_STORAGE_PATH, f"users/{email}.json")
            user_data = load_from_local(filepath)

        if not user_data:
            return jsonify({"message": "User not found"}), 404

        # Check if old password is correct
        if not bcrypt.check_password_hash(user_data["password"], old_password):
            return jsonify({"message": "Old password is incorrect"}), 401

        # Hash the new password
        hashed_new_password = bcrypt.generate_password_hash(new_password).decode('utf-8')

        # Update the user data with the new password
        user_data["password"] = hashed_new_password

        # Save updated user data
        if USE_AWS:
            save_to_aws(user_data, filename)
        else:
            save_to_local(user_data, filepath)

        return jsonify({"message": "Password reset successful"}), 200

    except Exception as e:
        print(f"Error in change_password: {e}")
        return jsonify({"message": "Internal server error"}), 500

 