from src.user_login.send_emails import *
from src.utils.aws_data import *

# 2. Sign Up

@app.route('/api/sign-up', methods=['POST'])
def sign_up():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"message": "Invalid JSON"}), 400
 
        email = data.get('email')
        password = data.get('password')
        confirm_password = data.get('confirm_password')
        otp = data.get('otp')
        first_name = data.get('first_name')
        last_name = data.get('last_name')
 
        if not all([email, password,otp, confirm_password, first_name, last_name]):
            return jsonify({"message": "All fields are required"}), 400
 
        if password != confirm_password:
            return jsonify({"message": "Passwords do not match"}), 400
 
        if load_user_data(email):
            return jsonify({"message": "User already exists"}), 400
        
        print(type(otp))
        # Validate OTP
        if otp_store[email] == str(otp):  # OTP and user input should both be strings
            del otp_store[email]
            print("OTP verified successfully!")
        else:
            return jsonify({"message": "Invalid OTP"}), 400
        
        # if otp_store.get(email) == int(otp):
        #     del otp_store[email]
        #     print("OTP verified successfully!")
        # else:
        #     return jsonify({"error": "Invalid OTP"}), 400
 
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user_data = {
            "email": email,
            "password": hashed_password,
            "first_name": first_name,
            "last_name": last_name,
            "data": {}
        }
 
        save_user_data(user_data, email)
        return jsonify({"message": "Sign up successful"}), 200
    except Exception as e:
        print(f"Error in sign-up: {e}")
        return jsonify({"message": "Internal server error"}), 500
   