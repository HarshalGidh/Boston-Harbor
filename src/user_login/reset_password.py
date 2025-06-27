from src.utils.aws_data import *
from src.user_login.email_verification import *
import traceback
# 5. Reset password :

@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    try:
        data = request.get_json()
        print("Data received:", data)
 
        email = data.get('email')
        reset_code = data.get('reset_code')
        new_password = data.get('new_password')
 
        if not all([email, reset_code, new_password]):
            return jsonify({"message": "All fields are required"}), 400
 
        email = email.lower()
        user_data = load_user_data(email)
 
        if not user_data:
            return jsonify({"message": "User not found"}), 404
 
        user_reset_code = user_data.get('reset_code')
        print(f"Reset code from request: {reset_code}")
        print(f"Reset code from user data: {user_reset_code}")
 
        if str(user_reset_code) != str(reset_code):
            print(f"Reset code from request: {reset_code}")
            print(f"Reset code from user data: {user_reset_code}")
            return jsonify({"message": "Invalid reset code"}), 400
 
        # Update password
        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        user_data['password'] = hashed_password
        user_data.pop('reset_code', None)
        user_data.pop('reset_timestamp', None)
 
        save_user_data(user_data, email)
        return jsonify({"message": "Password reset successful"}), 200
 
    except Exception as e:
        traceback.print_exc()
        return jsonify({"message": "Internal server error"}), 500
 
 