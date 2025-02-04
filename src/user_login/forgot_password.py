from src.utils.aws_data import *
from src.user_login.email_verification import *
#  # 4. Forgot Password

import traceback

@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    try:
        data = request.get_json()
        print("Data received:", data)
        if not data:
            return jsonify({"message": "Invalid JSON"}), 400
 
        email = data.get('email')
        print("Email extracted:", email)
        if not email:
            return jsonify({"message": "Email is required"}), 400
 
        # Generate a reset code
        reset_code = random.randint(100000, 999999)
        print("Reset code generated:", reset_code)
 
        # Load the user data
        user_data = load_user_data(email)
        if not user_data:
            return jsonify({"message": "User not found"}), 404
 
        # Add the reset code to the user data
        user_data['reset_code'] = reset_code
        user_data['reset_timestamp'] = str(datetime.now())
 
        # Save the updated user data
        save_user_data(user_data, email)
        print("Reset data saved successfully.")
 
        # Send reset code via email
        if send_email(email, reset_code):
            print("Email sent successfully.")
            return jsonify({"message": "Password reset code sent successfully"}), 200
        else:
            print("Failed to send email.")
            return jsonify({"error": "Failed to send reset code"}), 500
 
    except Exception as e:
        traceback.print_exc()  # Logs the full stack trace
        return jsonify({"error": "Internal server error"}), 500
 
