from src.user_login.send_emails import *
import dns.resolver  # For checking email domain validity
import string

# 🔹 Function to Validate Email Domain (MX Record Lookup)

def is_valid_email_domain(email):
    """Checks if the domain of the email has valid MX records."""
    try:
        domain = email.split('@')[1]  # Extract domain from email
        dns.resolver.resolve(domain, 'MX')  # Check MX records
        return True
    except dns.resolver.NoAnswer:
        return False  # No MX record found
    except dns.resolver.NXDOMAIN:
        return False  # Domain does not exist
    except Exception as e:
        print(f"DNS lookup error for {email}: {e}")
        return False  # Other DNS errors
 
# Function to Generate OTP


def generate_otp():
    return str(random.randint(100000, 999999))

# def generate_otp(length=6):
#     """Generates a random OTP of given length."""
#     return ''.join(random.choices(string.digits, k=length))


# 1. Email verification :
 
@app.route('/api/email-verification', methods=['POST'])
def email_verification():
    try:
        email = request.json.get('email')  # Extract email from the request
        url = request.json.get('url','https://wealth-management.mresult.net')
        if not email:
            return jsonify({"message": "Email is required"}), 400
        
        #  Check if Email Domain is Valid (MX Lookup)
        if not is_valid_email_domain(email):
            return jsonify({"message": "Invalid email address, please enter a valid email"}), 400

        print(f"Processing email verification for: {email}")
 
        # Generate the sign-up link
        sign_up_link = f"{url}/signUp/{email}"
 
        # Create the email message
        msg = Message(
            "Sign-Up Link - Verify Your Email",
            sender="your_email@gmail.com",
            recipients=[email]
        )
        
        # add check whether the email is valid and verified :
        otp = generate_otp()
        otp_store[email] = otp
        print(f"Generated OTP for {email}: {otp}")
        
        msg.body = (
            f"Dear User,\n\n"
            f"Congratulations! Your email has been successfully verified. You're just one step away from completing your sign-up process.\n\n"
            f"Your OTP for verification is: {otp}\n\n"
            f"Click the link below to finish setting up your account:\n"
            f"{sign_up_link}\n\n"
            f"Thank you for choosing us.\n\n"
        )
       
        print(f"Sending email to: {email}\nContent: {msg.body}")
       
        # Send the email
        
        mail.send(msg)
        print("Email sent successfully.")
        
        otp_store[email] = otp
        otps = otp_store[email]
        print(f"otp store : {otps}")
        return jsonify({"message": "Sign-up link and OTP sent successfully", "otp": otp}), 200
        # return jsonify({"message": "Sign-up link sent successfully"}), 200
 
    except Exception as e:
        print(f"Error sending email: {e}")
        return jsonify({"message": f"Error occurred: {str(e)}"}), 500