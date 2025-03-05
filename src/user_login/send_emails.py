import os
from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
import random
import boto3
import json
from datetime import datetime
import re
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta,timezone
from src.utils.app_config import *
from src.utils.aws_config import *

# Flask app initialization
# app = Flask(__name__)
bcrypt = Bcrypt(app)

app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')

bcrypt = Bcrypt(app)

# Email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME') # 'your_email@gmail.com'
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD') #'your_email_password'

mail = Mail(app)

# AWS S3 setup
# s3 = boto3.client('s3')
# S3_BUCKET_NAME = os.getenv('S3_BUCKET_NAME')

# In-memory storage for email and OTP (for simplicity)
otp_store = {}

# API Endpoints

# Replace with your email credentials
EMAIL_ADDRESS = os.getenv('MAIL_USERNAME')  #'your-email@gmail.com'
EMAIL_PASSWORD = os.getenv('MAIL_PASSWORD')  #'your-email-password'

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
    
# def send_email(to_email, otp):
#     try:
#         print(f"to_email{to_email}")
#         # Validate email format
#         if not re.match(r"[^@]+@[^@]+\.[^@]+", to_email):
#             print(f"Invalid email address: {to_email}")
#             return False
 
#         # Setup email message
#         subject = "Your Reset Password Code"
#         message = f"Your Reset Password Code is: {otp}"
#         msg = MIMEMultipart()
#         msg['From'] = EMAIL_ADDRESS
#         msg['To'] = to_email
#         msg['Subject'] = subject
#         msg.attach(MIMEText(message, 'plain'))
 
#         # Send email using SMTP
#         with smtplib.SMTP('smtp.gmail.com', 587) as server:
#             server.starttls()
#             server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
#             server.sendmail(EMAIL_ADDRESS, to_email, msg.as_string())
#         print("Email sent successfully")
#         return True
#     except Exception as e:
#         print(f"Error sending email: {e}")
#         return False
    
    
# Email configuration : Gmail Working Method :

# app.config['MAIL_SERVER'] = 'smtp.gmail.com'
# app.config['MAIL_PORT'] = 587
# app.config['MAIL_USE_TLS'] = True
# app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME') # 'your_email@gmail.com'
# app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD') #'your_email_password'

# mail = Mail(app)
# print(f"Mail object: {mail}")

# # In-memory storage for email and OTP (for simplicity)
# otp_store = {}

# # API Endpoints
# from flask import Flask, request, jsonify
# import random
# import smtplib
# from email.mime.text import MIMEText
# from email.mime.multipart import MIMEMultipart

# # Replace with your email credentials
# EMAIL_ADDRESS = os.getenv('MAIL_USERNAME')  #'your-email@gmail.com'
# EMAIL_PASSWORD = os.getenv('MAIL_PASSWORD')  #'your-email-password'

# Previous Wroking Code with Personal Email Id : 
# Send email :
# from src.user_login.send_emails import send_email

# need to include failsafe system when email bounces back 
# def is_valid_email_domain(email):
#     """Checks if the domain of the email has valid MX records."""
#     try:
#         domain = email.split('@')[1]  # Extract domain from email
#         dns.resolver.resolve(domain, 'MX')  # Check MX records
#         return True
#     except dns.resolver.NoAnswer:
#         return False  # No MX record found
#     except dns.resolver.NXDOMAIN:
#         return False  # Domain does not exist
#     except Exception as e:
#         print(f"DNS lookup error for {email}: {e}")
#         return False  # Other DNS errors
 
# Function to Generate OTP
# import string

# def generate_otp():
#     return str(random.randint(100000, 999999))

# def generate_otp(length=6):
#     """Generates a random OTP of given length."""
#     return ''.join(random.choices(string.digits, k=length))
 
# @app.route('/api/email-verification', methods=['POST'])
# def email_verification():
#     try:
#         email = request.json.get('email')  # Extract email from the request
#         url = request.json.get('url','https://wealth-management.mresult.net')
#         if not email:
#             return jsonify({"message": "Email is required"}), 400
        
        # #  Check if Email Domain is Valid (MX Lookup)
        # if not is_valid_email_domain(email):
        #     return jsonify({"message": "Invalid email address, please enter a valid email"}), 400

        # print(f"Processing email verification for: {email}")
 
#         # Generate the sign-up link
#         sign_up_link = f"{url}/signUp/{email}"
 
#         # Create the email message
#         msg = Message(
#             "Sign-Up Link - Verify Your Email",
#             sender="your_email@gmail.com",
#             recipients=[email]
#         )
        
#         # add check whether the email is valid and verified :
#         otp = generate_otp()
#         otp_store[email] = otp
#         print(f"Generated OTP for {email}: {otp}")
        
#         msg.body = (
#             f"Dear User,\n\n"
#             f"Congratulations! Your email has been successfully verified. You're just one step away from completing your sign-up process.\n\n"
#             f"Your OTP for verification is: {otp}\n\n"
#             f"Click the link below to finish setting up your account:\n"
#             f"{sign_up_link}\n\n"
#             f"Thank you for choosing us.\n\n"
#         )
       
#         print(f"Sending email to: {email}\nContent: {msg.body}")
       
#         # Send the email
        
#         mail.send(msg)
#         print("Email sent successfully.")
        
#         otp_store[email] = otp
#         otps = otp_store[email]
#         print(f"otp store : {otps}")
#         return jsonify({"message": "Sign-up link and OTP sent successfully", "otp": otp}), 200
#         # return jsonify({"message": "Sign-up link sent successfully"}), 200
 
#     except Exception as e:
#         print(f"Error sending email: {e}")
#         return jsonify({"message": f"Error occurred: {str(e)}"}), 500


#############################################################################################################

# Working SMTP Method :

# import urllib.request
# import smtplib
# import ssl
# import os
# from flask import Flask, request, jsonify
# from flask_mail import Mail, Message
# from email.mime.multipart import MIMEMultipart
# from email.mime.text import MIMEText

# # ✅ Office 365 SMTP Configuration
# SMTP_SERVER = "smtp.office365.com"
# SMTP_PORT = 587

# # ✅ Get email credentials securely from environment variables
# support_email = os.getenv("support_email", "wealth-mgmt-support@mresult.net")
# support_password = os.getenv("support_password")  # Must be set in environment variables

# app.config['MAIL_SERVER'] = SMTP_SERVER
# app.config['MAIL_PORT'] = SMTP_PORT
# app.config['MAIL_USE_TLS'] = True
# app.config['MAIL_USERNAME'] = support_email
# app.config['MAIL_PASSWORD'] = support_password

# mail = Mail(app)
# print(f"Mail object: {mail}")

# # In-memory storage for email and OTP (for simplicity)
# otp_store = {}

# # ✅ Function to Send Email using Office 365 SMTP
# def send_email(to_email, subject, body):
#     try:
#         # Ensure credentials are set
#         if not support_email or not support_password:
#             print("❌ Email credentials are missing! Set environment variables `SUPPORT_EMAIL` and `SUPPORT_PASSWORD`.")
#             return False

#         # ✅ Construct the email message
#         msg = MIMEMultipart()
#         msg["From"] = support_email
#         msg["To"] = to_email
#         msg["Subject"] = subject
#         msg.attach(MIMEText(body, "plain"))

#         # ✅ Create a secure connection with TLS 1.2
#         context = ssl.create_default_context()

#         with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
#             server.ehlo()  # Identify ourselves to the SMTP server
#             server.starttls(context=context)  # Secure the connection
#             server.ehlo()  # Re-identify after securing the connection
#             server.login(support_email, support_password)  # Login to SMTP server
#             server.sendmail(support_email, to_email, msg.as_string())  # Send email

#         print(f"✅ Email sent successfully to {to_email}")
#         return True

#     except smtplib.SMTPAuthenticationError:
#         print("❌ Authentication Error: Check your username, password, or Office 365 security settings.")
#     except smtplib.SMTPException as e:
#         print(f"❌ SMTP Error: {e}")
#     except Exception as e:
#         print(f"❌ General Error: {e}")
#     return False


# import dns.resolver  # For checking email domain validity
# import string

# # from src.user_login.email_verification import is_valid_email_domain,generate_otp # didnt work

# # need to include failsafe system when email bounces back 
# def is_valid_email_domain(email):
#     """Checks if the domain of the email has valid MX records."""
#     try:
#         domain = email.split('@')[1]  # Extract domain from email
#         dns.resolver.resolve(domain, 'MX')  # Check MX records
#         return True
#     except dns.resolver.NoAnswer:
#         return False  # No MX record found
#     except dns.resolver.NXDOMAIN:
#         return False  # Domain does not exist
#     except Exception as e:
#         print(f"DNS lookup error for {email}: {e}")
#         return False  # Other DNS errors
 
# # Function to Generate OTP
# import string

# def generate_otp():
#     return str(random.randint(100000, 999999))

# #################################################################################################


# # ✅ Function to Send Email using Office 365 SMTP

# import urllib.request
# import smtplib
# import ssl
# import os
# from flask import Flask, request, jsonify
# from flask_mail import Mail, Message
# from email.mime.multipart import MIMEMultipart
# from email.mime.text import MIMEText

# # ✅ Office 365 SMTP Configuration
# SMTP_SERVER = "smtp.office365.com"
# SMTP_PORT = 587

# # ✅ Get email credentials securely from environment variables
# support_email = os.getenv("support_email", "wealth-mgmt-support@mresult.net")
# support_password = os.getenv("support_password")  # Must be set in environment variables

# app.config['MAIL_SERVER'] = SMTP_SERVER
# app.config['MAIL_PORT'] = SMTP_PORT
# app.config['MAIL_USE_TLS'] = True
# app.config['MAIL_USERNAME'] = support_email
# app.config['MAIL_PASSWORD'] = support_password

# mail = Mail(app)
# print(f"Mail object: {mail}")

# # In-memory storage for email and OTP (for simplicity)
# otp_store = {}

# # ✅ Function to Send Email using Office 365 SMTP
# def send_email(to_email, otp):
#     try:
#         print(f"to_email{to_email}")
#         # Validate email format
#         if not re.match(r"[^@]+@[^@]+\.[^@]+", to_email):
#             print(f"Invalid email address: {to_email}")
#             return False
 
#         # Setup email message
#         subject = "Reset Password Request – Your One-Time Password (OTP)"
#         message = (
#             "Dear Valued User,\n\n"
#             "We received a request to reset your password. To proceed with resetting your password, please use the following One-Time Password (OTP):\n\n"
#             f"    OTP: {otp}\n\n"
#             "This OTP is valid for the next 10 minutes. If you did not request a password reset, please disregard this email or contact our support team immediately.\n\n"
#             "Thank you,\n"
#             "Your Support Team"
#         )
        
#         # Create a multipart message
#         msg = MIMEMultipart()
#         msg['From'] = support_email
#         msg['To'] = to_email
#         msg['Subject'] = subject
#         msg.attach(MIMEText(message, 'plain'))
 
#         # Send email using SMTP
#         # ✅ Create a secure connection with TLS 1.2
#         context = ssl.create_default_context()

#         with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
#             server.ehlo()  # Identify ourselves to the SMTP server
#             server.starttls(context=context)  # Secure the connection
#             server.ehlo()  # Re-identify after securing the connection
#             server.login(support_email, support_password)  # Login to SMTP server
#             server.sendmail(support_email, to_email, msg.as_string())  # Send email
        
#         print(f"✅ Email sent successfully to {to_email}")
#         return True
      
#     except Exception as e:
#         print(f"Error sending email: {e}")
#         return False

# import dns.resolver  # For checking email domain validity
# import string

# # from src.user_login.email_verification import is_valid_email_domain,generate_otp # didnt work

# # need to include failsafe system when email bounces back 
# def is_valid_email_domain(email):
#     """Checks if the domain of the email has valid MX records."""
#     try:
#         domain = email.split('@')[1]  # Extract domain from email
#         dns.resolver.resolve(domain, 'MX')  # Check MX records
#         return True
#     except dns.resolver.NoAnswer:
#         return False  # No MX record found
#     except dns.resolver.NXDOMAIN:
#         return False  # Domain does not exist
#     except Exception as e:
#         print(f"DNS lookup error for {email}: {e}")
#         return False  # Other DNS errors
 
# # Function to Generate OTP
# import string

# def generate_otp():
#     return str(random.randint(100000, 999999))

# #################################################################################################

# # # 1. Email Verification :

# # ✅ Email Verification API : using support email :
# @app.route('/api/email-verification', methods=['POST'])
# def email_verification():
#     try:
#         email = request.json.get('email')
#         url = request.json.get('url', 'http://wealth-management.mresult.net')

#         if not email:
#             return jsonify({"message": "Email is required"}), 400
        
#         #  Check if Email Domain is Valid (MX Lookup)
#         if not is_valid_email_domain(email):
#             return jsonify({"message": "Invalid email address, please enter a valid email"}), 400

#         print(f"Processing email verification for: {email}")

#         # ✅ Generate the sign-up link
#         sign_up_link = f"{url}/signUp/{email}"
        
#         # Generate OTP and store it (assuming generate_otp() and otp_store are defined)
#         otp = generate_otp()
#         otp_store[email] = otp
#         print(f"Generated OTP for {email}: {otp}")

#         # ✅ Construct email message
#         msg = Message(
#             "Sign-Up Link - Verify Your Email",
#             sender=support_email,
#             recipients=[email]
#         )
        
#         msg.body = (
#             f"Dear User,\n\n"
#             f"Congratulations! Your email has been successfully verified. You're just one step away from completing your sign-up process.\n\n"
#             f"Your OTP for verification is: {otp}\n\n"
#             f"Click the link below to finish setting up your account:\n"
#             f"{sign_up_link}\n\n"
#             f"Thank you for choosing us.\n\n"
#         )

#         print(f"Sending email to: {email}\nContent: {msg.body}")

#         # ✅ Send Email Using Flask-Mail & Backup SMTP
        
#         try:
#             mail.send(msg)  # Using Flask-Mail
#         except Exception as e:
#             send_email(email,otp)  # Backup SMTP
#             print(f"Error sending email using Flask-Mail.Using Backup send_email to send email: {e}")

#         print("✅ Email sent successfully.")
#         return jsonify({"message": "Sign-up link sent successfully"}), 200

#     except Exception as e:
#         print(f"❌ Error sending email: {e}")
#         return jsonify({"message": f"Error occurred: {str(e)}"}), 500

