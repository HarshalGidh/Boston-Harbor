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
    
def send_email(to_email, otp):
    try:
        print(f"to_email{to_email}")
        # Validate email format
        if not re.match(r"[^@]+@[^@]+\.[^@]+", to_email):
            print(f"Invalid email address: {to_email}")
            return False
 
        # Setup email message
        subject = "Your Reset Password Code"
        message = f"Your Reset Password Code is: {otp}"
        msg = MIMEMultipart()
        msg['From'] = EMAIL_ADDRESS
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(message, 'plain'))
 
        # Send email using SMTP
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.sendmail(EMAIL_ADDRESS, to_email, msg.as_string())
        print("Email sent successfully")
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False