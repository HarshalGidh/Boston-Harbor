import os
import boto3

# # AWS keys
aws_access_key = os.getenv('aws_access_key')
aws_secret_key = os.getenv('aws_secret_key')
S3_BUCKET_NAME = os.getenv('S3_BUCKET_NAME')
client_summary_folder = os.getenv('client_summary_folder') 
suggestions_folder = os.getenv('suggestions_folder') 
order_list_folder = os.getenv('order_list_folder')
portfolio_list_folder = os.getenv('portfolio_list_folder') 
personality_assessment_folder = os.getenv('personality_assessment_folder') 
login_folder = os.getenv('login_folder')
daily_changes_folder = os.getenv('daily_changes_folder')
signUp_user_folder = os.getenv('signUp_user_folder')
PREDICTIONS_FOLDER = os.getenv('PREDICTIONS_FOLDER')
tax_assessment_folder = os.getenv('tax_assessment_folder')
TAX_QUESTIONS_KEY = f"{tax_assessment_folder}/tax_questions.json"

# Connecting to Amazon S3
s3 = boto3.client(
    's3',
    aws_access_key_id=aws_access_key,
    aws_secret_access_key=aws_secret_key
)

def list_s3_keys(bucket_name, prefix=""):
    try:
        # List objects in the bucket with the given prefix
        response = s3.list_objects_v2(Bucket=bucket_name, Prefix=prefix)
        if 'Contents' in response:
            print("Keys in the S3 folder:")
            for obj in response['Contents']:
                print(obj['Key'])
        else:
            print("No files found in the specified folder.")
    except Exception as e:
        print(f"Error listing objects in S3: {e}")
        
USE_AWS = True # Set to False to use local storage

LOCAL_STORAGE_PATH = os.getenv('LOCAL_STORAGE_PATH')
