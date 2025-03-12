from src.utils.aws_config import *
import json
# Using AWS and Local Storage :

from botocore.exceptions import NoCredentialsError, PartialCredentialsError


def load_from_local(filepath):
    try:
        if not os.path.exists(filepath):
            return None
        with open(filepath, 'r') as file:
            return json.load(file)
    except Exception as e:
        print(f"Error loading file: {e}")
        return None
 
def save_to_local(data, filepath):
    try:
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, 'w') as file:
            json.dump(data, file)
        print(f"Data saved at {filepath}")  # Debug log
    except Exception as e:
        print(f"Error saving file: {e}")  # Debug log
        raise
 
def delete_from_local(filename):
    file_path = os.path.join(LOCAL_STORAGE_PATH, filename)
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
            print(f"File {filename} deleted from local storage.")  # Debug log
        else:
            print(f"File {filename} not found in local storage.")  # Debug log
    except Exception as e:
        print(f"Error deleting file: {e}")  # Debug log
        raise
 
def save_to_aws(data, filename):
    try:
        s3.put_object(
            Bucket=S3_BUCKET_NAME,
            Key=filename,
            Body=json.dumps(data),
            ContentType='application/json'
        )
        print(f"Data saved to AWS at {filename}")
    except (NoCredentialsError, PartialCredentialsError) as e:
        print(f"AWS credentials error: {e}")
        raise
    except Exception as e:
        print(f"Error saving to AWS: {e}")
        raise
 
def load_from_aws(filename):
    try:
        obj = s3.get_object(Bucket=S3_BUCKET_NAME, Key=filename)
        return json.loads(obj['Body'].read().decode('utf-8'))
    except s3.exceptions.NoSuchKey:
        return None
    except Exception as e:
        print(f"Error loading from AWS: {e}")
        return None
 
def save_user_data(data, email):
    # Ensure that role and organization are part of data
    if "role" not in data:
        data["role"] = "user"  # default role
    if "organization" not in data:
        data["organization"] = ""
        
    if USE_AWS:
        # Store in AWS under 'signUp_user_folder/<email>.json'
        filename = f"{signUp_user_folder}{email}.json"
        save_to_aws(data, filename)
    else:
        # Store locally under 'users/<email>.json'
        filename = os.path.join(LOCAL_STORAGE_PATH, f"users/{email}.json")
        save_to_local(data, filename)
 
def load_user_data(email):
    if USE_AWS:
        filename = f"{signUp_user_folder}{email}.json"
        return load_from_aws(filename) or {} # Fixed returning None
    else:
        filename = f"users/{email}.json"
        return load_from_local(os.path.join(LOCAL_STORAGE_PATH, filename)) or {} # Fixed returning None
 
def delete_user_data(email):
    if USE_AWS:
        try:
            filename = f"{signUp_user_folder}{email}.json"
            s3.delete_object(Bucket=S3_BUCKET_NAME, Key=filename)
            print(f"File {filename} deleted from AWS.")  # Debug log
        except Exception as e:
            print(f"Error deleting file from AWS: {e}")  # Debug log
            raise
    else:
        filename = f"users/{email}.json"
        delete_from_local(filename)
        
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