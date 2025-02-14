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
chat_history_folder = os.getenv("chat_history_folder")
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

# Call the function
# list_s3_keys(S3_BUCKET_NAME, signUp_user_folder) 
# list_s3_keys(S3_BUCKET_NAME, client_summary_folder) 
# list_s3_keys(S3_BUCKET_NAME, order_list_folder) 
# list_s3_keys(S3_BUCKET_NAME, portfolio_list_folder) 


####################################################################################

# Download the files :

# def download_json_file(bucket_name, file_key, local_file_path):
#     """
#     Downloads a JSON file from an S3 bucket to a local file.

#     :param bucket_name: Name of the S3 bucket
#     :param file_key: Key (path) of the file in the bucket
#     :param local_file_path: Path to save the file locally
#     """
#     try:
#         # Download the file
#         s3.download_file(bucket_name, file_key, local_file_path)
#         print(f"File '{file_key}' successfully downloaded to '{local_file_path}'.")
        
#         # Load the JSON content to confirm it's valid
#         with open(local_file_path, 'r') as file:
#             data = json.load(file)
#             print("Downloaded JSON content:", data)
#         return data
    
#     except Exception as e:
#         print(f"Error downloading file: {e}")
#         return None

# # Example usage 
# local_file_path = "local_data\orders\orders_SF3648.json"
# downloaded_data = download_json_file(S3_BUCKET_NAME,"order_list_folder/SF3648_orders.json", local_file_path)

# downloaded_data = download_json_file(S3_BUCKET_NAME, "portfolio_list_folder//SF3648.json", local_file_path)

# print(downloaded_data)

######################################################################################

# Upload File :

# def upload_json_file(bucket_name, file_key, local_file_path):
#     """
#     Uploads a JSON file from the local file system to an S3 bucket.

#     :param bucket_name: Name of the S3 bucket
#     :param file_key: Key (path) to upload the file to in the bucket
#     :param local_file_path: Path of the file locally to be uploaded
#     """
#     try:
#         # Upload the file
#         s3.upload_file(local_file_path, bucket_name, file_key, ExtraArgs={'ContentType': 'application/json'})
#         print(f"File '{local_file_path}' successfully uploaded to '{file_key}' in bucket '{bucket_name}'.")
    
#     except Exception as e:
#         print(f"Error uploading file: {e}")

# # Example usage
# local_file_path = "local_data\portfolios\portfolio_SF3648.json"
# upload_json_file(S3_BUCKET_NAME, "portfolio_list_folder//SF3648.json", local_file_path)

# local_file_path = "local_data\orders\orders_SF3648.json"
# upload_json_file(S3_BUCKET_NAME, "order_list_folder/SF3648_orders.json", local_file_path)

# list_s3_keys(S3_BUCKET_NAME, order_list_folder) 


######################################################################################


# delete folders/files from bucket :



# S3 bucket and file details

# FILE_KEY = "order_list_folder/JM4162_orders.json"
# FILE_KEY = "order_list_folder/JR5059_orders.json"
# FILE_KEY = "portfolio_list_folder//JM4162.json"
# FILE_KEY = "portfolio_list_folder//JR5059.json"
# FILE_KEY = "portfolio_list_folder//KK3893.json"
# FILE_KEY = "portfolio_list_folder//JL5407.json"


# FILE_KEY = "order_list_folder/KK3893_orders.json" 
# FILE_KEY = "order_list_folder/J9488_orders.json" 
# FILE_KEY = "order_list_folder/JL5407_orders.json" 

# FILE_KEY = "order_list_folder/SF3648_orders.json" 
# list_s3_keys(S3_BUCKET_NAME, client_summary_folder) 
# FILE_KEY = "client_summary_folder/client-data/CM5657.json"
# FILE_KEY = "client_summary_folder/client-data/JL5407.json"

# FILE_KEY = "client_summary_folder/client-data/J9488.json"
# FILE_KEY = "client_summary_folder/client-data/KK3893.json"


# def delete_file_from_s3(bucket_name, file_key):
#     """
#     Deletes a specified file from an S3 bucket.

#     :param bucket_name: Name of the S3 bucket
#     :param file_key: Key (path) of the file in the bucket
#     """
#     try:
#         # Delete the file
#         response = s3.delete_object(Bucket=bucket_name, Key=file_key)
        
#         # Confirm deletion
#         if response.get('ResponseMetadata', {}).get('HTTPStatusCode') == 204:
#             print(f"File '{file_key}' successfully deleted from bucket '{bucket_name}'.")
#         else:
#             print(f"Failed to delete file '{file_key}' from bucket '{bucket_name}'.")
    
#     except Exception as e:
#         print(f"Error deleting file: {e}")

# # Call the function
# delete_file_from_s3(S3_BUCKET_NAME, FILE_KEY)


# list_s3_keys(S3_BUCKET_NAME, client_summary_folder) 
# #list_s3_keys(S3_BUCKET_NAME, portfolio_list_folder) 
# list_s3_keys(S3_BUCKET_NAME, portfolio_list_folder) 
# list_s3_keys(S3_BUCKET_NAME, order_list_folder) 



# =------------------------------------------------------=

