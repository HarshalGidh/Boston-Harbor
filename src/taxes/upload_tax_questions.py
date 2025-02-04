from src.utils.aws_config import *
import json

# Updated Tax Questions
tax_questions = {
    "questions": [
        "What is your primary source of income?",
        "What is your total annual taxable income?",
        "Which state do you reside in?",
        "Do you have any dependents?",
        "What tax deductions or exemptions are you eligible for?",
        "Do you own any real estate properties?",
        "Are you self-employed or a small business owner?",
        "Do you have medical expenses exceeding a certain percentage of your income?",
        "Do you contribute to a charity or nonprofit organization?",
        "Have you made any large one-time purchases in the past year?"
    ]
}

# Function to upload tax questions to S3
def upload_tax_questions_to_s3():
    try:
        s3.put_object(
            Bucket=S3_BUCKET_NAME,
            Key=TAX_QUESTIONS_KEY,
            Body=json.dumps(tax_questions, indent=4),
            ContentType="application/json"
        )
        print("✅ Tax questions uploaded successfully to S3.")
    except Exception as e:
        print(f"❌ Error uploading tax questions: {e}")

# Function to retrieve tax questions from S3
def get_tax_questions_from_s3():
    try:
        response = s3.get_object(Bucket=S3_BUCKET_NAME, Key=TAX_QUESTIONS_KEY)
        return json.loads(response["Body"].read().decode("utf-8"))
    except Exception as e:
        print(f"❌ Error retrieving tax questions: {e}")
        return None


# Example Usage:
# upload_tax_questions_to_s3()
# questions = get_tax_questions_from_s3()