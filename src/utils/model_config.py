import os
import google.generativeai as genai

GOOGLE_API_KEY = os.getenv('GOOGLE_API_KEY')

# Configure generativeai with your API key
genai.configure(api_key=GOOGLE_API_KEY)

# Initialize the model :
model = genai.GenerativeModel("gemini-1.5-flash")