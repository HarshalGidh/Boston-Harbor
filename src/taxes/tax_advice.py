import json
import os
import requests
from src.utils.aws_config import *
from src.utils.app_config import *
from src.utils.model_config import *
from src.utils.formatting import *
from flask import Flask, request, jsonify, session

app.secret_key = os.getenv('FLASK_SECRET_KEY', 'supersecretkey')

# AWS S3 Configuration
# S3_BUCKET_NAME = os.getenv('S3_BUCKET_NAME')
tax_assessment_folder = os.getenv('tax_assessment_folder')
TAX_QUESTIONS_KEY = f"{tax_assessment_folder}/tax_questions.json"

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

#################################################################################

# Taxes Calculations 

# Sample tax rates : Static :
# Default tax rates (fallback if online search fails)
DEFAULT_TAX_RATES = {
    "Employment": 0.3,         # 30% tax on employment income
    "Capital Gains": 0.15,     # 15% tax on investment gains
    "Real Estate": 0.25,       # 25% property tax on real estate
    "Business": 0.2,           # 20% tax on business income
    "Other Assets": 0.1,       # 10% tax on miscellaneous assets
    "Liabilities": 0.05        # 5% tax on loan interests
}

# Dynaminc Approach Needs API key :
# Function to dynamically fetch the latest tax rates

def get_latest_tax_rates():
    """
    Fetch the latest tax rates using DuckDuckGo API.
    Returns default tax rates if DuckDuckGo fails.
    """
    print("🔍 Using method: DuckDuckGo...")
    return search_duckduckgo_tax_rates()

def search_duckduckgo_tax_rates():
    """
    Fetches tax rates using DuckDuckGo Instant Answer API.
    Returns default tax rates if DuckDuckGo fails.
    """
    query = "latest income tax rates in USA 2024 site:irs.gov"
    url = f"https://api.duckduckgo.com/?q={query}&format=json"

    try:
        response = requests.get(url)
        
        if response.status_code == 200:
            results = response.json()
            abstract_text = results.get("AbstractText", "").strip()
            
            if abstract_text:
                print(f"🔍 Found on DuckDuckGo: {abstract_text}")
                return DEFAULT_TAX_RATES  # Replace with extracted values if applicable

        print("⚠️ DuckDuckGo API failed or returned no useful results.")
    
    except Exception as e:
        print(f"❌ Error fetching tax rates from DuckDuckGo: {e}")
    
    print("⚠️ Falling back to default tax rates.")
    return DEFAULT_TAX_RATES  # Final fallback

# Load tax rates (Fetch latest or use default)
TAX_RATES = get_latest_tax_rates()


def calculate_taxes(user_responses, client_data):
    """
    Calculate total taxes based on user's chatbot responses and financial data.
    
    :param user_responses: Dictionary of user-provided responses from chatbot
    :param client_data: Dictionary containing client's financial data
    :return: Dictionary with total tax amount and detailed breakdown
    """
    total_taxes = 0
    tax_details = {}

    # 🔹 **Step 1: Tax on Income**
    income_sources = client_data.get("incomeFields", [])
    for income in income_sources:
        source = income.get("sourceIncome", "Other")  # Default to "Other" if not found
        income_amount = float(income.get("amountIncome", "0") or 0)
        tax_rate = TAX_RATES.get(source, DEFAULT_TAX_RATES.get(source, 0.3))  # Get rate dynamically

        income_tax = income_amount * tax_rate
        tax_details[f"Income Tax - {source}"] = income_tax
        total_taxes += income_tax

    # 🔹 **Step 2: Tax on Assets**
    assets = client_data.get("assetsLiabilities", {})
    for key, asset in assets.items():
        asset_value = float(asset.get("currentLibKb", "0") or 0)
        asset_name = asset.get("assetsName", "Other Assets")

        if "Home" in asset_name or "Real Estate" in asset_name:
            tax_rate = TAX_RATES["Real Estate"]
        elif "Business" in asset_name:
            tax_rate = TAX_RATES["Business"]
        else:
            tax_rate = TAX_RATES["Other Assets"]

        asset_tax = asset_value * tax_rate
        tax_details[f"Asset Tax - {asset_name}"] = asset_tax
        total_taxes += asset_tax

    # 🔹 **Step 3: Tax on Liabilities**
    liabilities = client_data.get("myLiabilities", {})
    for key, liability in liabilities.items():
        interest_rate = float(liability.get("mortgageInterest", "0") or 0) / 100
        loan_balance = float(liability.get("mortgageBalance", "0") or 0)
        interest_tax = loan_balance * interest_rate * TAX_RATES["Liabilities"]

        liability_name = liability.get("liabilityName", "Loan Interest")
        tax_details[f"Loan Interest Tax - {liability_name}"] = interest_tax
        total_taxes += interest_tax

    return {"total_taxes": total_taxes, "tax_breakdown": tax_details}

# Example Usage:
# tax_result = calculate_taxes(user_responses, client_data)
# print(json.dumps(tax_result, indent=4))




#################################################################################


# Function to generate tax-saving suggestions
def generate_tax_suggestions(user_responses):
    prompt = f"Given the following user financial data, suggest tax-saving strategies:\n{json.dumps(user_responses, indent=4)}"
    
    response = model.generate_content(prompt)
    
    # Process the response from LLM
    html_suggestions = markdown.markdown(response.text)
    format_suggestions = markdown_to_text(html_suggestions)
    
    return format_suggestions if response else "No suggestions available."



@app.route('/api/start-tax-chatbot', methods=['POST'])
def start_chatbot():
    session['chat_index'] = 0
    session['user_responses'] = {}
    return jsonify({"message": tax_questions[0], "question_index": 0}), 200

@app.route('/api/tax-chatbot', methods=['POST'])
def tax_chatbot():
    if 'chat_index' not in session or 'user_responses' not in session:
        return jsonify({"message": "Chatbot session not started. Use /api/start-tax-chatbot first."}), 400
    
    answer = request.get_json('answer')
    is_assessment_completed = False
    # Check for None Answers :
    if not answer:
        return jsonify({"message": "Missing answer field."}), 400
    
    question_index = session['chat_index']
    session['user_responses'][tax_questions[question_index]] = answer
    session['chat_index'] += 1
    
    # When Questions are Pending :
    if session['chat_index'] < len(tax_questions):
        return jsonify({"message": tax_questions[session['chat_index']],
                        "question_index": session['chat_index'],
                        "is_assessment_completed" : is_assessment_completed}), 200
    
    # When Assessment is Completed :
    else:
        tax_result = calculate_taxes(session['user_responses'])
        tax_advice = generate_tax_suggestions(session['user_responses'])
        is_assessment_completed = True
        session.clear()
        return jsonify({"message": "Assessment completed.",
                        "is_assessment_completed":is_assessment_completed ,
                        "tax_details": tax_result, 
                        "suggestions": tax_advice}), 200



