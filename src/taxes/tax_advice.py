import json
import os
import requests
from src.utils.aws_config import *
from src.utils.app_config import *
from src.utils.model_config import *
from src.utils.formatting import *
from flask import Flask, request, jsonify, session
import logging

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
from urllib.parse import urlparse, parse_qs, unquote
from bs4 import BeautifulSoup

# working code :

def extract_tax_rates(text):
    tax_rates = DEFAULT_TAX_RATES.copy()
    patterns = {
        "Employment": r"(?:Federal Income Tax Rates|Taxable Income).*?(\d{1,2}\.?\d*)%",
        "Capital Gains": r"(Capital\s+Gains|Investments).*?(\d{1,2}\.?\d*)%",
        "Real Estate": r"(Real\s+Estate|Property).*?(\d{1,2}\.?\d*)%",
        "Business": r"(Business Income|Self-Employment).*?(\d{1,2}\.?\d*)%",
        "Other Assets": r"(Other\s+Assets|Miscellaneous).*?(\d{1,2}\.?\d*)%",
        "Liabilities": r"(Loan\s+Interest|Debt).*?(\d{1,2}\.?\d*)%",
    }
    
    # First try to find tables with tax rates
    tables = re.findall(r"<table.*?>(.*?)</table>", text, re.DOTALL | re.IGNORECASE)
    for table in tables:
        matches = re.findall(r">(\d{1,2}\.?\d*)%<", table)
        if matches:
            try:
                tax_rates["Employment"] = max(tax_rates["Employment"], float(matches[0])/100)
            except:
                pass

    # Then try pattern matching
    for category, pattern in patterns.items():
        matches = re.findall(pattern, text, re.IGNORECASE | re.DOTALL)
        if matches:
            try:
                # Take the highest rate found for each category
                rates = [float(m[-1])/100 for m in matches if m]
                if rates:
                    tax_rates[category] = max(rates)
            except (ValueError, IndexError) as e:
                continue

    return tax_rates

def get_irs_url():
    FALLBACK_URL = "https://www.irs.gov/filing/federal-income-tax-rates-and-brackets"
    
    try:
        # Try DuckDuckGo search first
        query = "IRS tax rates 2024 site:irs.gov"
        search_url = f"https://html.duckduckgo.com/html/?q={query.replace(' ', '+')}"
        
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Accept-Language": "en-US,en;q=0.9",
        }
        
        response = requests.get(search_url, headers=headers, timeout=10)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, "html.parser")
        results = soup.find_all("a", class_="result__url")
        
        for result in results:
            url = result.get("href", "")
            if "irs.gov" in url:
                # Handle DuckDuckGo redirects
                if url.startswith("/l/"):
                    parsed = urlparse(url)
                    uddg = parse_qs(parsed.query).get("uddg", [""])[0]
                    if uddg:
                        return unquote(uddg)
                return url

    except Exception as e:
        print(f"Search failed: {e}")

    # Fallback to direct URL
    print("Using fallback IRS URL")
    return FALLBACK_URL

def fetch_tax_rates():
    url = get_irs_url()
    print(f"Fetching from: {url}")
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }

    try:
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        
        # Clean up HTML
        soup = BeautifulSoup(response.text, "html.parser")
        for script in soup(["script", "style", "nav", "footer"]):
            script.decompose()
            
        return extract_tax_rates(soup.get_text(separator=" ", strip=True))
    
    except Exception as e:
        print(f"Fetch failed: {e}")
        return DEFAULT_TAX_RATES

def get_latest_tax_rates():
    print("Fetching latest tax rates...")
    rates = fetch_tax_rates()
    print("Successfully retrieved rates" if rates != DEFAULT_TAX_RATES else "Using default rates")
    return rates

def calculate_taxes(user_responses, client_id,TAX_RATES):
    """
    Calculate total taxes based on user's chatbot responses and financial data.
   
    :param user_responses: Dictionary of user-provided responses from chatbot
    :param client_id: Client's unique identifier
    :return: Dictionary with total tax amount and detailed breakdown
    """
    total_taxes = 0
    tax_details = {}
 
    # 🔹 Load client financial data (from AWS or local based on USE_AWS)
    client_data = None  # Initialize to avoid reference errors
 
    if USE_AWS:
        client_data_key = f"{client_summary_folder}client-data/{client_id}.json"
        try:
            response = s3.get_object(Bucket=S3_BUCKET_NAME, Key=client_data_key)
            client_data = json.loads(response['Body'].read().decode('utf-8'))
        except Exception as e:
            logging.error(f"Error occurred while retrieving client data from AWS: {e}")
            return {"error": f"Error retrieving client data from AWS: {str(e)}"}
    else:
        client_data_file_path = os.path.join("client_data", "client_data", f"{client_id}.json")
        if not os.path.exists(client_data_file_path):
            return {"error": f"No client data found for client ID: {client_id}"}
 
        try:
            with open(client_data_file_path, 'r') as f:
                client_data = json.load(f)
        except Exception as e:
            logging.error(f"Error loading local client data: {e}")
            return {"error": f"Failed to load client data: {str(e)}"}
 
    if not client_data:
        return {"error": "Client data could not be retrieved."}
 
    # 🔹 **Step 1: Tax on Income**
    income_sources = client_data.get("incomeFields", [])
    for income in income_sources:
        source = income.get("sourceIncome", "Other")
        income_amount = float(income.get("amountIncome", 0) or 0)  # Ensure numeric conversion
        tax_rate = TAX_RATES.get(source, DEFAULT_TAX_RATES.get(source, 0.3))  # Use fallback rate
 
        income_tax = income_amount * tax_rate
        tax_details[f"Income Tax - {source}"] = income_tax
        total_taxes += income_tax
 
    # 🔹 **Step 2: Tax on Assets**
    assets = client_data.get("assetsLiabilities", {})
    for asset in assets.values():  # Use `.values()` to avoid key errors
        asset_value = float(asset.get("currentLibKb", 0) or 0)
        asset_name = asset.get("assetsName", "Other Assets")
 
        if "Home" in asset_name or "Real Estate" in asset_name:
            tax_rate = TAX_RATES.get("Real Estate", 0.2)  # Default rate fallback
        elif "Business" in asset_name:
            tax_rate = TAX_RATES.get("Business", 0.25)
        else:
            tax_rate = TAX_RATES.get("Other Assets", 0.15)
 
        asset_tax = asset_value * tax_rate
        tax_details[f"Asset Tax - {asset_name}"] = asset_tax
        total_taxes += asset_tax
 
    # 🔹 **Step 3: Tax on Liabilities**
    liabilities = client_data.get("myLiabilities", {})
    for liability in liabilities.values():  # Use `.values()` to avoid key errors
        interest_rate = float(liability.get("mortgageInterest", 0) or 0) / 100  # Convert % to decimal
        loan_balance = float(liability.get("mortgageBalance", 0) or 0)
        interest_tax = loan_balance * interest_rate * TAX_RATES.get("Liabilities", 0.05)
 
        liability_name = liability.get("liabilityName", "Loan Interest")
        tax_details[f"Loan Interest Tax - {liability_name}"] = interest_tax
        total_taxes += interest_tax
 
    return {"total_taxes": round(total_taxes, 2), "tax_breakdown": tax_details}


# from groq import Groq  # For fast inference
from phi.agent import Agent  # For structured reasoning
from phi.agent import Agent, AgentMemory
from phi.model.groq import Groq
from phi.tools.yfinance import YFinanceTools
from phi.tools.duckduckgo import DuckDuckGo

from phi.agent import Agent, RunResponse
from phi.model.google import Gemini

# Initialize Groq client
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
groq_client = Groq(api_key=GROQ_API_KEY)

# Set Google API Key
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")

# setx GROQ_API_KEY # # set it up manually in cmd

# Initialize Phi agent
phi_agent = Agent()

# web search for the current tax rates :
web_search_agent = Agent(
    name="Web Search Agent",
    role="Search Web for Current US Tax Rates",
    # model=Groq(id="llama-3.3-70b-versatile"), # cant handle large tokens
    model=Gemini(id="gemini-1.5-flash",api_key=GOOGLE_API_KEY),
    tools = [DuckDuckGo(),],
    instructions = ["Always provide Sources"],
    show_tools_calls= True,
    markdown = True,
)

# calculate taxes on the assets invested in :
finance_agent = Agent(
    name="Finance Agent",
    role="Calculate the taxes on the given assets if in profits and based on the investment duration", 
    # model=Groq(id="llama-3.3-70b-versatile"), # cant handle large tokens
    model=Gemini(id="gemini-1.5-flash",api_key=GOOGLE_API_KEY),
    tools = [
        YFinanceTools(stock_price=True,analyst_recommendations=True,stock_fundamentals=True,
                      company_news=True,company_info=True,key_financial_ratios=True,
                      income_statements= True,technical_indicators=True,historical_prices=True),
        ],
    description = "Format your response using markdown and use tables to display data where possible.",
    instructions = ["Always provide Sources",
                    "Format your response using markdown and use tables to display data where possible."],
    show_tools_calls= True,
    markdown = True,
)

multi_ai_agent = Agent(
    # model=Groq(id="llama-3.3-70b-versatile"), # cant handle large tokens
    model=Gemini(id="gemini-1.5-flash",api_key=GOOGLE_API_KEY),
    team = [web_search_agent,finance_agent],
    instructions = ["Always provide Sources",
                    "Format your response using markdown and use tables to display data where possible."],
    description="You are a helpful assistant that always responds in a polite, upbeat and positive manner.",
    # num_history_responses=3,
    # memory = AgentMemory(
    #     create_user_memories=True,
    #     create_session_summary=True
    #     ),
    # add_chat_history_to_messages = True,
    show_tools_calls= True,
    markdown = True,
)

# Function to generate tax-saving suggestions using Multi-AI Agent
def generate_tax_suggestions(user_responses, client_id,TAX_RATES):
    """
    Generate tax-saving suggestions using the multi-ai-agent (Groq + Phi).
    """
    # Step 1: Load client financial data
    client_data = None
    if USE_AWS:
        client_data_key = f"{client_summary_folder}client-data/{client_id}.json"
        try:
            response = s3.get_object(Bucket=S3_BUCKET_NAME, Key=client_data_key)
            client_data = json.loads(response['Body'].read().decode('utf-8'))
        except Exception as e:
            logging.error(f"Error retrieving client data from AWS: {e}")
            return {"error": f"Error retrieving client data from AWS: {str(e)}"}
    else:
        client_data_file_path = os.path.join("client_data", "client_data", f"{client_id}.json")
        if not os.path.exists(client_data_file_path):
            return {"error": f"No client data found for client ID: {client_id}"}

        try:
            with open(client_data_file_path, 'r') as f:
                client_data = json.load(f)
        except Exception as e:
            logging.error(f"Error loading local client data: {e}")
            return {"error": f"Failed to load client data: {str(e)}"}

    if not client_data:
        return {"error": "Client data could not be retrieved."}
    
    # 🔹 **Step 2: Load Portfolio Data**
    portfolio_data = None
    if USE_AWS:
        portfolio_key = f"{portfolio_list_folder}/{client_id}.json"
        try:
            response = s3.get_object(Bucket=S3_BUCKET_NAME, Key=portfolio_key)
            portfolio_data = json.loads(response['Body'].read().decode('utf-8'))
        except s3.exceptions.NoSuchKey:
            logging.warning(f"Portfolio file not found for client ID: {client_id}")
            portfolio_data = "No investments made"
    else:
        portfolio_file_path = os.path.join("portfolio_data", f"portfolio_{client_id}.json")
        if os.path.exists(portfolio_file_path):
            with open(portfolio_file_path, 'r') as file:
                portfolio_data = json.load(file)
        else:
            logging.warning(f"Portfolio file not found for client ID: {client_id}")
            portfolio_data = "No investments made"

    # Step 2: Prepare input for Multi-AI Agent
    input_data = {
        "user_responses": user_responses,
        "client_data": client_data,
        "tax_rates": TAX_RATES,
        "portfolio_data": portfolio_data
    }

    # Step 3: Use Multi-AI Agent for Tax Optimization
    # response = multi_ai_agent.print_response(
    #     f"""
    #     Based on the following financial data, tax rates, and user responses,
    #     generate **actionable tax-saving strategies**:
        
    #     ```json
    #     {json.dumps(input_data, indent=4)}
    #     ```
        
    #     - Consider state-specific tax regulations.
    #     - Identify possible deductions or exemptions.
    #     - Suggest optimal investment strategies for tax efficiency.
    #     - Provide structured, markdown-formatted output.
    #     """
    # )
    
    print(input_data)
    # Step 3: Use Multi-AI Agent for Tax Optimization
    try:
        response = multi_ai_agent.run(
             message=f"""
                        Based on the available financial data:
                        - **Annual Income:** {client_data.get('income', 'N/A')}
                        - **Tax Bracket:** {TAX_RATES}
                        - **Investment Portfolio:** {portfolio_data}
                        - **Real Estate Holdings:** {client_data.get('real_estate', 'N/A')}
                        - **Business Details:** {client_data.get('business', 'N/A')}

                        Generate **a structured tax-saving strategy** that includes:

                        1. **Investment Strategies for Tax Efficiency**
                            - Tax-advantaged accounts (401(k), IRA, etc.).
                            - Tax-efficient investing strategies.

                        2. **Deductions, Exemptions, and Credits**
                            - Identify applicable federal and Texas-specific deductions.
                            - Highlight key tax credits that reduce liability.

                        3. **State-Specific Tax Optimizations (Texas)**
                            - Considerations based on local tax laws.

                        4. **Tax-Loss Harvesting Opportunities**
                            - Evaluate the investment portfolio for capital gains offsets.

                        **Ensure the response is structured in markdown format with tables where applicable.**  
                        - Do not request additional user input.  
                        - Do not use first-person language.  
                        - Do not mention AI agents or task delegation.  
                        """,
            messages=[input_data], 
            stream=False  # Ensure it's not streamed, so we can capture it
        )

        # Extract response content safely
        if isinstance(response, RunResponse) and hasattr(response, "content"):
            response_text = response.content  # Extracting the actual response text
        else:
            response_text = "Error: Unexpected AI response format."

        # Process the response from LLM
        response_text = markdown.markdown(response_text, extensions=["extra"]) # html_suggestions # best o/p so far
        # response_text = markdown_to_text(html_suggestions) # format_suggestions
        
        # markdown_parser = mistune.create_markdown(renderer=mistune.HTMLRenderer())
        # response_text = markdown_parser(response_text)

    except Exception as e:
        logging.error(f"Error during AI processing: {e}")
        response_text = f"Error: {str(e)}"
        
    # Step 4: Extract meaningful response
      # 🔹 **Extract response content correctly**
        if isinstance(response, RunResponse):
            response_text = getattr(response, "content", None)  # Extract content safely
            if response_text is None:
                response_text = "Error: No content received from AI."
        else:
            response_text = str(response)  # Convert any unexpected response to string

    except Exception as e:
        logging.error(f"Error during AI processing: {e}")
        response_text = f"Error: {str(e)}"
    
     # Step 4: Save Response to a File
    output_file = f"tax_suggestions_{client_id}.txt"
    os.makedirs("output", exist_ok=True)
    try:
        with open(output_file, "w", encoding="utf-8") as file:
            file.write(response_text)  # Write extracted response text
    except Exception as e:
        logging.error(f"Error saving response to file: {e}")
    
    print("Response successfully stored at:", output_file)
    
    return response_text


# aws folder for taxes assessment :

tax_assessment_folder = os.getenv('tax_assessment_folder')  # Folder in S3

# Local storage fallback
LOCAL_SAVE_DIR = "local_tax_assessments"

def save_user_responses(client_id,user_responses,question_index=0):
    """
    Save user responses as a JSON file in AWS S3 or locally.
    """
    try:
    # Define the filename
        responses_key = f"{tax_assessment_folder}/{client_id}_user_responses.json"
        
        if USE_AWS:
            responses_json = json.dumps(user_responses,indent=4)
            print(f"Response json: {responses_json}\n")
            
            # Upload to S3
            s3.put_object(
                Bucket=S3_BUCKET_NAME,
                Key=responses_key,
                Body=responses_json,
                ContentType='application/json'
            )
            print(f"Saved {question_index} user responses for client_id: {client_id} in AWS S3.")
            logging.info(f"Saved {question_index} user responses for client_id: {client_id} in AWS S3.")
            return f"Saved {question_index} user responses for client_id: {client_id} in AWS S3."
        
        else:
                # Ensure local directory exists
                os.makedirs(LOCAL_SAVE_DIR, exist_ok=True)

                # Save locally
                local_file_path = os.path.join(LOCAL_SAVE_DIR, f"{client_id}_user_responses.json")
                with open(local_file_path, 'w') as file:
                    json.dump(responses_json, file, indent=4)
                
                logging.info(f"Saved user responses for client_id: {client_id} locally.")
                return f"Saved user responses for client_id: {client_id} "
        
    except Exception as e:
        print(f"Error saving user responses : {e}")
        logging.error(f"Error saving user responses : {e}")
        return f"Error saving user responses : {e}"
    

def save_tax_suggestions(client_id,tax_details, tax_suggestions): #,revisit_assessment_count):
   
    # Define the filename
    tax_data = {
        "tax_suggestions": tax_suggestions,
        "tax_details": tax_details
    }
    
    # tax_data = {
    #     "tax_suggestions": tax_suggestions,
    #     "tax_details": tax_details,
    #     "revisit_assessment_count":revisit_assessment_count
    # }
    suggestions_key = f"{tax_assessment_folder}/{client_id}_tax_suggestions.json"

    try:
        if USE_AWS:
            # Convert tax suggestions to JSON
            suggestions_json = json.dumps(tax_data, indent=4)
            print(f"Suggestions json: {suggestions_json}\n")

            # Upload to S3
            s3.put_object(
                Bucket=S3_BUCKET_NAME,
                Key=suggestions_key,
                Body=suggestions_json,
                ContentType='application/json'
            )
            logging.info(f"Saved tax suggestions for client_id: {client_id} in AWS S3.")
            print(f"Saved tax suggestions for client_id: {client_id} in AWS S3.")
            return f"Saved tax suggestions for client_id: {client_id} in AWS S3."
        
        else:
            # Ensure local directory exists
            os.makedirs(LOCAL_SAVE_DIR, exist_ok=True)

            # Save locally
            local_file_path = os.path.join(LOCAL_SAVE_DIR, f"{client_id}_tax_suggestions.json")
            with open(local_file_path, 'w') as file:
                json.dump(tax_data, file, indent=4)
            
            logging.info(f"Saved tax suggestions for client_id: {client_id} locally.")
            return f"Saved tax suggestions for client_id: {client_id} "

    except Exception as e:
        print(f"Error saving tax suggestions: {e}")
        logging.error(f"Error saving tax suggestions: {e}")
        return f"Error saving tax suggestions: {e}"

tax_questions = [
     "What is your Primary Source of Income?",
     "What is your Total Annual Taxable Income?",
     "Which state do you Reside In?",
     "Do you have any Dependents?",
     "What Tax Deductions or Exemptions are you Eligible for?",
     "What is the Approximate Net Capital Value of All of your Real Estate Properties?",
     "State the Total Investments that you have done",
     "Do you have Medical Expenses exceeding a certain Percentage of your Income?",
     "Do you contribute to a Charity or Nonprofit Organization?",
     "Have you made any Large One-Time Purchases in the Past Year?",
]

# previous working system however it didnt saved sessions :

@app.route('/api/start-tax-chatbot', methods=['POST'])
def start_chatbot():
    """
    Starts the tax assessment chatbot by returning the first question.
    """
    try:
        if not tax_questions:
            return jsonify({"message": "No tax questions available"}), 500
        
        print("Starting tax assessment chatbot...")
        print(tax_questions)
        return jsonify({"message": "Tax Questions Passed successfully",
                        "tax_questions": tax_questions}),200
        # first_question = tax_questions["questions"][0]  # Access list inside dictionary
        # return jsonify({"message": first_question, "question_index": 0}), 200

    except Exception as e:
        print(f"❌ Error in chatbot start: {e}")
        return jsonify({"message": f"Internal server error: {str(e)}"}), 500

# #generate tax suggestions :

@app.route('/api/generate-tax-suggestions', methods=['POST']) 
def generate_tax_suggestions():
    try:
        # 🔹 Extract the user's answer from the request
        data = request.json.get('data')
 
        if isinstance(data, list) and all(isinstance(item, dict) for item in data):
            questions = [item.get('question', None) for item in data]
            answers = [item.get('answer', None) for item in data]
            # client_id = data.get('client_id', None)  # Extract from the first item (if applicable)
 
            print("Questions:", questions)
            print("Answers:", answers)
            
        else:
            return jsonify({"message": "Invalid data format"}), 400
 
        # 🔹 Validate that an answer was provided
        if not answers:
            return jsonify({"message": "Missing answers field."}), 400
        
    
        client_id = request.json.get('client_id', None)
        print("Client ID:", client_id)
        
        # Store User Responses : # need to map questions with the ans
        # user_responses = {
        #     "question": questions,
        #     "answer": answers
        # }
        
        # print("User Responses :", user_responses)
        print("User Responses :", data)
        
        save_user_responses(client_id, data)
        # save_user_responses(client_id, user_responses)
        
        # Get Tax Rates :
        TAX_RATES = get_latest_tax_rates()
        print("Final Tax Rates:", TAX_RATES)
        
        # Calculate Tax Details :
        tax_result = calculate_taxes(answers, client_id,TAX_RATES)
        print("Generating Tax Calculations :",tax_result)
        
        # Generate Tax Suggestions :
        tax_advice = generate_tax_suggestions(answers,client_id,TAX_RATES)
        print("Generating Tax Suggestions",tax_advice)
        
        # revisit_assessment_count['client_id'] += 1

        save_tax_suggestions(client_id, tax_result, tax_advice) #,revisit_assessment_count)
        # save_tax_suggestions(client_id, tax_result, tax_advicerevisit_assessment_count)
        
        return jsonify({
            "message": "Assessment completed.",
            # "revisit_assessment_count": revisit_assessment_count,
            "TAX_RATES": TAX_RATES,
            "tax_details": tax_result,
            "suggestions": tax_advice
        }), 200
 
    except Exception as e:
        print(f"❌ Error in chatbot: {e}")
        return jsonify({"message": f"Internal server error: {str(e)}"}), 500

# @app.route('/api/tax-chatbot', methods=['POST']) #generate-tax-suggestions
# def tax_chatbot():
#     """
#     Handles the tax chatbot interaction by storing user responses and returning the next question.
#     """
#     try:
#         # 🔹 Extract the user's answer from the request
#         data = request.json.get('data')
 
#         if isinstance(data, list) and all(isinstance(item, dict) for item in data):
#             questions = [item.get('question', None) for item in data]
#             answers = [item.get('answer', None) for item in data]
#             # client_id = data.get('client_id', None)  # Extract from the first item (if applicable)
 
#             print("Questions:", questions)
#             print("Answers:", answers)
            
#         else:
#             return jsonify({"message": "Invalid data format"}), 400
 
#         # 🔹 Validate that an answer was provided
#         if not answers:
#             return jsonify({"message": "Missing answers field."}), 400
        
    
#         client_id = request.json.get('client_id', None)
#         print("Client ID:", client_id)
        
#         # Store User Responses : # need to map questions with the ans
#         # user_responses = {
#         #     "question": questions,
#         #     "answer": answers
#         # }
        
#         # print("User Responses :", user_responses)
#         print("User Responses :", data)
        
#         save_user_responses(client_id, data)
#         # save_user_responses(client_id, user_responses)
        
#         # Get Tax Rates :
#         TAX_RATES = get_latest_tax_rates()
#         print("Final Tax Rates:", TAX_RATES)
        
#         # Calculate Tax Details :
#         tax_result = calculate_taxes(answers, client_id,TAX_RATES)
#         print("Generating Tax Calculations :",tax_result)
        
#         # Generate Tax Suggestions :
#         tax_advice = generate_tax_suggestions(answers,client_id,TAX_RATES)
#         print("Generating Tax Suggestions",tax_advice)
        
#         # revisit_assessment_count['client_id'] += 1

#         save_tax_suggestions(client_id, tax_result, tax_advice) #,revisit_assessment_count)
#         # save_tax_suggestions(client_id, tax_result, tax_advicerevisit_assessment_count)
        
#         return jsonify({
#             "message": "Assessment completed.",
#             # "revisit_assessment_count": revisit_assessment_count,
#             "TAX_RATES": TAX_RATES,
#             "tax_details": tax_result,
#             "suggestions": tax_advice
#         }), 200
 
#     except Exception as e:
#         print(f"❌ Error in chatbot: {e}")
#         return jsonify({"message": f"Internal server error: {str(e)}"}), 500
     
# retrive previous tax suggestions :

@app.route('/api/get-tax-suggestions', methods=['POST'])
def get_tax_suggestions():
    """
    Retrieves the tax suggestions for a given client_id.
    """
    try:
        client_id = request.json.get('client_id', None)
        print("Client ID:", client_id)
    
        suggestions_key = f"{tax_assessment_folder}/{client_id}_tax_suggestions.json"
    
        if USE_AWS:
            # Download from S3
            # s3 = boto3.client('s3')
            response = s3.get_object(Bucket=S3_BUCKET_NAME, Key=suggestions_key)
            suggestions_json = response['Body'].read().decode('utf-8')
            print("Retrieved tax suggestions data:", suggestions_json)
            return jsonify(json.loads(suggestions_json)),200
    
    except Exception as e:
        print(f"�� No tax suggestions found: {e}")
        return jsonify({"message": f"No tax suggestions found: {str(e)}"}), 404
    
# Get Previous user responses :

@app.route('/api/get-user-responses', methods=['POST'])
def get_user_responses():
    """
    Retrieves the user responses for a given client_id.
    """
    try:
        client_id = request.json.get('client_id', None)
        print("Client ID:", client_id)
        
        responses_key = f"{tax_assessment_folder}/{client_id}_user_responses.json"
        
        if USE_AWS:
            # Download from S3
            # s3 = boto3.client('s3')
            response = s3.get_object(Bucket=S3_BUCKET_NAME, Key=responses_key)
            responses_json = response['Body'].read().decode('utf-8')
            print("Retrieved responses data:", responses_json)
            return jsonify(json.loads(responses_json)),200
    
    except Exception as e:
        print(f"�� No user responses found: {e}")
        return jsonify({"message": f"No user responses found: {str(e)}"}), 404


# testing purposes : 
# {
#   "data": [
#     {
#       "question": "What is your primary source of income?",
#       "answer": "Business"
#     },
#     {
#       "question": "What is your total annual taxable income?",
#       "answer": "300000"
#     },
#     {
#       "question": "Which state do you reside in?",
#       "answer": "Texas"
#     },
#     {
#       "question": "Do you have any dependents?",
#       "answer": "yes"
#     },
#     {
#       "question": "What tax deductions or exemptions are you eligible for?",
#       "answer": "no"
#     },
#     {
#       "question": "What is the approximate net capital value of all of your real estate properties?",
#       "answer": "500000"
#     },
#     {
#       "question": "State the total investments that you have done",
#       "answer": "none"
#     },
#     {
#       "question": "Do you have medical expenses exceeding a certain percentage of your income?",
#       "answer": "no"
#     },
#     {
#       "question": "Do you contribute to a charity or nonprofit organization?",
#       "answer": "yes, 30,000 annually"
#     },
#     {
#       "question": "Have you made any large one-time purchases in the past year?",
#       "answer": "no"
#     }
#   ],
#   "client_id": "SB6064",
#   "question_index":9
# }