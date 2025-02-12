# Chatbot :
from src.utils.libraries import *

from phi.agent import Agent, AgentMemory
phi_agent = Agent()

# ✅ Fix Memory Issue: Provide explicit storage
chat_memory = AgentMemory(
    create_user_memories=True,
    create_session_summary=True,
    storage="file"  # ✅ Stores memory in a local file
)

# ✅ Web Search Agent - Ensure it does not use OpenAI
duckduckgo_search_agent = Agent(
    name="Web Search Agent",
    role="Search Web for Current US Tax Rates",
    model=Gemini(id="gemini-1.5-flash", api_key=GOOGLE_API_KEY),
    tools=[DuckDuckGo()],  # ✅ Ensure it does not fall back to OpenAI
    instructions=["Always provide sources"],
    show_tools_calls=True,
    markdown=True,
)

# ✅ Finance Agent - Ensure it does not use OpenAI
stocks_agent = Agent(
    name="Stock Market Agent",
    role="Give analysis and sugggestions on the given assets if its profitable to buy/hold/sell the asset and when to do so",
    model=Gemini(id="gemini-1.5-flash", api_key=GOOGLE_API_KEY),
    tools=[
        YFinanceTools(
            stock_price=True, analyst_recommendations=True,
            stock_fundamentals=True, company_news=True,
            company_info=True, key_financial_ratios=True,
            income_statements=True, technical_indicators=True,
            historical_prices=True
        )
    ],
    description="Format your response using markdown and use tables for clarity.",
    instructions=[
        "Always provide sources",
        "Format responses using markdown and use tables where applicable."
    ],
    show_tools_calls=True,
    markdown=True,
)

# ✅ Multi-AI Chatbot - Ensuring Gemini Handles All Responses
multi_ai_chatbot = Agent(
    name="Multi-AI Chatbot",
    role="A chatbot that can search the web, fetch stock data, and answer general user queries.",
    model=Gemini(id="gemini-1.5-flash", api_key=GOOGLE_API_KEY),
    team=[duckduckgo_search_agent, stocks_agent],  # ✅ Use Gemini-based sub-agents
    instructions=[
        "Always provide sources for your answers.",
        "Format your response in markdown with tables for clarity.",
        "Use YFinance for financial queries, DuckDuckGo for general knowledge.",
        "Use `search_web(query)` to look up general queries and provide sources.",
        "Use `get_stock_info(symbol)` for finance-related queries.",
        "Ensure responses are **clear, structured, and contain no AI references."
    ],
    add_chat_history_to_messages=True,
    show_tools_calls=True,
    markdown=True,
    function_declarations=[
        {"name": "search_web", "description": "Search the web for information and provide sources.", "parameters": ["query"]},
        {"name": "get_stock_info", "description": "Fetch stock data.", "parameters": ["symbol"]}
    ],
    # function_declarations	= Optional[List[FunctionDeclaration]]
)

# ✅ Define Function Calls (Web Search & Stock Data)
def search_web(query):
    """ Searches the web using DuckDuckGo and returns summarized results. """
    search_tool = DuckDuckGo()
    results = search_tool.run(query=query, max_results=5)  # Get top 5 results
    return results if results else "No relevant information found."

def get_stock_info(symbol):
    """ Fetches stock details using Yahoo Finance API. """
    stock_tool = YFinanceTools(stock_price=True)
    stock_info = stock_tool.get_current_stock_price(symbol)
    return stock_info if stock_info else "No stock data available."

# 🔹 **API for Chatbot Conversation**
@app.route('/api/chatbot', methods=['POST'])
def chatbot():
    try:
        data = request.json
        user_input = data.get("user_input", "")
        session_id = data.get("session_id", "default")

        if not user_input:
            return jsonify({"error": "No user input provided"}), 400

        print(f"📩 Received Query: {user_input}")
        print(f"�� Session ID: {session_id}")

        # 🔹 **Generate AI Response**
        response = multi_ai_chatbot.run(
            message = f"""Based on user's query : {user_input} use DuckDuckGo search for general information,
            and use YFinance for financial-related information.Give Accurate and Correct Responses.
            If you dont know or dont have enough information ask user to provide more data.
            **Ensure the response is structured in markdown format with tables where applicable.** 
            Do not use first-person language.  
            Do not mention AI agents or task delegation.  
            """,
            messages=[user_input],
            session_id=session_id,
            stream=False
        )

        # # 🔹 **Extract Response Text**
        # ai_response = response.content if hasattr(response, "content") else str(response)
        
        # Extract response content safely
        if isinstance(response, RunResponse) and hasattr(response, "content"):
            response_text = response.content  # Extracting the actual response text
        else:
            response_text = str(response) # "Error: Unexpected AI response format."
        
        # Process the response from LLM
        response_text = markdown.markdown(response_text, extensions=["extra"]) # html_suggestions
        # response_text = markdown_to_text(html_suggestions) # format_suggestions
        
        print("ai_response", response_text)
        
        # 🔹 **Save Response History (Optional)**
        save_chat_history(session_id, user_input, response_text)

        return jsonify({
            "user_input": user_input,
            "ai_response": response_text
        }), 200

    except Exception as e:
        logging.error(f"Error in chatbot: {e}")
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500


# 🔹 **Save Chat History**
def save_chat_history(session_id, user_input, ai_response):
    history_folder = "chat_history"
    os.makedirs(history_folder, exist_ok=True)
    file_path = os.path.join(history_folder, f"{session_id}.json")

    chat_entry = {"user_input": user_input, "ai_response": ai_response}

    # Append to existing history
    if os.path.exists(file_path):
        with open(file_path, "r") as file:
            chat_history = json.load(file)
    else:
        chat_history = []

    chat_history.append(chat_entry)

    with open(file_path, "w") as file:
        json.dump(chat_history, file, indent=4)

    print(f"💾 Chat history saved for session: {session_id}")


# 🔹 **API to Fetch Chat History**
@app.route('/api/chat-history', methods=['POST'])
def get_chat_history():
    try:
        session_id = request.json.get("session_id", "default")
        file_path = os.path.join("chat_history", f"{session_id}.json")

        if os.path.exists(file_path):
            with open(file_path, "r") as file:
                chat_history = json.load(file)
            return jsonify(chat_history), 200
        else:
            return jsonify({"message": "No chat history found."}), 404

    except Exception as e:
        logging.error(f"Error retrieving chat history: {e}")
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500

