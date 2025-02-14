# Chatbot :
from src.utils.libraries import *

from phi.agent import Agent  # For structured reasoning
from phi.agent import Agent, AgentMemory
from phi.model.groq import Groq
from phi.tools.yfinance import YFinanceTools
from phi.tools.duckduckgo import DuckDuckGo

from phi.agent import Agent, RunResponse
from phi.model.google import Gemini

from phi.agent import Agent, AgentMemory
phi_agent = Agent()

# ✅ Define Function Calls (Web Search & Stock Data)

def search_web(query: str) -> str:
    """
    Searches the web using DuckDuckGo and returns the top 5 results in a Markdown table.
    """
    search_tool = DuckDuckGo()
    # Use the correct method: "search" (not "run")
    results = search_tool.search(query=query, max_results=5)
    if results:
        table = "| Title | URL | Snippet |\n| --- | --- | --- |\n"
        for res in results:
            title = res.get("title", "N/A")
            url = res.get("href", "N/A")
            snippet = res.get("body", "N/A")
            table += f"| {title} | {url} | {snippet} |\n"
        return table
    else:
        return "No relevant information found."

def get_stock_info(symbol: str) -> str:
    """
    Fetches the current stock price using Yahoo Finance API and returns it in a Markdown table.
    """
    stock_tool = YFinanceTools(stock_price=True)
    stock_price = stock_tool.get_current_stock_price(symbol)
    if stock_price:
        table = "| Symbol | Current Price |\n| --- | --- |\n"
        table += f"| {symbol.upper()} | {stock_price} |\n"
        return table
    else:
        return "No stock data available."

def get_company_info(symbol: str) -> str:
    """
    Fetches detailed company information using Yahoo Finance API and returns it in a Markdown table.
    """
    info_tool = YFinanceTools(company_info=True)
    company_info = info_tool.get_company_info(symbol)
    # Check if company_info is a dict (expected) or already a string.
    if isinstance(company_info, dict):
        table = "| Field | Value |\n| --- | --- |\n"
        for key, value in company_info.items():
            table += f"| {key} | {value} |\n"
        return table
    elif isinstance(company_info, str):
        return company_info
    else:
        return "No company info available."

def get_company_news(symbol: str) -> str:
    """
    Fetches recent company news using Yahoo Finance API and returns the results in a Markdown table.
    """
    news_tool = YFinanceTools(company_news=True)
    news = news_tool.get_company_news(symbol)
    if isinstance(news, list):
        table = "| Date | Title | URL |\n| --- | --- | --- |\n"
        for article in news:
            if isinstance(article, dict):
                date = article.get("date", "N/A")
                title = article.get("title", "N/A")
                url = article.get("url", "N/A")
                table += f"| {date} | {title} | {url} |\n"
            else:
                table += f"| {article} |\n"
        return table
    elif isinstance(news, str):
        return news
    else:
        return "No company news available."

def get_analyst_recommendations(symbol: str) -> str:
    """
    Fetches analyst recommendations using Yahoo Finance API and returns them in a Markdown table.
    """
    rec_tool = YFinanceTools(analyst_recommendations=True)
    recommendations = rec_tool.get_analyst_recommendations(symbol)
    if isinstance(recommendations, list):
        table = "| Analyst | Recommendation | Target Price |\n| --- | --- | --- |\n"
        for rec in recommendations:
            if isinstance(rec, dict):
                analyst = rec.get("analyst", "N/A")
                recommendation = rec.get("recommendation", "N/A")
                target_price = rec.get("target_price", "N/A")
                table += f"| {analyst} | {recommendation} | {target_price} |\n"
            else:
                table += f"| {rec} |\n"
        return table
    elif isinstance(recommendations, str):
        return recommendations
    else:
        return "No analyst recommendations available."

def calculate_math(query: str) -> str:
    """
    Extracts a mathematical expression from the query and evaluates it.
    """
    expression_matches = re.findall(r"([\d\.\+\-\*xX\/\s]+)", query)
    if expression_matches:
        expr = expression_matches[0].strip()
        expr = expr.replace('x', '*').replace('X', '*')
        if not re.match(r'^[\d\.\+\-\*\/\s]+$', expr):
            return "Invalid characters in the mathematical expression."
        try:
            result = eval(expr)
            return f"The result of `{expr}` is **{result}**."
        except Exception as e:
            return f"Error evaluating expression: {e}"
    else:
        return "No valid mathematical expression found."

def handle_query(user_input: str) -> str:
    """
    Determines which function to use based on the user's query.
    """
    user_lower = user_input.lower()
    if ("price" in user_lower or "current price" in user_lower) and "tsla" in user_lower:
        return get_stock_info("TSLA")
    elif ("company details" in user_lower or "about" in user_lower) and "tesla" in user_lower:
        return get_company_info("TSLA")
    elif "news" in user_lower and "tesla" in user_lower:
        return get_company_news("TSLA")
    elif ("analysis" in user_lower or "recommendations" in user_lower) and "tesla" in user_lower:
        return get_analyst_recommendations("TSLA")
    elif "what is" in user_lower and any(op in user_lower for op in ["+", "-", "x", "*", "/"]):
        return calculate_math(user_input)
    else:
        return search_web(user_input)


# ✅ Fix Memory Issue: Provide explicit storage
chat_memory = AgentMemory(
    create_user_memories=True,
    create_session_summary=True,
    storage="file"  # ✅ Stores memory in a local file
)

# ✅ Web Search Agent - Ensure it does not use OpenAI
duckduckgo_search_agent = Agent(
    name="Web Search Agent",
    role="Search Web for any general queries or facts.",
    model=Gemini(id="gemini-1.5-flash", api_key=GOOGLE_API_KEY),
    tools=[DuckDuckGo(),search_web],  # ✅ Ensure it does not fall back to OpenAI
    instructions=["Always provide sources"],
    show_tools_calls=True,
    markdown=True,
)

# ✅ Finance Agent - Ensure it does not use OpenAI
stocks_agent = Agent(
    name="Stock Market Agent",
    role="Provide stock/asset data, analysis, financial data, and suggestions.",
    model=Gemini(id="gemini-1.5-flash", api_key=GOOGLE_API_KEY),
    tools=[
        YFinanceTools(
            stock_price=True, analyst_recommendations=True,
            stock_fundamentals=True, company_news=True,
            company_info=True, key_financial_ratios=True,
            income_statements=True, technical_indicators=True,
            historical_prices=True
        ),
        get_stock_info,
        get_company_info,
        get_analyst_recommendations
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
        "Provide concise, accurate, and well-formatted responses.",
        "Format your response in markdown with tables for clarity.",
        "For financial queries, use YFinanceTools (e.g., get_stock_info, get_company_info, get_company_news, get_analyst_recommendations,etc),output only the requested data in a table without extra commentary about data sources or API limitations..",
        "For general queries, use DuckDuckGo search,provide a clear, straightforward answer without internal details.",
        "Ensure responses are clear, structured, and do not refer to internal AI agents or use first-person language,output only the requested data without extra commentary about data sources or API limitations."
    ],
    add_chat_history_to_messages=True,
    tools = [search_web,get_stock_info,get_company_info,get_analyst_recommendations,calculate_math],
    show_tools_calls=True,
    markdown=True,
    # reasoning=True,
    # structured_outputs=True,
    function_declarations=[
        {
            "name": "search_web",
            "description": "Search the web for information and provide sources.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string"}
                },
                "required": ["query"]
            }
        },
        {
            "name": "get_stock_info",
            "description": "Fetch current stock price data.",
            "parameters": {
                "type": "object",
                "properties": {
                    "symbol": {"type": "string"}
                },
                "required": ["symbol"]
            }
        },
        {
            "name": "get_company_info",
            "description": "Fetch detailed company information.",
            "parameters": {
                "type": "object",
                "properties": {
                    "symbol": {"type": "string"}
                },
                "required": ["symbol"]
            }
        },
        {
            "name": "get_company_news",
            "description": "Fetch recent company news.",
            "parameters": {
                "type": "object",
                "properties": {
                    "symbol": {"type": "string"}
                },
                "required": ["symbol"]
            }
        },
        {
            "name": "get_analyst_recommendations",
            "description": "Fetch analyst recommendations.",
            "parameters": {
                "type": "object",
                "properties": {
                    "symbol": {"type": "string"}
                },
                "required": ["symbol"]
            }
        },
        {
            "name": "calculate_math",
            "description": "Evaluate a mathematical expression.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string"}
                },
                "required": ["query"]
            }
        }
    ],
    # function_declarations	= Optional[List[FunctionDeclaration]]
)


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
            message=f"""Based on the user's query: "{user_input}"
            decide whether the query is finance-related or general. Use the appropriate functions:
            - For finance-related queries, consider using `get_stock_info`, `get_company_info`, `get_company_news`, or `get_analyst_recommendations`.
            - For general queries, use `search_web` to look up the information.
            Provide accurate, structured, and source-cited responses. Format your answer in markdown with tables where applicable,
            provide a clear, straightforward answer without internal details.
            Do not use first-person language or mention internal task delegation.""",
            messages=[user_input],
            session_id=session_id,
            stream=False
        )
        
        # response = multi_ai_agent.print_response(
        #     f"""Based on the user's query: "{json.dumps(user_input, indent=4)}"
        #     decide whether the query is finance-related or general. Use the appropriate functions:
        #     - For finance-related queries, consider using `get_stock_info`, `get_company_info`, `get_company_news`, or `get_analyst_recommendations`.
        #     - For general queries, use `search_web` to look up the information.
        #     Provide accurate, structured, and source-cited responses. Format your answer in markdown with tables where applicable.
        #     Do not use first-person language or mention internal task delegation.""",
        #     )
        
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


# 🔹 **Save Chat History* into local*
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