from flask import Flask, request, jsonify
import yfinance as yf
import pandas as pd
import requests
import os
import logging
import numpy as np
from utils import libraries
from utils import formatting
from utils import model_config
from utils import app_config

NEWS_API_KEY = os.getenv('NEWS_API_KEY')

def compute_volatility(returns):
    """Calculate standard deviation of returns (volatility)."""
    return np.std(returns)

def compute_sharpe_ratio(returns, risk_free_rate=0.0):
    """Calculate Sharpe Ratio (risk-adjusted return)."""
    mean_return = np.mean(returns)
    std_dev = np.std(returns)
    return (mean_return - risk_free_rate) / std_dev if std_dev != 0 else 0


def compute_beta(asset_returns, market_returns):
    """Calculate Beta (sensitivity to market)."""
    # Align lengths of asset_returns and market_returns
    min_length = min(len(asset_returns), len(market_returns))
    asset_returns = asset_returns.iloc[-min_length:]
    market_returns = market_returns.iloc[-min_length:]

    # Calculate covariance and beta
    covariance = np.cov(asset_returns, market_returns)[0][1]
    market_variance = np.var(market_returns)
    return covariance / market_variance if market_variance != 0 else 0

# # Fetch Stock Data :
def get_stock_data(ticker):
    try:
        # Step 1: Fetch Stock Data :
        stock = yf.Ticker(ticker)
        
        data = {}

        company_details = stock.info.get('longBusinessSummary', 'No details available')
        data['Company_Details'] = company_details
        sector = stock.info.get('sector', 'No sector information available')
        data['Sector'] = sector
        prev_close = stock.info.get('previousClose', 'No previous close price available')
        data['Previous_Closing_Price'] = prev_close
        open_price = stock.info.get('open', 'No opening price available')
        data['Today_Opening_Price'] = open_price
         
        hist = stock.history(period="5d")
        if not hist.empty and 'Close' in hist.columns:
            if hist.index[-1].date() == yf.download(ticker, period="1d").index[-1].date():
                close_price = hist['Close'].iloc[-1]
                data['Todays_Closing_Price'] = close_price
            else:
                data['Todays_Closing_Price'] = "Market is open, no closing price available yet."
        else:
            data['Todays_Closing_Price'] = "No historical data available for closing price."

        day_high = stock.info.get('dayHigh', 'No high price available')
        data['Today_High_Price'] = day_high
        day_low = stock.info.get('dayLow', 'No low price available')
        data['Today_Low_Price'] = day_low
        volume = stock.info.get('volume', 'No volume information available')
        data['Today_Volume'] = volume
        dividends = stock.info.get('dividendRate', 'No dividend information available')
        data['Today_Dividends'] = dividends
        splits = stock.info.get('lastSplitFactor', 'No stock split information available')
        data['Today_Stock_Splits'] = splits
        pe_ratio = stock.info.get('trailingPE', 'No P/E ratio available')
        data['PE_Ratio'] = pe_ratio
        market_cap = stock.info.get('marketCap', 'No market cap available')
        data['Market_Cap'] = market_cap

        # Additional KPIs
        data['EPS'] = stock.info.get('trailingEps', 'No EPS information available')
        data['Book_Value'] = stock.info.get('bookValue', 'No book value available')
        data['ROE'] = stock.info.get('returnOnEquity', 'No ROE information available')
        data['ROCE'] = stock.info.get('returnOnAssets', 'No ROCE information available')  # ROCE is not available directly
        
        # Revenue Growth (CAGR) and Earnings Growth would need to be calculated based on historical data
        earnings_growth = stock.info.get('earningsGrowth', 'No earnings growth available')
        revenue_growth = stock.info.get('revenueGrowth', 'No revenue growth available')

        data['Earnings_Growth'] = earnings_growth
        data['Revenue_Growth'] = revenue_growth
        
        
        income_statement = stock.financials
        balance_sheet = stock.balance_sheet
        cashflow = stock.cashflow

        # Step 2: Get News Related to Stock
        try:
            # Fetch Stock News
            news_url = f'https://newsapi.org/v2/everything?q={ticker}&apiKey={NEWS_API_KEY}&pageSize=3'
            news_response = requests.get(news_url, timeout=10)

            if news_response.status_code == 200:
                news_data = news_response.json()
                articles = news_data.get('articles', [])
                if articles:
                    top_news = "\n\n".join([f"{i+1}. {article['title']} - {article['url']}" for i, article in enumerate(articles)])
                    data['Top_News'] = top_news
                else:
                    data['Top_News'] = "No news articles found."
            else:
                error_msg = news_response.json().get("message", "Unknown error occurred.")
                data['Top_News'] = f"Failed to fetch news articles. Error: {error_msg}"
        except requests.exceptions.RequestException as e:
            logging.error(f"Network error fetching news: {e}")
            data['Top_News'] = "Network error occurred while fetching news."

        # news_url = f'https://newsapi.org/v2/everything?q={ticker}&apiKey={NEWS_API_KEY}&pageSize=3'
        # news_response = requests.get(news_url)
        # if news_response.status_code == 200:
        #     news_data = news_response.json()
        #     articles = news_data.get('articles', [])
        #     if articles:
        #         top_news = "\n\n".join([f"{i+1}. {article['title']} - {article['url']}" for i, article in enumerate(articles)])
        #         data['Top_News'] = top_news
        #     else:
        #         data['Top_News'] = "No news articles found."
        # else:
        #     data['Top_News'] = "Failed to fetch news articles."
    except Exception as e:
        logging.info(f"Error occurred while collecting stock data: {e}")
        print(f"Error occurred while collecting stock data: :\n{e}")
        return jsonify({'message': 'Internal Server Error in Stock Data Collection'}), 500
    
    print(data['Top_News'])
    
    try:
            
        # Step 3: Save Financial Data to Excel
        file_path = os.path.join('data', f'{ticker}_financial_data.xlsx')
        with pd.ExcelWriter(file_path, engine='xlsxwriter') as writer:
            income_statement.to_excel(writer, sheet_name='Income Statement')
            balance_sheet.to_excel(writer, sheet_name='Balance Sheet')
            cashflow.to_excel(writer, sheet_name='Cashflow')

        # Step 4: Perform Analysis
        avg_close = hist['Close'].mean()
        formatted_data = extract_excel_data(file_path)
        return data,formatted_data,avg_close,file_path
    except Exception as e:
        logging.info(f"Error occurred while performing analysis: {e}")
        print(f"Error occurred while performing analysis :\n{e}")
        return jsonify({'message': 'Internal Server Error in Stock Analysis'}), 500



@app.route('/fetch_stock_data', methods=['GET'])
def fetch_stock_data():
    ticker = request.args.get('ticker')
    if not ticker:
        return jsonify({"error": "Ticker is required"}), 400

    stock = yf.Ticker(ticker)
    data = {}

    company_details = stock.info.get('longBusinessSummary', 'No details available')
    data['Company Details'] = company_details
    sector = stock.info.get('sector', 'No sector information available')
    data['Sector'] = sector
    prev_close = stock.info.get('previousClose', 'No previous close price available')
    data['Previous Closing Price'] = prev_close
    open_price = stock.info.get('open', 'No opening price available')
    data['Today Opening Price'] = open_price

    hist = stock.history(period="5d")
    if not hist.empty and 'Close' in hist.columns:
        if hist.index[-1].date() == yf.download(ticker, period="1d").index[-1].date():
            close_price = hist['Close'].iloc[-1]
            data['Todays Closing Price'] = close_price
        else:
            data['Todays Closing Price'] = "Market is open, there is no closing price available yet."
    else:
        data['Todays Closing Price'] = "No historical data available for closing price."

    day_high = stock.info.get('dayHigh', 'No high price available')
    data['Today High Price'] = day_high
    day_low = stock.info.get('dayLow', 'No low price available')
    data['Today Low Price'] = day_low
    volume = stock.info.get('volume', 'No volume information available')
    data['Today Volume'] = volume
    dividends = stock.info.get('dividendRate', 'No dividend information available')
    data['Today Dividends'] = dividends
    splits = stock.info.get('lastSplitFactor', 'No stock split information available')
    data['Today Stock Splits'] = splits
    pe_ratio = stock.info.get('trailingPE', 'No P/E ratio available')
    data['P/E Ratio'] = pe_ratio
    market_cap = stock.info.get('marketCap', 'No market cap available')
    data['Market Cap'] = market_cap

    income_statement = stock.financials
    balance_sheet = stock.balance_sheet
    cashflow = stock.cashflow

    news_url = f'https://newsapi.org/v2/everything?q={ticker}&apiKey={NEWS_API_KEY}&pageSize=3'
    news_response = requests.get(news_url)
    if news_response.status_code == 200:
        news_data = news_response.json()
        articles = news_data.get('articles', [])
        if articles:
            top_news = "\n\n".join([f"{i+1}. {article['title']} - {article['url']}" for i, article in enumerate(articles)])
            data['Top News'] = top_news
        else:
            data['Top News'] = "No news articles found."
    else:
        data['Top News'] = "Failed to fetch news articles."

    graph_url = f"https://finance.yahoo.com/chart/{ticker}"
    data['graph_url'] = graph_url

    file_path = os.path.join('data', f'{ticker}_financial_data.xlsx')
    with pd.ExcelWriter(file_path, engine='xlsxwriter') as writer:
        income_statement.to_excel(writer, sheet_name='Income Statement')
        balance_sheet.to_excel(writer, sheet_name='Balance Sheet')
        cashflow.to_excel(writer, sheet_name='Cashflow')

    data_list = list(data.items())
    data_str = str(data_list)

    return jsonify({
        "data": data,
        "file_path": file_path,
        "data_str": data_str
    })

@app.route('/analyze_stock_data', methods=['GET'])
def analyze_stock_data():
    ticker = request.args.get('ticker')
    if not ticker:
        return jsonify({"error": "Ticker is required"}), 400

    hist, data_str, file_path = fetch_stock_data(ticker)
    avg_close = hist['Close'].mean()
    formatted_data = extract_excel_data(file_path)

    task = f"""You are a Stock Market Expert. You know everything about stock market trends and patterns.
                Based on the provided stock data, analyze the stock's performance, including whether it is overvalued or undervalued.
                Predict the stock price range for the next week and provide reasons for your prediction.
                Advise whether to buy this stock now or not, with reasons for your advice."""

    query = task + "\nStock Data: " + data_str + "\nFinancial Data: " + formatted_data
    model = genai.GenerativeModel('gemini-1.5-flash')
    response = model.generate_content(query)
    
    # Log the response object to understand its structure
    logging.info(f"Model response: {response}")
    
    # Extract the text content from the response
    try:
        response_text = response.text
        format_response = markdown_to_text(response_text)
    except Exception as e:
        logging.error(f"Error extracting text from response: {e}")
        return jsonify({"error": "Failed to analyze stock data"}), 500

    return jsonify({
        "average_closing_price": f"${avg_close:.2f}",
        "analysis": format_response
    })

def extract_excel_data(file_path):
    financial_data = ""
    xls = pd.ExcelFile(file_path)
    for sheet_name in xls.sheet_names:
        df = pd.read_excel(xls, sheet_name=sheet_name)
        financial_data += f"\n\nSheet: {sheet_name}\n"
        financial_data += df.to_string()
    return financial_data



@app.route('/analyze_stock', methods=['POST'])
def analyze_stock():
    """
    Generate thorough stock analysis using LLM based on company details, market news, and performance.
    """
    try:
        # Fetch input data
        ticker = request.json.get('ticker')
        company = request.json.get('company', None)
        
        if not ticker:
            print("error : Ticker is required")
            ticker = "AMGN"
            # return jsonify({"error": "Ticker is required"}), 400
        
        # Fetch stock data
        data, formatted_data, avg_close, file_path = get_stock_data(ticker)
        
        # Create analysis task prompt for LLM
        task_prompt = f"""
        You are a Stock Market Expert with in-depth knowledge of stock market trends and patterns.
        Analyze the stock performance for {ticker}. The company's details are as follows:{formatted_data}
        Company news : {data.get('Top_News')}
        You have enough data available to analyze the stock and no need to say lack of data or context.

        **Company Name:** 
        **PE Ratio:** {data.get('PE_Ratio')}
        **EPS:** {data.get('EPS')}
        **Book Value:** {data.get('Book_Value')}
        **ROE:** {data.get('ROE')}
        **ROCE:** {data.get('ROCE')}
        **Order Booking:** Not Provided
        **Revenue Growth:** {data.get('Revenue_Growth')}
        **Earnings Growth:** {data.get('Earnings_Growth')}
        **Today's Market Performance:** Closing Price - {data.get('Todays_Closing_Price')}, High Price - {data.get('Today_High_Price')}

        Evaluate the company's income statement, balance sheet, and cash flow. Provide insights into:
        - Whether the stock is overvalued or undervalued.
        - Predictions for its performance in the upcoming quarter.
        - Recommendations for buying, holding, or selling the stock.
        - Give your views on the KPIs in a table format for the Stock:
        PE, EPS, Book Value, ROE, ROCE, Revenue Growth (CAGR), Earnings Growth
        """
        
        # Generate content using LLM model
        model = genai.GenerativeModel('gemini-1.5-flash')
        llm_response = model.generate_content(task_prompt)
        # analysis_response = markdown_to_text(llm_response.text)
        
        # # Extract insights and suggestions from the response
        # formatted_suggestions = markdown.markdown(analysis_response)
        # print(f"\nOutput:\n{formatted_suggestions}")
        
        htmlSuggestions = markdown.markdown(llm_response.text)
        logging.info(f"Suggestions for investor: \n{htmlSuggestions}")
        
        formatSuggestions = markdown_to_text(htmlSuggestions)
        answer = markdown_table_to_html(formatSuggestions)
        print(answer)
        
        stock_price_predictions_data = stock_price_predictions(ticker)
        # Construct response object
        response_data = {
            "ticker": ticker,
            "company": company,
            "average_closing_price": f"${avg_close:.2f}",
            "analysis": answer, # formatted_suggestions,
            "news": data.get("Top_News", "No news available"),
            "graph_url": f"https://finance.yahoo.com/chart/{ticker}",
            "predictions":stock_price_predictions_data
        }

        # Attach the Excel file if available
        # if os.path.exists(file_path):
        #     file_response = send_file(file_path, as_attachment=True, download_name=f'{ticker}_financial_data.xlsx')
        #     file_response.headers['X-Stock-Metadata'] = jsonify(response_data)
        #     return file_response

        return jsonify(response_data)

    except Exception as e:
        logging.error(f"Error generating stock analysis: {e}")
        return jsonify({"error": f"Failed to generate stock analysis: {str(e)}"}), 500

def stock_price_predictions(ticker):
    try:
        # Step 1: Fetch historical stock data
        stock = yf.Ticker(ticker)
        historical_data = stock.history(period="6mo")
        if historical_data.empty:
            return jsonify({"message": f"No historical data found for ticker: {ticker}"}), 404

        # Step 2: Calculate key statistics from historical data
        volatility = compute_volatility(historical_data['Close'])
        sharpe_ratio = compute_sharpe_ratio(historical_data['Close'])
        recent_trend = historical_data['Close'].pct_change().tail(5).mean() * 100  # Last 5-day trend

        # Step 3: Fetch related market and economic news
        news = fetch_news(ticker)
        market_conditions = collect_market_conditions()
        
        if market_conditions == None:
            print("Market Conditions couldnt be determined")
            market_conditions = ""
        
        print(market_conditions)

        # Generate prompt for LLM model
        task = f"""
            You are a top financial analyst tasked with predicting stock price trends for {ticker}.
            Analyze the following:
            - Recent stock price volatility: {volatility:.2f}%
            - Sharpe Ratio: {sharpe_ratio:.2f}
            - Recent price trends (5-day): {recent_trend:.2f}%
            - Market and economic conditions: {market_conditions}
            - Relevant news: {news}

            Predict the expected stock prices for the next month (30 days) under these conditions:
            1. **Best-Case Scenario** (Optimistic market conditions).
            2. **Worst-Case Scenario** (Pessimistic market conditions).
            3. **Confidence Band** (Range of expected prices with 95% confidence).
            
            Introduce **realistic daily ups and downs** caused by market conditions and noise to simulate realistic portfolio performance.

            Example of simulated_response = 
            ### Response Format:
            | Date       | Best-Case Return (%) | Worst-Case Return (%) | Confidence Band (%) | Total Return (%) |
            |------------|-----------------------|-----------------------|---------------------|------------------|
            | 2025-01-01 | 2.5 | -1.0 | 1.0% - 2.0% | 0.75 |
            | 2025-01-15 | 3.0 | -0.5 | 1.5% - 2.5% | 1.25 |
            | 2025-01-31 | 3.5 | 0.0 | 2.0% - 3.0% | 1.75 |
            | 2025-02-01 | 4.0 | 0.5 | 2.5% - 3.5% | 2.25 |
            | 2025-02-15 | 4.5 | 1.0 | 3.0% - 4.0% | 2.75 |
            | 2025-02-28 | 5.0 | 1.5 | 3.5% - 4.5% | 3.25 |
            | 2025-03-01 | 5.5 | 2.0 | 4.0% - 5.0% | 3.75 |
            | 2025-03-15 | 6.0 | 2.5 | 4.5% - 5.5% | 4.25 |
            | 2025-03-31 | 6.5 | 3.0 | 5.0% - 6.0% | 4.75 |

            
            Your Response must be in the above table format no messages is required just table format data.
            """

        # Step 4: Simulate LLM prediction
        model = genai.GenerativeModel('gemini-1.5-flash')
        response = model.generate_content(task)

        simulated_response = markdown_to_text(response.text)
        print(simulated_response)

        # Step 5: Extract and refine predictions
        line_chart_data = extract_line_chart_data(simulated_response)
        refined_predictions = add_noise(line_chart_data)

        # Return refined prediction results
        return refined_predictions
    
        # return jsonify({
        #     "ticker": ticker,
        #     "predictions": refined_predictions,
        #     "analysis": simulated_response
        # })

    except Exception as e:
        print(f"Error in predicting stock prices: {e}")
        return jsonify({"message": f"Error predicting stock prices: {e}"}), 500


def collect_market_conditions():
    """
    Fetch and process current market conditions data, including economic indicators,
    news, and trends to assist in stock analysis and prediction.
    
    Returns:
        dict: A dictionary containing market conditions such as interest rates, inflation,
              geopolitical news, and general market sentiment.
    """
    market_conditions = {}

    try:
        # economic_data_url = "https://api.example.com/economic-indicators"
        economic_data_url = f"https://www.alphavantage.co/query?function=REAL_GDP&apikey={ALPHA_VANTAGE_API_KEY}"
        
        market_news_url = f"https://www.alphavantage.co/query?function=SECTOR&apikey={ALPHA_VANTAGE_API_KEY}"

        # market_news_url = "https://api.example.com/market-news"

        # Fetch economic indicators
        # economic_response = requests.get(economic_data_url)
        # if economic_response.status_code == 200:
        #     economic_data = economic_response.json()
        #     market_conditions['interest_rates'] = economic_data.get('interest_rates', 'Data unavailable')
        #     market_conditions['inflation_rate'] = economic_data.get('inflation_rate', 'Data unavailable')
        # else:
        #     market_conditions['interest_rates'] = 'Failed to fetch interest rates'
        #     market_conditions['inflation_rate'] = 'Failed to fetch inflation rate'

        # # Fetch market news
        # news_response = requests.get(market_news_url)
        # if news_response.status_code == 200:
        #     news_data = news_response.json()
        #     market_conditions['market_news'] = [article['title'] for article in news_data.get('articles', [])][:5]
        # else:
        #     market_conditions['market_news'] = 'Failed to fetch market news'

        # # Add other relevant conditions
        # market_conditions['geopolitical_tensions'] = "Moderate tensions observed globally."
        # market_conditions['us_elections'] = "Upcoming elections may influence market trends."
        
        try:
            # Fetch market data from API
            economic_response = requests.get(economic_data_url)
            market_response = requests.get(market_news_url)

            # Check for successful API responses
            if economic_response.status_code == 200 and market_response.status_code == 200:
                market_conditions = {
                    "interest_rates": economic_response.json().get("interest_rates", "Data unavailable"),
                    "inflation_rate": economic_response.json().get("inflation_rate", "Data unavailable"),
                    "market_news": market_response.json().get("news", []),
                    "geopolitical_tensions": "Moderate tensions observed globally.",
                    "us_elections": "Upcoming elections may influence market trends."
                }
            else:
                raise ValueError("API data fetch failed.")

        except Exception as e:
            print(f"Error fetching market conditions: {e}")
            market_conditions = get_default_market_conditions()


    except Exception as e:
        logging.error(f"Error fetching market conditions: {e}")
        market_conditions['error'] = f"Error fetching market conditions: {e}"

    return market_conditions

def get_default_market_conditions():
    default_conditions = {
        "interest_rates": "Stable interest rates at 4.5%.",
        "inflation_rate": "Moderate inflation at 3.1%.",
        "market_news": [
            "Global markets show mixed trends amid economic recovery.",
            "Tech stocks rally as demand for AI-driven solutions increases.",
            "Oil prices stabilize after months of volatility."
        ],
        "geopolitical_tensions": "Moderate tensions observed globally.",
        "us_elections": "After the elections result of Donald Trump winning the electeions may influence market trends in positive way.",
        "global_trade": "Trade agreements show positive progress with new MAGA (Make America Great Again) Policies.",
        "consumer_confidence": "Consumer confidence index steadily increasing."
    }
    return default_conditions



