 
@app.route('/fetch-commodities', methods=['POST'])
def fetch_commodities():
    """
    Fetches the price of a specific commodity using the ticker provided in the request payload.
    """
    try:
        data = request.get_json()
        selected_ticker = data.get("commodities")  

        if not selected_ticker:
            return jsonify({
                "message": "Ticker not provided in the request.",
                "price": "N/A"
            }), 400

        # Function to fetch the latest closing price
        def fetch_price(ticker):
            try:
                # Fetch historical data for the commodity
                data = yf.download(ticker, period="1d", interval="1d")
                if not data.empty:
                    # Get the latest closing price
                    return round(data['Close'].iloc[-1], 2)
                else:
                    return "Price not available"
            except Exception as e:
                print(f"Error fetching data for ticker {ticker}: {e}")
                return "Price not available"

        # Fetch price for the selected commodity
        price = fetch_price(selected_ticker)
        print(f"Commodity price for {selected_ticker}:\n{price}")

        return jsonify({
            "message": f"Price for {selected_ticker} fetched successfully",
            "ticker": selected_ticker,
            "price": price
        }), 200

    except Exception as e:
        print(f"Error fetching commodity prices: {e}")
        return jsonify({"message": f"Internal server error: {e}"}), 500




# V-1 : working properly for all

# @app.route('/fetch-commodities', methods=['POST'])
# def fetch_commodities():
#     """
#     Fetches the price of specific commodities: WTI Crude, Brent Crude, Gold, Silver, Natural Gas.
#     """
#     try:
#         data = request.get_json()
#         selected_commodity = data.get("commodity")  # Single commodity or None

#         # Commodity tickers for Yahoo Finance
#         commodity_tickers = {
#             "WTI Crude": "CL=F",
#             "Brent Crude": "BZ=F",
#             "Gold": "GC=F",
#             "Silver": "SI=F",
#             "Natural Gas": "NG=F"
#         }

#         # Function to fetch the latest closing price
#         def fetch_price(ticker):
#             try:
#                 # Fetch historical data for the commodity
#                 data = yf.download(ticker, period="1d", interval="1d")
#                 if not data.empty:
#                     # Get the latest closing price
#                     return round(data['Close'].iloc[-1], 2)
#                 else:
#                     return "Price not available"
#             except Exception as e:
#                 print(f"Error fetching data for ticker {ticker}: {e}")
#                 return "Price not available"

#         # If a specific commodity is requested
#         if selected_commodity:
#             ticker = commodity_tickers[selected_commodity] #commodity_tickers.get(selected_commodity)
#             print(ticker)
#             if not ticker:
#                 return jsonify({
#                     "message": f"Commodity '{selected_commodity}' not found",
#                     "prices": {}
#                 }), 404

#             # Fetch price for the selected commodity
#             price = fetch_price(ticker)
#             print(f"Commodity price for {selected_commodity} :\n{price}")
            
#             return jsonify({
#                 "message": f"Price for {selected_commodity} fetched successfully",
#                 "prices": {price}
#             }), 200

#         # #Fetch prices for all commodities if no specific one is provided
#         commodity_prices = {}
#         for name, ticker in commodity_tickers.items():
#             commodity_prices[name] = fetch_price(ticker)

#         print("Commodity prices :\n", commodity_prices)

#         return jsonify({
#             "message": "Commodity prices fetched successfully",
#             "prices": commodity_prices
#         }), 200

#     except Exception as e:
#         print(f"Error fetching commodity prices: {e}")
#         return jsonify({"message": f"Internal server error: {e}"}), 500
