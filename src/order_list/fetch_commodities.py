from utils import libraries
# #V2 : working properly 
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
            "symbol": selected_ticker,
            "price": price
        }), 200

    except Exception as e:
        print(f"Error fetching commodity prices: {e}")
        return jsonify({"message": f"Internal server error: {e}"}), 500
