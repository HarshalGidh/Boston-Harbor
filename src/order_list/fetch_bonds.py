from utils import libraries
@app.route('/get-bonds', methods=['POST'])
def get_bonds():
    """
    Fetches the List of Bonds for various categories
    """
    try:
        data = request.get_json()
        category = data.get("category", "").lower()
        treasury_bonds = [
            {"name":"13 WEEK TREASURY BILL" ,"symbol":"^IRX"},
            {"name":"Treasury Yield 5 Years" ,"symbol":"^FVX"},
            {"name":"CBOE Interest Rate 10 Year T No" ,"symbol":"^TNX"},
            {"name":"Treasury Yield 30 Years" ,"symbol":"^TYX"}
        ]
        corporate_bonds = [
            {"name":"BlackRock High Yield Port Svc","symbol":"BHYSX"},
            {"name":"American Funds American High-Inc F2","symbol":"AHIFX"},
            {"name":"PGIM High Yield R6","symbol":"PHYQX"},
            {"name":"Federated Hermes Instl High Yield Bd IS","symbol":"FIHBX"}
        ]
        if category == "treasury":
            return jsonify({"bonds":treasury_bonds}), 200
        elif category == "corporate":
            return jsonify({"bonds":corporate_bonds}), 200
        else:
            return jsonify({"message": "Invalid category. Choose between 'treasury' or 'corporate'."}), 400
            
    except Exception as e:
        print(f"Error in get-bonds API: {e}")
        return jsonify({"message": f"Error in get-bonds API: {e}"}), 500


@app.route('/fetch-bonds', methods=['POST'])
def fetch_bonds():
    """
    Fetches the price of a specific bond using the ticker provided in the request payload.
    """
    try:
        data = request.get_json()
        category = data.get("category", "").lower()

        if not category:
            return jsonify({
                "message": "Ticker not provided in the request.",
                "price": "N/A"
            }), 400
            
        selected_ticker = data.get("ticker")
        
        # Function to fetch the latest closing price
        def fetch_price(ticker):
            try:
                # Fetch historical data for the bond
                data = yf.download(ticker, period="1mo", interval="1d")
                if not data.empty:
                    # Get the latest closing price
                    return round(data['Close'].iloc[-1], 2)
                else:
                    return "Price not available"
            except Exception as e:
                print(f"Error fetching data for ticker {ticker}: {e}")
                return "Price not available"

        # Fetch price for the selected Bond
        price = fetch_price(selected_ticker)
        print(f"Bond price for {selected_ticker}:\n{price}")

        return jsonify({
            "message": f"Price for {selected_ticker} fetched successfully",
            "ticker": selected_ticker,
            "price": price
        }), 200

    except Exception as e:
        print(f"Error fetching bond prices: {e}")
        return jsonify({"message": f"Internal server error: {e}"}), 500

