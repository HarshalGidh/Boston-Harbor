
@app.route("/fetch-reits", methods=['POST'])
def fetch_reits():
    try:
        # AWS key for the REIT list
        reit_list_key = "reits/reit_list.json"

        # Check if the REIT list already exists in AWS
        try:
            response = s3.get_object(Bucket=S3_BUCKET_NAME, Key=reit_list_key)
            reit_list = json.loads(response['Body'].read().decode('utf-8'))
            logging.info("REIT list loaded from AWS.")
            return jsonify({"message": "REITs loaded from AWS successfully", "data": reit_list}), 200
        except s3.exceptions.NoSuchKey:
            logging.info("REIT list not found in AWS. Fetching from Finnhub.")

        # Fetch the list of US stocks from Finnhub
        url = f"https://finnhub.io/api/v1/stock/symbol?exchange=US&token={FINNHUB_API_KEY}"
        response = requests.get(url)

        if response.status_code != 200:
            return jsonify({"message": "Failed to fetch REITs from Finnhub", "status_code": response.status_code}), 500

        data = response.json()
        valid_reits = []

        # Filter REITs and fetch prices in a single loop
        for item in data:
            if "REIT" in item.get("description", "") or "Real Estate" in item.get("description", ""):
                symbol = item["symbol"]
                name = item["description"]

                # Fetch the price for the current REIT
                price_url = f"https://finnhub.io/api/v1/quote?symbol={symbol}&token={FINNHUB_API_KEY}"
                price_response = requests.get(price_url)

                if price_response.status_code == 200:
                    price_data = price_response.json()
                    price = price_data.get("c", 0)  # "c" is the current price key

                    # Only add to the list if the price is greater than 0
                    if price > 0:
                        valid_reits.append({"symbol": symbol, "name": name, "price": price})

        # Save the valid REITs list to AWS
        s3.put_object(
            Bucket=S3_BUCKET_NAME,
            Key=reit_list_key,
            Body=json.dumps(valid_reits),
            ContentType='application/json'
        )
        logging.info("REIT list saved to AWS.")

        return jsonify({"message": "REITs fetched and saved successfully", "data": valid_reits}), 200

    except Exception as e:
        logging.error(f"Error fetching REITs from Finnhub: {e}")
        return jsonify({"message": "An error occurred while fetching REITs", "error": str(e)}), 500

@app.route("/get-reit-price", methods=['POST'])
def get_reit_price():
    try:
        # Ensure Content-Type is application/json
        if not request.is_json:
            return jsonify({"message": "Invalid Content-Type. Please set 'Content-Type: application/json'."}), 415

        # Parse the REIT symbol from the request
        symbol = request.json.get("symbol")
        if not symbol or not isinstance(symbol, str) or not symbol.strip():
            return jsonify({"message": "Invalid symbol provided. Must be a non-empty string."}), 400

        symbol = symbol.strip()  # Remove any leading/trailing spaces

        # Load the REIT list from AWS
        response = s3.get_object(Bucket=S3_BUCKET_NAME, Key="reits/reit_list.json")
        reit_list = json.loads(response['Body'].read())

        # Validate if the symbol exists in the REIT list
        reit = next((item for item in reit_list if item["symbol"] == symbol), None)
        if not reit:
            return jsonify({"message": f"Symbol {symbol} is not a valid REIT."}), 400

        # Fetch yield for the REIT
        yield_url = f"https://finnhub.io/api/v1/stock/metric?symbol={symbol}&metric=dividends&token={FINNHUB_API_KEY}"
        yield_response = requests.get(yield_url)

        if yield_response.status_code == 200:
            yield_data = yield_response.json()
            dividend_yield = yield_data.get("metric", {}).get("dividendYieldIndicatedAnnual", "4%-6%")
        else:
            dividend_yield = "4%-6%"

        # Return the REIT information
        return jsonify({
            "message": "Price and yield fetched successfully",
            "reit_info": {"symbol": reit["symbol"], "name": reit["name"], "price": reit["price"], "yield": dividend_yield}
        }), 200

    except Exception as e:
        logging.error(f"Error fetching REIT prices: {e}")
        return jsonify({"message": "An error occurred while fetching REIT prices", "error": str(e)}), 500
