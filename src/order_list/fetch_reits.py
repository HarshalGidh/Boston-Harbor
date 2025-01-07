# # Fetch REITS :

# FINNHUB_API_KEY = os.getenv('FINNHUB_API_KEY')

# v-3 : time taking bit good code :

@app.route("/fetch-reits", methods=['POST'])
def fetch_reits():
    REITS_LIST_KEY = "reit_data/reits_list.json"  # S3 key for storing the REITs list
    try:
        # Check if REITs list already exists in AWS S3
        if USE_AWS:
            try:
                response = s3.get_object(Bucket=S3_BUCKET_NAME, Key=REITS_LIST_KEY)
                reits_data = json.loads(response['Body'].read().decode('utf-8'))
                logging.info("Fetched REITs list from AWS S3.")
                
                return jsonify({"message": "REITs fetched successfully", "data": reits_data}), 200
            except s3.exceptions.NoSuchKey:
                logging.info("REITs list not found in AWS S3. Fetching from Finnhub.")
            except Exception as e:
                logging.error(f"Error fetching REITs list from AWS S3: {e}")
                return jsonify({"message": f"Error fetching REITs list from S3: {e}"}), 500

        # If not found in S3, fetch the list from Finnhub
        url = f"https://finnhub.io/api/v1/stock/symbol?exchange=US&token={FINNHUB_API_KEY}"
        response = requests.get(url)

        if response.status_code != 200:
            return jsonify({"message": "Failed to fetch REITs from Finnhub", "status_code": response.status_code}), 500

        data = response.json()
        reits_data = [
            {"symbol": item["symbol"], "name": item["description"]}
            for item in data
            if "REIT" in item.get("description", "") or "Real Estate" in item.get("description", "")
        ]

        # Save REITs list to AWS S3
        if USE_AWS:
            try:
                s3.put_object(
                    Bucket=S3_BUCKET_NAME,
                    Key=REITS_LIST_KEY,
                    Body=json.dumps(reits_data),
                    ContentType='application/json'
                )
                logging.info("Saved REITs list to AWS S3.")
            except Exception as e:
                logging.error(f"Error saving REITs list to AWS S3: {e}")
                return jsonify({"message": f"Error saving REITs list: {e}"}), 500

        # Return the REITs data
        
        return jsonify({"message": "REITs fetched successfully", "data": reits_data}), 200

    except Exception as e:
        logging.error(f"Error fetching REITs: {e}")
        return jsonify({"message": "An error occurred while fetching REITs", "error": str(e)}), 500

@app.route("/get-reit-price", methods=['POST'])
def get_reit_price():
    try:
        # Parse the REIT symbol from the request
        symbol = request.json.get("symbol", [])
        
        if not symbol or not isinstance(symbol, list):
            return jsonify({"message": "No valid symbol provided"}), 400

        reit_prices = []
        default_yield = {"average_yield": "4%-6%"}  # Default yield for REITs

        # Fetch price and yield for each REIT
        for symbol in symbol:
            # Ensure the symbol is treated as a whole string
            if not isinstance(symbol, str) or not symbol.strip():
                logging.warning(f"Invalid symbol format: {symbol}")
                continue

            # Fetch price
            price_url = f"https://finnhub.io/api/v1/quote?symbol={symbol}&token={FINNHUB_API_KEY}"
            price_response = requests.get(price_url)

            if price_response.status_code == 200:
                price_data = price_response.json()
                price = price_data.get("c", 0)  # Current price

                # Fetch yield
                yield_url = f"https://finnhub.io/api/v1/stock/metric?symbol={symbol}&metric=dividends&token={FINNHUB_API_KEY}"
                yield_response = requests.get(yield_url)

                if yield_response.status_code == 200:
                    yield_data = yield_response.json()
                    dividend_yield = yield_data.get("metric", {}).get("dividendYieldIndicatedAnnual", default_yield["average_yield"])
                else:
                    dividend_yield = default_yield["average_yield"]

                # Append to results if price is greater than 0
                if price > 0:
                    reit_prices.append({"symbol": symbol, "price": price, "yield": dividend_yield})
            else:
                logging.warning(f"Failed to fetch price for symbol: {symbol}")
        print(reit_prices)
        return jsonify({"message": "Prices and yields fetched successfully", "reit_prices": reit_prices}), 200

    except Exception as e:
        logging.error(f"Error fetching REIT prices: {e}")
        return jsonify({"message": "An error occurred while fetching REIT prices", "error": str(e)}), 500


# # v-3 : time taking bit good code :

# # @app.route("/fetch-reits", methods=['POST'])
# # def fetch_reits():
# #     try:
# #         # Fetch the list of US stocks from Finnhub
# #         url = f"https://finnhub.io/api/v1/stock/symbol?exchange=US&token={FINNHUB_API_KEY}"
# #         response = requests.get(url)

# #         if response.status_code != 200:
# #             print(f"Failed to fetch REITs. Status code: {response.status_code}")
# #             return []

# #         data = response.json()
# #         reits = [
# #             {"symbol": item["symbol"], "name": item["description"]}
# #             for item in data
# #             if "REIT" in item["description"] or "Real Estate" in item["description"]
# #         ]

# #         # Fetch the current price for each REIT
# #         for reit in reits:
# #             price_url = f"https://finnhub.io/api/v1/quote?symbol={reit['symbol']}&token={FINNHUB_API_KEY}"
# #             price_response = requests.get(price_url)

# #             if price_response.status_code == 200:
# #                 price_data = price_response.json()
# #                 reit["price"] = price_data.get("c", "N/A")  # "c" is the current price key
# #                 print(reit)
                
# #             else:
# #                 reit["price"] = "N/A"

# #         # Print the final REITs data with price
# #         print(reits)
# #         return reits

# #     except Exception as e:
# #         print(f"Error fetching REITs from Finnhub: {e}")
# #         return []


# # v-2 :best version

# @app.route("/fetch-reits", methods=['POST'])
# def fetch_reits():
#     try:
#         # Fetch the list of US stocks from Finnhub
#         url = f"https://finnhub.io/api/v1/stock/symbol?exchange=US&token={FINNHUB_API_KEY}"
#         response = requests.get(url)

#         if response.status_code != 200:
#             return jsonify({"message": "Failed to fetch REITs from Finnhub", "status_code": response.status_code}), 500

#         data = response.json()
#         valid_reits = []

#         # Filter REITs and fetch prices in a single loop
#         for item in data:
#             if "REIT" in item.get("description", "") or "Real Estate" in item.get("description", ""):
#                 symbol = item["symbol"]
#                 name = item["description"]

#                 # Fetch the price for the current REIT
#                 price_url = f"https://finnhub.io/api/v1/quote?symbol={symbol}&token={FINNHUB_API_KEY}"
#                 price_response = requests.get(price_url)

#                 if price_response.status_code == 200:
#                     price_data = price_response.json()
#                     price = price_data.get("c", 0)  # "c" is the current price key

#                     # Only add to the list if the price is greater than 0
#                     if price > 0:
#                         valid_reits.append({"symbol": symbol, "name": name, "price": price})

#         # Return the filtered REITs with success message
#         print(valid_reits)
#         return jsonify({"message": "REITs fetched successfully", "data": valid_reits}), 200

#     except Exception as e:
#         print(f"Error fetching REITs from Finnhub: {e}")
#         return jsonify({"message": "An error occurred while fetching REITs", "error": str(e)}), 500