# Fetch REITS :


FINNHUB_API_KEY = os.getenv('FINNHUB_API_KEY')


# v-3 : time taking bit good code :

# @app.route("/fetch-reits", methods=['POST'])
# def fetch_reits():
#     try:
#         # Fetch the list of US stocks from Finnhub
#         url = f"https://finnhub.io/api/v1/stock/symbol?exchange=US&token={FINNHUB_API_KEY}"
#         response = requests.get(url)

#         if response.status_code != 200:
#             print(f"Failed to fetch REITs. Status code: {response.status_code}")
#             return []

#         data = response.json()
#         reits = [
#             {"symbol": item["symbol"], "name": item["description"]}
#             for item in data
#             if "REIT" in item["description"] or "Real Estate" in item["description"]
#         ]

#         # Fetch the current price for each REIT
#         for reit in reits:
#             price_url = f"https://finnhub.io/api/v1/quote?symbol={reit['symbol']}&token={FINNHUB_API_KEY}"
#             price_response = requests.get(price_url)

#             if price_response.status_code == 200:
#                 price_data = price_response.json()
#                 reit["price"] = price_data.get("c", "N/A")  # "c" is the current price key
#                 print(reit)
                
#             else:
#                 reit["price"] = "N/A"

#         # Print the final REITs data with price
#         print(reits)
#         return reits

#     except Exception as e:
#         print(f"Error fetching REITs from Finnhub: {e}")
#         return []


# v-2 :best version

@app.route("/fetch-reits", methods=['POST'])
def fetch_reits():
    try:
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

        # Return the filtered REITs with success message
        print(valid_reits)
        return jsonify({"message": "REITs fetched successfully", "data": valid_reits}), 200

    except Exception as e:
        print(f"Error fetching REITs from Finnhub: {e}")
        return jsonify({"message": "An error occurred while fetching REITs", "error": str(e)}), 500