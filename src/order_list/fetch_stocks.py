from utils import libraries


def fetch_all_assets_by_preference(market_name, preference=None):
    """
    Fetch assets for a given market and filter by type if preference is provided.
    Handles NASDAQ, NYSE, S&P500, and Dow Jones dynamically.
    Preferences: "stocks", "etfs", "bonds", "commodities", "mutual funds".
    """
    try:
        market_name = market_name.lower()
        preference = preference.lower() if preference else None
        assets = []

        # Fetch for NASDAQ and NYSE using Alpha Vantage
        if market_name in ["nasdaq", "nyse"]:
            exchange_code = "NASDAQ" if market_name == "nasdaq" else "NYSE"
            url = f"https://www.alphavantage.co/query?function=LISTING_STATUS&apikey={ALPHA_VANTAGE_API_KEY}"
            response = requests.get(url)
            print(response)
            if response.status_code == 200:
                stocks = response.text.splitlines()  # Alpha Vantage returns CSV data
                print(stocks)
                for row in stocks[1:]:  # Skip header row
                    data = row.split(",")
                    if len(data) > 2 and data[2].strip() == exchange_code:
                        symbol = data[0]
                        name = data[1]

                        # Filter based on preference
                        # Determine asset type (heuristics for ETF or stock)
                        asset_type = "stock"
                        if "ETF" in name.upper() or "TRUST" in name.upper() or symbol.endswith("O"):
                            asset_type = "etf"
                            assets.append({"name": name, "symbol": symbol, "type": "ETF"})
                            
                        # Filter based on preference
                        # if not preference or preference == asset_type:
                        elif preference:
                            assets.append({"name": name, "symbol": symbol, "type": preference})
                            
                        # if preference:  # Assuming preference is handled externally
                        #     assets.append({"name": name, "symbol": symbol, "type": preference})
                        
                print(f"Assets in {market_name} :\n{assets}")
                return assets
            else:
                print(f"Alpha Vantage API error: {response.status_code}")
                return []

        # Fetch for S&P500 using Wikipedia
        elif market_name == "s&p500":
            url = "https://en.wikipedia.org/wiki/List_of_S%26P_500_companies"
            response = requests.get(url)
            if response.status_code == 200:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(response.content, "html.parser")
                table = soup.find("table", {"id": "constituents"})
                rows = table.find_all("tr")[1:]  # Skip header row
                for row in rows:
                    cols = row.find_all("td")
                    symbol = cols[0].text.strip()
                    name = cols[1].text.strip()
                    if not preference or preference == "stocks":
                        assets.append({"name": name, "symbol": symbol, "type": "stock"})
                return assets
            else:
                print(f"Failed to fetch S&P500 data from Wikipedia: {response.status_code}")
                return []
            
        # If no matching market is found
        return []

    except Exception as e:
        print(f"Error fetching assets for {market_name}: {e}")
        return []



@app.route('/market-assets', methods=['POST'])
def market_assets():
    try:
        data = request.get_json()
        market_name = data.get("market_name")
        preference = data.get("preference")
        print(market_name)
        print(preference)
        # preference = "stocks"
        
        if not market_name:
            return jsonify({"message": "Market name is required"}), 400

        # Define filename for storage
        filename = f"{MARKET_ASSETS_FOLDER}{market_name.lower()}_assets.json"
        if USE_AWS:
            assets = load_from_aws(filename)
        else:
            assets = load_from_local(os.path.join(LOCAL_STORAGE_PATH, filename))

        # Fetch updated assets for the market
        
        # updated_assets = fetch_all_stocks_for_market_dynamic(market_name)
        updated_assets = fetch_all_assets_by_preference(market_name,preference)
        
        if not updated_assets:
            return jsonify({"message": f"No data found for the market: {market_name}"}), 404

        # Check if there are new assets
        if not assets or updated_assets != assets:
            # Update the assets list
            if USE_AWS:
                save_to_aws_with_timestamp(updated_assets, filename)
            else:
                save_to_local(updated_assets, os.path.join(LOCAL_STORAGE_PATH, filename))
            message = "Assets list updated successfully"
        else:
            message = "Assets list is up-to-date"

        print(f"\nUpdated Assets :\n{updated_assets}")
        
        return jsonify({
            "message": message,
            "market": market_name,
            "assets": updated_assets
        }), 200

    except Exception as e:
        print(f"Error in market-assets API: {e}")
        return jsonify({"message": f"Internal server error: {e}"}), 500