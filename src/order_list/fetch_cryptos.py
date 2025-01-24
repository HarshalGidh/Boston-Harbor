from utils import libraries

@app.route('/crypto-assets', methods=['POST'])
def fetch_cryptos_from_exchange():
    """
    Fetch the list of cryptocurrencies available on a given exchange.
    Supported exchanges: CoinGecko, Binance, Binance.US, Coincheck.
    """
    try:
        data = request.get_json()
        exchange_name = data.get("exchange_name", "").lower()
        cryptos = []
        #test reits :
        fetch_reits()
        if exchange_name == "coingecko":
            # Fetch data from CoinGecko
            url = "https://api.coingecko.com/api/v3/coins/markets"
            params = {
                "vs_currency": "usd",
                "order": "market_cap_desc",
                "per_page": 250,
                "page": 1,
            }
            response = requests.get(url, params=params)
            if response.status_code == 200:
                data = response.json()
                for coin in data:
                    symbol = coin["symbol"].upper()
                    cryptos.append({"name": coin["name"], "symbol": f"{symbol}-USD" })
                    
                    # if coin["name"] == "Bitcoin" or coin["name"] == "Ethereum":
                    #     symbol = coin["symbol"].upper()
                    #     cryptos.append({"name": coin["name"], "symbol": f"{symbol}-USD" })
                    # else:
                    #     cryptos.append({"name": coin["name"], "symbol": coin["symbol"].upper()})
            else:
                return jsonify({"message": f"Failed to fetch data from CoinGecko: {response.status_code}"}), 500

        elif exchange_name == "binance":
            # Fetch data from Binance
            url = "https://api.binance.com/api/v3/exchangeInfo"
            response = requests.get(url)
            if response.status_code == 200:
                data = response.json()
                for symbol_info in data["symbol"]:
                    base_asset = symbol_info["baseAsset"]
                    quote_asset = symbol_info["quoteAsset"]
                    
                    # if base_asset == 'ETH' or base_asset == 'BTC':
                    if base_asset == 'ETH' or base_asset == 'BTC' or base_asset == 'XRP' or base_asset == 'USDT' or 'BNB' :
                        cryptos.append({
                            "symbol": f"{base_asset}-USD",
                            "name": f"{base_asset}"
                        })
                    elif base_asset == 'ALGO':
                        cryptos.append({
                            "symbol": f"{base_asset}-INR",
                            "name": f"{base_asset}"
                        })
                    else:
                        cryptos.append({
                            "symbol": base_asset,
                            "name": f"{base_asset}"
                        })
            else:
                return jsonify({"message": f"Failed to fetch data from Binance: {response.status_code}"}), 500

        elif exchange_name == "binance.us":
            # Fetch data from Binance.US
            url = "https://api.binance.us/api/v3/exchangeInfo"
            response = requests.get(url)
            if response.status_code == 200:
                data = response.json()
                for symbol_info in data["symbol"]:
                    base_asset = symbol_info["baseAsset"]
                    quote_asset = symbol_info["quoteAsset"]
                    
                    if base_asset == 'ETH' or base_asset == 'BTC' or base_asset == 'XRP' or base_asset == 'USDT' or 'BNB' :
                        cryptos.append({
                            "symbol": f"{base_asset}-USD",
                            "name": f"{base_asset}"
                        })
                    elif base_asset == 'ALGO':
                        cryptos.append({
                            "symbol": f"{base_asset}-INR",
                            "name": f"{base_asset}"
                        })
                    else:
                        cryptos.append({
                            "symbol": base_asset,
                            "name": f"{base_asset}"
                        })
            else:
                return jsonify({"message": f"Failed to fetch data from Binance.US: {response.status_code}"}), 500

        else:
            return jsonify({"message": "Exchange not supported."}), 404

        # Return the list of cryptos
        return jsonify({
            "message": "Cryptos list fetched successfully.",
            "exchange_name": exchange_name,
            "cryptos": cryptos
        }), 200

    except Exception as e:
        return jsonify({"message": f"Internal server error: {e}"}), 500