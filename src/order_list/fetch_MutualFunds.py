from utils import libraries
# Function to fetch the latest price
def fetch_price(ticker):
    """
    Fetch the latest price of a mutual fund using Yahoo Finance.
    :param ticker: The symbol of the mutual fund.
    :return: The latest closing price or "Price not available".
    """
    try:
        # Fetch data for the mutual fund with valid period and interval
        data = yf.download(ticker, period="1mo", interval="1d")
        if not data.empty:
            # Get the latest closing price
            return round(data['Close'].iloc[-1], 2)
        else:
            return "Price not available"
    except Exception as e:
        print(f"Error fetching data for ticker {ticker}: {e}")
        return "Price not available"

def fetch_mutual_funds_from_yahoo():
    """
    Fetch a list of mutual funds and their prices from Yahoo Finance's Mutual Funds Gainers page.
    :return: List of mutual funds with symbol, name, and price.
    """
    try:
        url = "https://finance.yahoo.com/markets/mutualfunds/gainers/"
        response = requests.get(url)
        if response.status_code != 200:
            print(f"Failed to fetch Yahoo Finance page. Status code: {response.status_code}")
            return []

        soup = BeautifulSoup(response.content, "html.parser")
        table = soup.find("table")  # Locate the main table with mutual fund data

        if not table:
            print("No table found on the Yahoo Finance page.")
            return []

        rows = table.find_all("tr")[1:]  # Skip the header row
        mutual_funds = []

        for row in rows:
            cols = row.find_all("td")
            if len(cols) < 3:  # Ensure required columns are present
                continue

            symbol = cols[0].text.strip()
            name = cols[1].text.strip()
            price = fetch_price(symbol)  # Fetch the price dynamically

            # Skip mutual funds where the price is not available
            if price == "Price not available":
                continue

            mutual_funds.append({
                "symbol": symbol,
                "name": name,
                "price": price
            })

        return mutual_funds

    except Exception as e:
        print(f"Error fetching mutual funds from Yahoo Finance: {e}")
        return []

# Endpoint to fetch mutual funds
@app.route('/fetch-MutualFunds', methods=['POST'])
def fetch_MutualFunds():
    """
    Fetch and return mutual funds and their details.
    """
    try:
        mutual_funds = fetch_mutual_funds_from_yahoo()

        print(f"Mutual funds: {mutual_funds}")
        return jsonify({
            "message": "Mutual funds fetched successfully.",
            "mutual_funds": mutual_funds
        }), 200

    except Exception as e:
        print(f"Failed to fetch mutual funds: {e}")
        return jsonify({"error": "Failed to fetch mutual funds"}), 500