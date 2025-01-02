# # # Fetch Treasury Bonds

# def fetch_treasury_bonds():
#     try:
#         url = f"https://www.alphavantage.co/query?function=TREASURY_YIELD&interval=monthly&maturity=10year&apikey={ALPHA_VANTAGE_API_KEY}"
#         response = requests.get(url)

#         if response.status_code == 200:
#             data = response.json()
#             if "data" in data:
#                 bonds = []
#                 for item in data["data"]:
#                     maturity_date = item.get("maturityDate", "N/A")
#                     yield_rate = item.get("value", "N/A")
#                     bonds.append({
#                         "name": "10 Year Treasury",
#                         "symbol": "10Y",
#                         "yield": yield_rate,
#                         # "maturity": maturity_date
#                     })
#                 return bonds
#             else:
#                 print("No bond data available.")
#                 return []
#         else:
#             print(f"Alpha Vantage API error: {response.status_code}")
#             return []
#     except Exception as e:
#         print(f"Error fetching Treasury bonds: {e}")
#         return []

# # Fetch Corporate Bonds
# def fetch_corporate_bonds():
#     try:
#         url = f"https://www.alphavantage.co/query?function=CORPORATE_BOND&apikey={ALPHA_VANTAGE_API_KEY}"
#         response = requests.get(url)

#         if response.status_code == 200:
#             data = response.json()
#             if "data" in data:
#                 bonds = [
#                     {
#                         "name": item.get("name", "N/A"),
#                         "symbol": item.get("symbol", "N/A"),
#                         "yield": item.get("yield", "N/A"),
#                         "maturity": item.get("maturityDate", "N/A")
#                     }
#                     for item in data["data"]
#                 ]
#                 return bonds
#             else:
#                 print("No corporate bond data available.")
#                 return []
#         else:
#             print(f"Alpha Vantage API error: {response.status_code}")
#             return []
#     except Exception as e:
#         print(f"Error fetching Corporate bonds: {e}")
#         return []

# # Fetch Mortgage-Related Bonds
# def fetch_mortgage_related_bonds():
#     try:
#         url = f"https://www.alphavantage.co/query?function=MORTGAGE_RELATED_BONDS&apikey={ALPHA_VANTAGE_API_KEY}"
#         response = requests.get(url)

#         if response.status_code == 200:
#             data = response.json()
#             if "data" in data:
#                 bonds = [
#                     {
#                         "name": item.get("name", "N/A"),
#                         "symbol": item.get("symbol", "N/A"),
#                         "yield": item.get("yield", "N/A"),
#                         "maturity": item.get("maturityDate", "N/A")
#                     }
#                     for item in data["data"]
#                 ]
#                 return bonds
#             else:
#                 print("No mortgage-related bond data available.")
#                 return []
#         else:
#             print(f"Alpha Vantage API error: {response.status_code}")
#             return []
#     except Exception as e:
#         print(f"Error fetching Mortgage-Related bonds: {e}")
#         return []

# # Fetch Municipal Bonds
# def fetch_municipal_bonds():
#     try:
#         url = f"https://www.alphavantage.co/query?function=MUNICIPAL_BONDS&apikey={ALPHA_VANTAGE_API_KEY}"
#         response = requests.get(url)

#         if response.status_code == 200:
#             data = response.json()
#             if "data" in data:
#                 bonds = [
#                     {
#                         "name": item.get("name", "N/A"),
#                         "symbol": item.get("symbol", "N/A"),
#                         "yield": item.get("yield", "N/A"),
#                         "maturity": item.get("maturityDate", "N/A")
#                     }
#                     for item in data["data"]
#                 ]
#                 return bonds
#             else:
#                 print("No municipal bond data available.")
#                 return []
#         else:
#             print(f"Alpha Vantage API error: {response.status_code}")
#             return []
#     except Exception as e:
#         print(f"Error fetching Municipal bonds: {e}")
#         return []


# # Fetch Money Market Bonds
# def fetch_money_market_bonds():
#     """
#     Fetch Money Market bond data from Alpha Vantage.
#     """
#     try:
#         url = f"https://www.alphavantage.co/query?function=MONEY_MARKET_BONDS&apikey={ALPHA_VANTAGE_API_KEY}"
#         response = requests.get(url)

#         if response.status_code == 200:
#             data = response.json()
#             if "data" in data:
#                 bonds = [
#                     {
#                         "name": item.get("name", "N/A"),
#                         "symbol": item.get("symbol", "N/A"),
#                         "yield": item.get("yield", "N/A"),
#                         "maturity": item.get("maturityDate", "N/A")
#                     }
#                     for item in data["data"]
#                 ]
#                 return bonds
#             else:
#                 print("No money market bond data available.")
#                 return []
#         else:
#             print(f"Alpha Vantage API error: {response.status_code}")
#             return []
#     except Exception as e:
#         print(f"Error fetching Money Market bonds: {e}")
#         return []

# # API to Fetch Bonds :

# @app.route('/fetch-bonds', methods=['POST'])
# def fetch_bonds():
#     try:
#         data = request.get_json()
#         category = data.get("category")

#         # Map category to functions
#         category_mapping = {
#             "treasury": fetch_treasury_bonds,
#             "corporate": fetch_corporate_bonds,
#             "mortgage": fetch_mortgage_related_bonds,
#             "municipal": fetch_municipal_bonds,
#             "money_market": fetch_money_market_bonds
#         }

#         if category in category_mapping:
#             bonds = category_mapping[category]()
#             return jsonify({"category": category, "bonds": bonds}), 200
#         else:
#             return jsonify({"message": f"Category {category} not recognized."}), 400

#     except Exception as e:
#         print(f"Error in fetch-bonds API: {e}")
#         return jsonify({"message": f"Internal server error: {e}"}), 500
    
    
from flask import Flask, request, jsonify
import requests
import logging

# Flask App Initialization
# app = Flask(__name__)

# Configuration
FRED_API_KEY = "your_fred_api_key"  # Replace with your actual FRED API key
BASE_URL = "https://api.stlouisfed.org/fred/series/observations"

# Define Bond Categories and Their Series IDs
BOND_CATEGORIES = {
    "1_month": "DTB1MO",
    "3_months": "DTB3",
    "6_months": "DTB6",
    "1_year": "DGS1",
    "2_years": "DGS2",
    "5_years": "DGS5",
    "10_years": "DGS10",
    "30_years": "DGS30",
}

# Fetch Bond Yields from FRED API
def fetch_treasury_bond_yields():
    bonds = []
    try:
        for maturity, series_id in BOND_CATEGORIES.items():
            url = f"{BASE_URL}?series_id={series_id}&api_key={FRED_API_KEY}&file_type=json"
            response = requests.get(url)

            if response.status_code == 200:
                data = response.json()
                # Get the most recent observation
                if "observations" in data and data["observations"]:
                    latest_observation = data["observations"][-1]
                    yield_value = latest_observation.get("value", "N/A")
                    observation_date = latest_observation.get("date", "N/A")
                    bonds.append({
                        "name": f"{maturity.replace('_', ' ').title()} Treasury Bond",
                        "maturity": maturity,
                        "yield": yield_value,
                        "date": observation_date,
                    })
            else:
                logging.error(f"Failed to fetch data for {maturity}: {response.status_code}")
    except Exception as e:
        logging.error(f"Error fetching treasury bond yields: {e}")

    return bonds

# Flask Endpoint to Fetch Bond Data
@app.route('/fetch-treasury-bonds', methods=['GET'])
def get_treasury_bonds():
    try:
        bond_data = fetch_treasury_bond_yields()
        if not bond_data:
            return jsonify({"message": "No bond data available"}), 404

        return jsonify({
            "message": "Treasury bond yields fetched successfully",
            "bonds": bond_data
        }), 200
    except Exception as e:
        logging.error(f"Error in /fetch-treasury-bonds API: {e}")
        return jsonify({"message": f"Internal server error: {e}"}), 500


