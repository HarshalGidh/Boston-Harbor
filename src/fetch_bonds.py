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
    
##################################################################################################

import requests
from bs4 import BeautifulSoup

def fetch_bonds_from_yahoo():
    """
    Fetch bonds data from Yahoo Finance.
    Returns a dictionary with lists of bonds for each category.
    """
    try:
        url = "https://finance.yahoo.com/markets/bonds/"
        response = requests.get(url)
        if response.status_code != 200:
            print(f"Failed to fetch bonds page. Status code: {response.status_code}")
            return {}

        soup = BeautifulSoup(response.content, "html.parser")

        bond_categories = {
            "treasury": "Treasury Bonds",
            "corporate": "Corporate Bonds",
            "municipal": "Municipal Bonds",
            "money_market": "Money Market",
        }
        bond_data = {}

        # Parse bonds for each category
        for category, section_name in bond_categories.items():
            section = soup.find("section", {"aria-label": section_name})
            if not section:
                print(f"No data found for {section_name}.")
                bond_data[category] = []
                continue

            table = section.find("table")
            if not table:
                print(f"No table found for {section_name}.")
                bond_data[category] = []
                continue

            rows = table.find_all("tr")[1:]  # Skip header row
            bonds = []
            for row in rows:
                cols = row.find_all("td")
                if len(cols) < 3:
                    continue
                symbol = cols[0].text.strip()
                name = cols[1].text.strip()
                price = cols[2].text.strip() if len(cols) > 2 else "N/A"
                yield_rate = cols[3].text.strip() if len(cols) > 3 else "N/A"

                bonds.append({
                    "symbol": symbol,
                    "name": name,
                    "price": price,
                    "yield": yield_rate,
                })
            bond_data[category] = bonds

        return bond_data

    except Exception as e:
        print(f"Error fetching bonds: {e}")
        return {}

# Example usage
if __name__ == "__main__":
    bonds = fetch_bonds_from_yahoo()
    for category, bond_list in bonds.items():
        print(f"\n{category.capitalize()} Bonds:")
        for bond in bond_list:
            print(bond)
            
    



