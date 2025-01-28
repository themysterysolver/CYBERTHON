
import requests

# Your API key
api_key = "6ca49bd3-50ff-4a43-acdf-91a954893bf4"

# API endpoint for CVE data
url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Parameters for fetching data
params = {
    "pubStartDate": "2023-01-01T00:00:00.000",
    "pubEndDate": "2023-12-31T23:59:59.999",
    "apiKey": api_key
}

# Function to fetch data from NVD
def fetch_vulnerability_data():
    try:
        response = requests.get(url, params=params)
        
        # Check if the request was successful (status code 200)
        if response.status_code == 200:
            data = response.json()
            print("Data fetched successfully!")
            return data
        else:
            print(f"Failed to fetch data. Status code: {response.status_code}")
            return None
    except Exception as e:
        print(f"Error: {e}")
        return None

# Fetch and print the vulnerability data
vulnerabilities = fetch_vulnerability_data()

if vulnerabilities:
    # You can process the vulnerabilities data here
    # For example, print the first 5 CVEs
    print("Sample CVEs:")
    for cve in vulnerabilities.get("CVE_Items", [])[:5]:
        print(cve["cve"]["CVE_data_meta"]["ID"])

