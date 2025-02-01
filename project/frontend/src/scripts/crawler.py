import requests
from bs4 import BeautifulSoup
import json

# ScraperAPI configuration
url = "https://github.com/themysterysolver/"
api_key = "91045424b0c6c13022708dba62919440"  # Replace with your ScraperAPI key

# Fetch the HTML content of the page
response = requests.get(f"http://api.scraperapi.com?api_key={api_key}&url={url}")

if response.status_code == 200:
    # Parse the HTML content using BeautifulSoup
    soup = BeautifulSoup(response.text, 'html.parser')

    # Extract all sublinks (e.g., <a>, <button>, <form>)
    sublinks = []

    # 1. Extract all <a> tags (hyperlinks)
    for link in soup.find_all('a', href=True):
        sublinks.append(("link", link['href']))

    # 2. Extract all <button> tags that might lead to another page
    for button in soup.find_all('button'):
        if button.get('onclick') or button.get('data-url'):
            sublinks.append(("button", button.get('onclick') or button.get('data-url')))

    # 3. Extract all <form> tags (forms that submit to another page)
    for form in soup.find_all('form', action=True):
        sublinks.append(("form", form['action']))
    sublinks_json = json.dumps(sublinks, indent=4)
    print(sublinks_json)
else:
    print(f"Failed to fetch the page. Status code: {response.status_code}")