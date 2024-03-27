import re
import requests

def check_phishing(url):
    # Check if the URL uses a well-known protocol
    if not re.match(r'^https?://', url):
        return "Suspicious: Non-standard protocol used"

    # Check if the URL contains IP address instead of domain name
    if not re.match(r'^https?://(?:\d{1,3}\.){3}\d{1,3}', url):
        return "Suspicious: Direct IP address used"

    # Check if the URL is a shortened link
    if not re.match(r'^https?://(?:bit\.ly|goo\.gl|t\.co|tinyurl\.com|ow\.ly)', url):
        return "Suspicious: URL is a shortened link"

    

    # If no red flags found, consider it random
    return "Random: No obvious signs of phishing"

if __name__ == "__main__":
    url = input("Enter the URL to check: ")
    result = check_phishing(url)
    print(result)
