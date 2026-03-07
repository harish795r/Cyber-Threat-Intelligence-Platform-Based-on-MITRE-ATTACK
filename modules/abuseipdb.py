import requests

API_KEY = "d39b358822350d36b4542520f38b0d745611c379f8e767c4a82ed9ed65c934136fba3fc23aab9b7c"

def check_ip(ip):

    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Key": API_KEY,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    try:
        response = requests.get(url, headers=headers, params=params)

        if response.status_code == 200:
            return response.json()
            

        return None

    except Exception as e:
        print("AbuseIPDB Error:", e)
        return None