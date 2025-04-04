from flask import Flask, render_template, request, jsonify
import requests
import time                                                     #https://paypa1.com/  
                                                                #https://faceb00k.com/
                                                                

app = Flask(__name__)

# API Keys (Replace with your actual keys)
GOOGLE_SAFE_BROWSING_API_KEY = "AIzaSyB1NATbOoXh_0aPuGSR_L3h4yUjEhC5H-o"
VIRUSTOTAL_API_KEY = "77a89d6b7edbb7340eb6c879042931e3c243eecdfab4bc76034bbb30f81da23e"

def check_google_safe_browsing(url):
    """Check URL against Google Safe Browsing API with detailed reasons"""
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}"
    payload = {
        "client": {"clientId": "phishing-detector", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    response = requests.post(api_url, json=payload)
    response_data = response.json()

    if "matches" in response_data:
        threats = [match["threatType"] for match in response_data["matches"]]
        threat_list = ", ".join(threats)
        return f"🚨 This site is **dangerous due to: {threat_list}. Avoid clicking!"
    
    return "✅ This link looks Safe, but scanning in deep!"

def check_virustotal(url):
    """Check URL against VirusTotal API and provide scan details"""
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    data = {"url": url}

    # Submit URL for scanning
    response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=data)
    
    if response.status_code == 200:
        url_id = response.json()["data"]["id"]
        time.sleep(5)  # Wait for VirusTotal to process the request

        # Get report
        report_response = requests.get(f"https://www.virustotal.com/api/v3/analyses/{url_id}", headers=headers)
        report_data = report_response.json()

        if "data" in report_data and "attributes" in report_data["data"]:
            stats = report_data["data"]["attributes"]["stats"]
            malicious_count = stats.get("malicious", 0)
            suspicious_count = stats.get("suspicious", 0)

            if malicious_count > 0 or suspicious_count > 0:
                return f"🚨 {malicious_count} security vendors flagged this site as malicious. Avoid clicking!"
            else:
                return "✅ VirusTotal scan shows No Threats Detected."

    return "⚠️ Error checking URL. Try again later."

@app.route("/")
def index():
    return render_template("demo.html")

@app.route("/chat", methods=["POST"])
def chat():
    user_input = request.form.get("message").strip()  # Get user input
    
    if not user_input:  # Check if input is empty
        return jsonify({"response": "⚠️ Please enter a valid message."})

    if user_input.startswith("http"):  # If input is a URL
        google_result = check_google_safe_browsing(user_input)
        virustotal_result = check_virustotal(user_input)

        # Simulate processing delay
        time.sleep(1.5)

        # Determine Threat Confidence Level
        confidence = "✅ No Risk"
        if "Malicious" in google_result or "flagged" in virustotal_result:
            confidence = "⚠️ Medium Risk"
        if "dangerous" in google_result or "multiple vendors" in virustotal_result:
            confidence = "🚨 High Risk!"

        response_text = (
            f"🔍 **Google Safe Browsing:**\n{google_result}\n\n"
            f"🛡 **VirusTotal Scan:**\n{virustotal_result}\n\n"
            f"⚖ **Threat Confidence Level:** {confidence}\n\n"
            f"🔎 *Tip: Always check if the site has HTTPS & avoid links from unknown emails.*"
        )
    else:
        response_text = (
            "🤖 **I analyze website links for security threats.**\n"
            "🔗 Please enter a valid URL (e.g., `http://example.com`)."
        )

    return jsonify({"response": response_text})  # Return response correctly aligned


if __name__ == "__main__":
    app.run(debug=True)









