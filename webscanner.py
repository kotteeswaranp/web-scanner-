import requests
from bs4 import BeautifulSoup

class SQLInjectionModule:
    def __init__(self, target_url):
        self.target_url = target_url
        self.test_payloads = ["'", "' OR '1'='1", "' OR '1'='1' --"]

    def scan(self):
        # Get all forms from the target URL
        response = requests.get(self.target_url)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')

        for form in forms:
            form_details = self.get_form_details(form)
            for payload in self.test_payloads:
                self.test_payload_injection(form_details, payload)

    def get_form_details(self, form):
        # Extract form details
        details = {}
        action = form.attrs.get("action").lower()
        method = form.attrs.get("method", "get").lower()
        inputs = []

        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name")
            inputs.append({"type": input_type, "name": input_name})

        details["action"] = action
        details["method"] = method
        details["inputs"] = inputs
        return details

    def test_payload_injection(self, form_details, payload):
        # Test the form with the payload
        url = urljoin(self.target_url, form_details["action"])
        data = {}

        for input in form_details["inputs"]:
            if input["type"] == "text":
                data[input["name"]] = payload

        if form_details["method"] == "post":
            # Perform POST request
            response = requests.post(url, data=data)
        else:
            # Perform GET request
            response = requests.get(url, params=data)

        # Analyze the response for potential vulnerabilities
        # (e.g., check for error messages, unexpected behavior)
        # You can customize this part based on your needs.

# Example usage:
target_url = "https://example.com"
scanner = SQLInjectionModule(target_url)
scanner.scan()
