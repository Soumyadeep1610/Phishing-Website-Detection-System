import requests

s = requests.Session()

# Analyze a URL in this session
post_response = s.post('http://127.0.0.1:5000', data={'url': 'https://example.com'})
print('POST Status:', post_response.status_code)

# Check API again
api_response = s.get('http://127.0.0.1:5000/api/checks')
print('API Status:', api_response.status_code)

if api_response.status_code == 200:
    data = api_response.json()
    print('Number of checks in API:', len(data['checks']))
    for check in data['checks']:
        print(f'ID: {check["id"]}, URL: {check["url"]}, Prediction: {check["prediction"]}, Confidence: {check["confidence"]}%')
