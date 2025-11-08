import requests

s = requests.Session()

# Analyze a URL
post_response = s.post('http://127.0.0.1:5000', data={'url': 'https://google.com'})
print('POST Status:', post_response.status_code)

# Check dashboard
dashboard_response = s.get('http://127.0.0.1:5000/dashboard')
print('Dashboard Status:', dashboard_response.status_code)

if dashboard_response.status_code == 200:
    content = dashboard_response.text
    if 'stat-value total' in content:
        print('Stats section found')
        import re
        total_match = re.search(r'class="stat-value total">(\d+)</div>', content)
        if total_match:
            print('Total checks in dashboard:', total_match.group(1))
        phishing_match = re.search(r'class="stat-value phishing">(\d+)</div>', content)
        if phishing_match:
            print('Phishing checks in dashboard:', phishing_match.group(1))
        safe_match = re.search(r'class="stat-value safe">(\d+)</div>', content)
        if safe_match:
            print('Safe checks in dashboard:', safe_match.group(1))
    else:
        print('Stats section not found')
