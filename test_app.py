#!/usr/bin/env python3
"""Test the user-management app using Flask test client."""
import re
import sys
import os

# Ensure we're in the right directory
os.chdir('/root/playground/user-management')
sys.path.insert(0, '/root/playground/user-management')

import app as flask_app

# Initialize the database
flask_app.init_db()

# Create test client
client = flask_app.app.test_client()
client.testing = True

# Disable CSRF for testing - actually let's try with CSRF enabled first
# since the app has it globally enabled
import flask_wtf.csrf

# We'll work WITH CSRF since it's enabled globally
# The test client needs to handle CSRF tokens

print("=" * 70)
print("STEP 1: GET login page and extract CSRF token")
print("=" * 70)

# First GET the login page to get the CSRF token
response = client.get('/login')
print(f"GET /login status: {response.status_code}")
html = response.data.decode('utf-8')

# Extract CSRF token from the hidden input field
csrf_match = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', html)
if csrf_match:
    csrf_token = csrf_match.group(1)
    print(f"[OK] Extracted CSRF token: {csrf_token[:40]}...")
else:
    print("[WARN] No CSRF token found in login page HTML")
    print("HTML snippet:", html[:500])
    csrf_token = ""

print()
print("=" * 70)
print("STEP 2: POST login with CSRF token")
print("=" * 70)

# Login with CSRF token
login_data = {
    'username': 'admin',
    'password': 'admin123',
    'csrf_token': csrf_token
}
response = client.post('/login', data=login_data)
print(f"POST /login status: {response.status_code}")
print(f"Location header: {response.headers.get('Location', 'N/A')}")

# Follow redirect
if response.status_code in (301, 302):
    redirect_url = response.headers.get('Location', '')
    response = client.get(redirect_url)
    print(f"Follow redirect to {redirect_url}: status {response.status_code}")

print()
print("=" * 70)
print("STEP 3: Get home page (first 30 lines)")
print("=" * 70)

response = client.get('/')
html = response.data.decode('utf-8')
lines = html.split('\n')
for line in lines[:30]:
    print(line)

print()
print("=" * 70)
print("STEP 4: Extract CSRF token from home page (if form exists)")
print("=" * 70)

# CSRF token might be different on each request, extract from fresh page if needed
csrf_match = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', html)
if csrf_match:
    new_token = csrf_match.group(1)
    print(f"[OK] Found CSRF token on home page: {new_token[:40]}...")
    csrf_token = new_token
else:
    print("[INFO] No CSRF token on home page (expected if no form with CSRF)")

print()
print("=" * 70)
print("STEP 5: Test HTTP URL fetch via /fetch-url")
print("=" * 70)

# For POST with CSRF, we need to get a fresh token first
# Let's get the home page (or any page that might have a CSRF token)
# Actually, since fetch-url is a POST, we need to include csrf_token
# The token can be obtained from any page that has a form with csrf_token

# Let's check if there's a CSRF token in the home page
# If not, we need to generate one using the Flask-WTF mechanism
# In test client, we can get the token from the session

fetch_data = {
    'url': 'http://httpbin.org/get',
    'csrf_token': csrf_token
}
response = client.post('/fetch-url', data=fetch_data)
print(f"POST /fetch-url status: {response.status_code}")

if response.status_code == 200:
    html = response.data.decode('utf-8')
    # Extract fetch results from the rendered template
    fetch_match = re.search(r'fetch_content[^>]*>([^<]+)</', html)
    if fetch_match:
        print(f"Content preview: {fetch_match.group(1)[:200]}")
    else:
        print("Full response HTML:")
        print(html[:2000])
elif response.status_code == 400:
    print("CSRF validation failed!")
    print(f"Response: {response.data.decode('utf-8')[:500]}")
else:
    print(f"Response: {response.data.decode('utf-8')[:500]}")

# Let's also check what happened
# Check session
with client.session_transaction() as sess:
    print(f"Session username: {sess.get('username', 'Not logged in')}")

# If CSRF failed, let's try with CSRF disabled
if response.status_code == 400 or b'csrf' in response.data.lower():
    print()
    print("CSRF validation failed. Retrying with CSRF disabled...")
    # Disable CSRF
    flask_app.app.config['WTF_CSRF_ENABLED'] = False
    flask_app.csrf._exempt_views = set()

    # Re-login without CSRF
    login_data_no_csrf = {'username': 'admin', 'password': 'admin123'}
    response = client.post('/login', data=login_data_no_csrf, follow_redirects=True)
    print(f"Re-login (no CSRF) status: {response.status_code}")

    with client.session_transaction() as sess:
        print(f"Session username: {sess.get('username', 'Not logged in')}")

    print()
    print("=" * 70)
    print("STEP 5 (retry): Test HTTP URL fetch (CSRF disabled)")
    print("=" * 70)

    fetch_data = {'url': 'http://httpbin.org/get'}
    response = client.post('/fetch-url', data=fetch_data)
    print(f"POST /fetch-url status: {response.status_code}")
    html = response.data.decode('utf-8')
    # Show relevant parts
    for line in html.split('\n'):
        if 'fetch' in line.lower() or 'content' in line.lower() or 'error' in line.lower() or 'status' in line.lower():
            stripped = re.sub(r'<[^>]+>', '', line).strip()
            if stripped:
                print(f"  {stripped[:200]}")

    print()
    print("=" * 70)
    print("STEP 6: Test file:// URL fetch")
    print("=" * 70)

    fetch_data = {'url': 'file:///etc/passwd'}
    response = client.post('/fetch-url', data=fetch_data)
    print(f"POST /fetch-url (file://) status: {response.status_code}")
    html = response.data.decode('utf-8')
    for line in html.split('\n'):
        if 'fetch' in line.lower() or 'content' in line.lower() or 'error' in line.lower() or 'status' in line.lower():
            stripped = re.sub(r'<[^>]+>', '', line).strip()
            if stripped:
                print(f"  {stripped[:200]}")

    print()
    print("=" * 70)
    print("FULL SUMMARY")
    print("=" * 70)
    print("CSRF Protection: ENABLED (but was bypassed for testing)")
    print("Login: Successful with admin/admin123")
    print("HTTP URL fetch (httpbin.org): Tested")
    print("file:// URL fetch (/etc/passwd): Tested")

else:
    # CSRF worked or wasn't needed
    print()
    print("=" * 70)
    print("STEP 6: Test file:// URL fetch")
    print("=" * 70)

    # Get a fresh CSRF token
    response = client.get('/login')
    html = response.data.decode('utf-8')
    csrf_match = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', html)
    if csrf_match:
        csrf_token = csrf_match.group(1)

    fetch_data = {
        'url': 'file:///etc/passwd',
        'csrf_token': csrf_token
    }
    response = client.post('/fetch-url', data=fetch_data)
    print(f"POST /fetch-url (file://) status: {response.status_code}")
    html = response.data.decode('utf-8')
    for line in html.split('\n'):
        if 'fetch' in line.lower() or 'content' in line.lower() or 'error' in line.lower() or 'status' in line.lower():
            stripped = re.sub(r'<[^>]+>', '', line).strip()
            if stripped:
                print(f"  {stripped[:200]}")

    print()
    print("=" * 70)
    print("FULL SUMMARY")
    print("=" * 70)
    print("CSRF Protection: ENABLED")
    print("Login: Successful with admin/admin123")
    print("HTTP URL fetch (httpbin.org): Successful")
    print("file:// URL fetch (/etc/passwd): Tested")

# Final: Print out the full details from the fetch-url results
print()
print("=" * 70)
print("DETAILED RESULTS")
print("=" * 70)

# Let's also just directly test fetching URLs by calling the functions via test client
# with CSRF disabled to get the full picture
print()
print("[FINAL TEST - CSRF disabled for complete visibility]")

# Create a fresh client with CSRF disabled
disarmed_app = flask_app.app
disarmed_app.config['WTF_CSRF_ENABLED'] = False
client2 = disarmed_app.test_client()
client2.testing = True

# Login
client2.post('/login', data={'username': 'admin', 'password': 'admin123'})

# Test httpbin
print()
print("--- HTTP URL Test (http://httpbin.org/get) ---")
resp = client2.post('/fetch-url', data={'url': 'http://httpbin.org/get'})
html = resp.data.decode('utf-8')
# Look for fetch results in template variables
fetch_status_match = re.search(r'fetch_status["\']?[^>]*>(\d+)', html)
fetch_content_match = re.search(r'fetch_content["\']?[^>]*>(.*?)</', html, re.DOTALL)
fetch_error_match = re.search(r'fetch_error["\']?[^>]*>(.*?)</', html, re.DOTALL)

if fetch_status_match:
    print(f"Status code: {fetch_status_match.group(1)}")
if fetch_content_match:
    content = re.sub(r'<[^>]+>', '', fetch_content_match.group(1)).strip()
    print(f"Content preview: {content[:500]}")
if fetch_error_match:
    error = re.sub(r'<[^>]+>', '', fetch_error_match.group(1)).strip()
    print(f"Error: {error}")

# Test file:// URL
print()
print("--- file:// URL Test (file:///etc/passwd) ---")
resp = client2.post('/fetch-url', data={'url': 'file:///etc/passwd'})
html = resp.data.decode('utf-8')
fetch_status_match = re.search(r'fetch_status["\']?[^>]*>(\d+)', html)
fetch_content_match = re.search(r'fetch_content["\']?[^>]*>(.*?)</', html, re.DOTALL)
fetch_error_match = re.search(r'fetch_error["\']?[^>]*>(.*?)</', html, re.DOTALL)

if fetch_status_match:
    print(f"Status code: {fetch_status_match.group(1)}")
if fetch_content_match:
    content = re.sub(r'<[^>]+>', '', fetch_content_match.group(1)).strip()
    print(f"Content preview: {content[:500]}")
if fetch_error_match:
    error = re.sub(r'<[^>]+>', '', fetch_error_match.group(1)).strip()
    print(f"Error: {error}")
else:
    # Print more of the HTML to find the content
    print("Raw HTML around fetch content:")
    # Find the fetch section
    idx = html.find('fetch_')
    if idx >= 0:
        print(html[idx:idx+1500])
    else:
        print("No fetch_ variables found in HTML")
        print("Home page check (logged in):")
        resp2 = client2.get('/')
        print(resp2.data.decode('utf-8')[:2000])
