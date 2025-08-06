import os
import json
from flask import Flask, redirect, url_for, session, request, render_template, jsonify
from flask_session import Session
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from datetime import datetime, timedelta

app = Flask("Gmail Cleanup")
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'devkey')
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

# Google OAuth2 setup
CLIENT_SECRETS_FILE = "credentials.json"
SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]
REDIRECT_URI = "http://localhost:5000/oauth2callback"

@app.route('/')
def index():
    if 'credentials' not in session:
        return render_template('index.html', authorized=False)
    return render_template('index.html', authorized=True)

@app.route('/login')
def login():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI
    )
    session.permanent = True  # Help keep session alive
    auth_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true'
    )
    session['state'] = state
    return redirect(auth_url)

@app.route('/oauth2callback')
def oauth2callback():
    if 'state' not in session:
        return "Session expired or invalid. Please <a href='/login'>try logging in again</a>.", 400
    state = session['state']
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        state=state,
        redirect_uri=REDIRECT_URI
    )
    flow.fetch_token(authorization_response=request.url)
    credentials = flow.credentials
    session['credentials'] = {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# API: Get top domains
@app.route('/api/top-domains')
def api_top_domains():
    if 'credentials' not in session:
        return jsonify({'error': 'Not authorized'}), 401
    creds = Credentials(**session['credentials'])
    service = build('gmail', 'v1', credentials=creds)
    user_id = 'me'
    after = request.args.get('after', (datetime.now() - timedelta(days=365)).strftime('%Y/%m/%d'))
    before = request.args.get('before', datetime.now().strftime('%Y/%m/%d'))
    query = f"after:{after} before:{before}"
    next_page_token = None
    domain_counts = {}
    processed = 0
    while True:
        results = service.users().messages().list(userId=user_id, q=query, maxResults=200, pageToken=next_page_token).execute()
        messages = results.get('messages', [])
        if not messages:
            break
        for msg in messages:
            msg_detail = service.users().messages().get(userId=user_id, id=msg['id'], format='metadata', metadataHeaders=['From']).execute()
            headers = msg_detail.get('payload', {}).get('headers', [])
            sender = next((h['value'] for h in headers if h['name'] == 'From'), None)
            if sender:
                if '<' in sender and '>' in sender:
                    email = sender.split('<')[1].split('>')[0]
                else:
                    email = sender
                domain = email.split('@')[-1].lower().strip()
                domain_counts[domain] = domain_counts.get(domain, 0) + 1
            processed += 1
        next_page_token = results.get('nextPageToken')
        if not next_page_token or processed > 2000:
            break
    sorted_domains = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)
    return jsonify(sorted_domains)

# API: Delete/archive by domain
@app.route('/api/clean', methods=['POST'])
def api_clean():
    if 'credentials' not in session:
        return jsonify({'error': 'Not authorized'}), 401
    data = request.json
    domains = data.get('domains', [])
    after = data.get('after')
    before = data.get('before')
    action = data.get('action', 'trash')
    creds = Credentials(**session['credentials'])
    service = build('gmail', 'v1', credentials=creds)
    user_id = 'me'
    total = 0
    for domain in domains:
        query = f"from:@{domain} after:{after} before:{before}"
        next_page_token = None
        while True:
            results = service.users().messages().list(userId=user_id, q=query, maxResults=200, pageToken=next_page_token).execute()
            messages = results.get('messages', [])
            if not messages:
                break
            for msg in messages:
                if action == 'trash':
                    service.users().messages().trash(userId=user_id, id=msg['id']).execute()
                else:
                    service.users().messages().modify(userId=user_id, id=msg['id'], body={'removeLabelIds': ['INBOX']}).execute()
                total += 1
            next_page_token = results.get('nextPageToken')
            if not next_page_token:
                break
    return jsonify({'status': 'done', 'total': total})

if __name__ == '__main__':
    app.run(debug=True)