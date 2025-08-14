import os
import json
from flask import Flask, redirect, url_for, session, request, render_template, jsonify
from flask_session import Session
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from datetime import datetime, timedelta
 
import csv
from collections import Counter
 
 

app = Flask("Gmail Cleanup")
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'devkey')
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

# Google OAuth2 setup
CLIENT_SECRETS_FILE = "credentials.json"
SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]

REDIRECT_URI = os.environ.get('OAUTH_REDIRECT_URI', 'http://localhost:5000/oauth2callback')

# Health check route for Cloud Run
@app.route('/healthz')
def healthz():
    return "ok", 200

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


# For Gunicorn, expose 'app' at module level
# For local dev, run Flask directly
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port)

# --- Utility Functions from Standalone Scripts ---
def archive_brand_emails(service, start_date, end_date, brands=None):
    if brands is None:
        brands = [
            'nike.com', 'amazon.com', 'walmart.com', 'starbucks.com', 'apple.com', 'microsoft.com', 'google.com', 'facebookmail.com',
            'adidas.com', 'target.com', 'bestbuy.com', 'costco.com', 'lowes.com', 'homedepot.com', 'macys.com', 'kohls.com',
            'sephora.com', 'ulta.com', 'gap.com', 'oldnavy.com', 'bananarepublic.com', 'jcrew.com', 'express.com', 'abercrombie.com',
            'hollisterco.com', 'forever21.com', 'hm.com', 'zara.com', 'uniqlo.com', 'underarmour.com', 'puma.com', 'reebok.com',
            'samsung.com', 'sony.com', 'dell.com', 'hp.com', 'lenovo.com', 'asus.com', 'acer.com', 'nordstrom.com',
            'bloomingdales.com', 'saks.com', 'neimanmarcus.com', 'tjmaxx.com', 'marshalls.com', 'rossstores.com', 'bedbathandbeyond.com',
            'wayfair.com', 'overstock.com', 'ikea.com', 'anthropologie.com', 'urbanoutfitters.com', 'freepeople.com', 'patagonia.com',
            'columbia.com', 'timberland.com', 'vans.com', 'converse.com', 'crocs.com', 'drmartens.com', 'newbalance.com',
            'footlocker.com', 'finishline.com', 'dsw.com', 'zappos.com', 'ebay.com', 'etsy.com', 'shopify.com', 'paypal.com',
            'chase.com', 'bankofamerica.com', 'wellsfargo.com', 'citi.com', 'americanexpress.com', 'capitalone.com', 'discover.com',
            'td.com', 'usbank.com', 'pnc.com', 'ally.com', 'fidelity.com', 'vanguard.com', 'charlesSchwab.com', 'robinhood.com',
            'netflix.com', 'hulu.com', 'disneyplus.com', 'hbomax.com', 'paramountplus.com', 'peacocktv.com', 'spotify.com',
            'pandora.com', 'siriusxm.com', 'comcast.com', 'verizon.com', 'att.com', 't-mobile.com', 'sprint.com', 'boostmobile.com',
            'cricketwireless.com', 'metrobyt-mobile.com', 'dish.com', 'directv.com', 'spectrum.com', 'xfinity.com', 'centurylink.com',
            'statefarm.com', 'geico.com', 'progressive.com', 'allstate.com', 'libertymutual.com', 'nationwide.com', 'travelers.com',
            'farmers.com', 'usaa.com', 'aaa.com', 'aetna.com', 'cvs.com', 'walgreens.com', 'riteaid.com', 'humana.com', 'unitedhealthgroup.com',
            'anthem.com', 'kaiserpermanente.org', 'bluecross.com', 'bcbs.com', 'delta.com', 'united.com', 'americanairlines.com', 'southwest.com',
            'jetblue.com', 'alaskaair.com', 'spirit.com', 'frontier.com', 'booking.com', 'expedia.com', 'hotels.com', 'airbnb.com', 'tripadvisor.com',
            'lyft.com', 'uber.com', 'doordash.com', 'grubhub.com', 'postmates.com', 'instacart.com', 'shipt.com', 'ubereats.com', 'seamless.com',
            'opentable.com', 'yelp.com', 'groupon.com', 'livingsocial.com', 'ticketmaster.com', 'stubhub.com', 'eventbrite.com', 'fandango.com',
            'amtrak.com', 'greyhound.com', 'enterprise.com', 'hertz.com', 'avis.com', 'budget.com', 'nationalcar.com', 'alamo.com', 'thrifty.com',
            'dollar.com', 'sixt.com', 'costar.com', 'redfin.com', 'zillow.com', 'realtor.com', 'trulia.com', 'homes.com', 'apartments.com',
            'indeed.com', 'linkedin.com', 'glassdoor.com', 'monster.com', 'ziprecruiter.com', 'careerbuilder.com', 'simplyhired.com', 'dice.com',
            'github.com', 'gitlab.com', 'bitbucket.org', 'slack.com', 'zoom.us', 'dropbox.com', 'box.com', 'onedrive.com', 'icloud.com',
            'mailchimp.com', 'constantcontact.com', 'sendgrid.com', 'campaignmonitor.com', 'getresponse.com', 'aweber.com', 'convertkit.com',
            'activecampaign.com', 'klaviyo.com', 'shop.com', 'qvc.com', 'hsn.com', 'costco.com', 'bj.com', 'samsclub.com', 'aldi.us', 'traderjoes.com',
            'wholefoods.com', 'publix.com', 'kroger.com', 'safeway.com', 'meijer.com', 'wegmans.com', 'giantfood.com', 'stopandshop.com', 'foodlion.com',
            'winndixie.com', 'harristeeter.com', 'supervalu.com', 'savealot.com', 'freshdirect.com', 'peapod.com', 'boxed.com', 'thriveMarket.com',
            'vitacost.com', 'swansonvitamins.com', 'gnc.com', 'bodybuilding.com', 'iherb.com', 'luckyvitamin.com', 'puritan.com', 'walgreens.com',
            'riteaid.com', 'cvs.com', 'boots.com', 'superdrug.com', 'sears.com', 'kmart.com', 'acehardware.com', 'truevalue.com', 'doitbest.com',
            'harborfreight.com', 'grainger.com', 'fastenal.com', 'napaonline.com', 'autozone.com', 'advanceautoparts.com', 'oreillyauto.com',
            'pepboys.com', 'carmax.com', 'cars.com', 'autotrader.com', 'edmunds.com', 'carvana.com', 'vroom.com', 'shift.com', 'carfax.com',
            'progressive.com', 'geico.com', 'statefarm.com', 'allstate.com', 'libertymutual.com', 'nationwide.com', 'travelers.com', 'farmers.com',
            'usaa.com', 'aaa.com', 'aetna.com', 'cvs.com', 'walgreens.com', 'riteaid.com', 'humana.com', 'unitedhealthgroup.com', 'anthem.com',
            'kaiserpermanente.org', 'bluecross.com', 'bcbs.com'
        ]
    brand_query = ' OR '.join([f'from:{brand}' for brand in brands])
    date_query = f'after:{start_date} before:{end_date}'
    query = f'{brand_query} {date_query}'
    user_id = 'me'
    trashed_count = 0
    next_page_token = None
    while True:
        results = service.users().messages().list(userId=user_id, q=query, pageToken=next_page_token).execute()
        messages = results.get('messages', [])
        if not messages:
            break
        for msg in messages:
            service.users().messages().trash(userId=user_id, id=msg['id']).execute()
            trashed_count += 1
        next_page_token = results.get('nextPageToken')
        if not next_page_token:
            break
    return trashed_count

def bucket_emails_by_domain(service, after, before, max_results=10000):
    user_id = 'me'
    next_page_token = None
    domain_counter = Counter()
    processed = 0
    query = f'after:{after} before:{before}'
    while True:
        results = service.users().messages().list(userId=user_id, labelIds=['INBOX'], q=query, maxResults=500, pageToken=next_page_token).execute()
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
                domain_counter[domain] += 1
            processed += 1
            if processed >= max_results:
                break
        next_page_token = results.get('nextPageToken')
        if not next_page_token or processed >= max_results:
            break
    return domain_counter

def delete_top_domains(service, top_n=10, before='2025/01/01', csv_file='email_domain_buckets.csv'):
    domains = []
    try:
        with open(csv_file, newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for i, row in enumerate(reader):
                if i >= top_n:
                    break
                domains.append(row['domain'])
    except Exception as e:
        return {'error': str(e)}
    user_id = 'me'
    total_deleted = 0
    for domain in domains:
        query = f'from:@{domain} before:{before}'
        next_page_token = None
        while True:
            results = service.users().messages().list(userId=user_id, q=query, pageToken=next_page_token).execute()
            messages = results.get('messages', [])
            if not messages:
                break
            for msg in messages:
                service.users().messages().trash(userId=user_id, id=msg['id']).execute()
                total_deleted += 1
            next_page_token = results.get('nextPageToken')
            if not next_page_token:
                break
    return {'deleted': total_deleted, 'domains': domains}

# --- New API Endpoints ---
@app.route('/api/archive-brands', methods=['POST'])
def api_archive_brands():
    if 'credentials' not in session:
        return jsonify({'error': 'Not authorized'}), 401
    data = request.json
    start_date = data.get('start_date', '2017/01/01')
    end_date = data.get('end_date', '2023/12/31')
    brands = data.get('brands')
    creds = Credentials(**session['credentials'])
    service = build('gmail', 'v1', credentials=creds)
    count = archive_brand_emails(service, start_date, end_date, brands)
    return jsonify({'status': 'done', 'archived': count})

@app.route('/api/bucket-domains', methods=['POST'])
def api_bucket_domains():
    if 'credentials' not in session:
        return jsonify({'error': 'Not authorized'}), 401
    data = request.json
    after = data.get('after', '2024/01/01')
    before = data.get('before', '2024/12/31')
    creds = Credentials(**session['credentials'])
    service = build('gmail', 'v1', credentials=creds)
    buckets = bucket_emails_by_domain(service, after, before)
    # Optionally save to CSV
    try:
        with open('email_domain_buckets.csv', 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['domain', 'count'])
            for domain, count in buckets.most_common():
                writer.writerow([domain, count])
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    return jsonify(dict(buckets))

@app.route('/api/delete-top-domains', methods=['POST'])
def api_delete_top_domains():
    if 'credentials' not in session:
        return jsonify({'error': 'Not authorized'}), 401
    data = request.json
    top_n = int(data.get('top_n', 10))
    before = data.get('before', '2025/01/01')
    csv_file = data.get('csv_file', 'email_domain_buckets.csv')
    creds = Credentials(**session['credentials'])
    service = build('gmail', 'v1', credentials=creds)
    result = delete_top_domains(service, top_n, before, csv_file)
    return jsonify(result)

# For Gunicorn, expose 'app' at module level
# For local dev, run Flask directly
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port, debug=True)
