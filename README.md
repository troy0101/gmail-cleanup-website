# Gmail Cleanup Web App

A Flask web app to analyze and clean up your Gmail inbox by domain, with Google OAuth login.

## Features
- Google OAuth login (per user)
- View top sender domains
- Delete or archive emails by domain and date range
- Modern Bootstrap UI

## Setup
1. **Clone this repo**
2. **Create your own Google OAuth credentials**
   - Go to [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
   - Create OAuth client ID (Desktop or Web)
   - Add `http://localhost:5000/oauth2callback` to Authorized redirect URIs
   - Download `credentials.json` and place it in this folder (DO NOT commit it)
3. **Install dependencies**
   ```sh
   pip install -r requirements.txt
   ```
4. **Run locally** (Windows PowerShell):
   ```powershell
   $env:OAUTHLIB_INSECURE_TRANSPORT=1; cd gmail_web_cleaner; set FLASK_APP=app.py; python -m flask run --debug --host=127.0.0.1 --port=5000
   ```
5. **Open** [http://localhost:5000](http://localhost:5000) in your browser

## Security
- Never commit your `credentials.json` to GitHub.
- For production, use HTTPS and update your Google OAuth redirect URIs accordingly.

## License
MIT
