

This app allows you to log in with Google, analyze your Gmail inbox by domain, and bulk clean emails from selected domains.

## Deployment Notes
- Place `app.py`, `Dockerfile`, `requirements.txt`, and `credentials.json` in the root directory.
- Deploy to Google Cloud Run using the build context of the repo root.
- Set the environment variable `OAUTH_REDIRECT_URI` to your Cloud Run service URL with `/oauth2callback`.
