FROM python:3.11-slim
WORKDIR /app
COPY . .
COPY credentials.json /app/credentials.json
RUN pip install --no-cache-dir -r requirements.txt
ENV PORT=8080
CMD ["gunicorn", "-b", ":8080", "app:app"]
