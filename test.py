import requests

conn = requests.get("https://www.google.com")
print(len(conn.text))