import httpx
import os
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("VT_API_KEY")
BASE_URL = "https://www.virustotal.com/api/v3/urls"
HEADERS = {
    "x-apikey": API_KEY
}

# Enviar una URL para que VirusTotal la analice
async def scan_url(url: str):
    async with httpx.AsyncClient() as client:
        # La API requiere que la URL se envíe como un form-urlencoded
        response = await client.post(BASE_URL, headers=HEADERS, data={"url": url})
        response.raise_for_status()
        return response.json()

# Obtener el reporte del análisis de esa URL
async def get_url_report(url: str):
    import base64

    # La API requiere que la URL esté en base64 (modo URL-safe, sin padding)
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    async with httpx.AsyncClient() as client:
        response = await client.get(f"{BASE_URL}/{url_id}", headers=HEADERS)
        response.raise_for_status()
        return response.json()
