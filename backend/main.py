from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, HttpUrl
from fastapi.middleware.cors import CORSMiddleware #evitar problemas de CORS
from virustotal import scan_url, get_url_report
import asyncio
import httpx

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://phishslayer-ai-backend.onrender.com"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# validamos que venga una URL válida
class URLRequest(BaseModel):
    url: HttpUrl

# Ruta POST que recibe la URL a escanear
@app.post("/scan-url")
async def check_url(request: URLRequest):
    try:
        # 1. Enviamos la URL a VirusTotal para escanearla
        scan_response = await scan_url(request.url)
        scan_id = scan_response["data"]["id"]

        # 2. Esperamos unos segundos para que el análisis esté listo
        await asyncio.sleep(8)

        # 3. Obtenemos el reporte del análisis
        report = await get_url_report(str(request.url))

        # 4. Obtenemos la parte que nos interesa: análisis general
        stats = report["data"]["attributes"]["last_analysis_stats"]

        # 5. Si hay motores que lo marcaron como malicioso
        if stats["malicious"] > 0:
            return {
                "url": request.url,
                "malicious": True,
                "stats": stats
            }
        else:
            return {
                "url": request.url,
                "malicious": False,
                "stats": stats
            }

    except httpx.HTTPStatusError as e:
        if e.response.status_code == 400:
            raise HTTPException(
                status_code=400,
                detail="La URL ingresada no es válida o fue rechazada por el sistema de análisis."
            )
        else:
            raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))