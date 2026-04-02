from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from utils import analyze_url

app = FastAPI()

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 🔥 SERVE FRONTEND
@app.get("/")
def serve_frontend():
    return FileResponse("index.html")


@app.get("/check")
def check_url(url: str):
    return analyze_url(url)