from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from utils import analyze_url

app = FastAPI()

# CORS FIX
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def home():
    return {"message": "URL Safety Checker Running"}

@app.get("/check")
def check_url(url: str):
    return analyze_url(url)