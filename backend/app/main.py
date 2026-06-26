from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routers import auth, scans, reports

app = FastAPI(title="MCP Shield API", version="1.0.0")

# Set up CORS middleware to whitelist frontend (or all in development)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Routers
app.include_router(auth.router, prefix="/api/v1")
app.include_router(scans.router, prefix="/api/v1")
app.include_router(reports.router) # reports prefix is already specified internally

@app.get("/")
def read_root():
    return {"status": "MCP Shield API running"}
