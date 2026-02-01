from fastapi import FastAPI
from app.api.routes import router

app = FastAPI(title="Agentic Honeypot API")

# Include our API routes
app.include_router(router)

@app.get("/")
def root():
    return {"status": "Agentic Honeypot API running"}
