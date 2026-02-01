from fastapi import FastAPI
from api.routes import router

app = FastAPI(title="Agentic Honeypot API")

# Include our API routes
app.include_router(router)

@app.get("/")
def root():
    return {"status": "Agentic Honeypot API running"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)