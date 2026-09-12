from fastapi import FastAPI

app = FastAPI(
    title="IPsec Security Intelligence API",
    version="0.1.0",
)


@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": "ipsec-security-intelligence",
        "version": "0.1.0",
    }

