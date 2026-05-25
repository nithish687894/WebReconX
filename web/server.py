import os
import sys
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from typing import List, Optional

# Add project root to path so we can import WebReconX and its modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from webreconx import WebReconX
except ImportError:
    # If starting from parent directory
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from webreconx import WebReconX

app = FastAPI(
    title="WebReconX API",
    description="Backend scanner programmatic API for WebReconX Advanced Web Security Reconnaissance Framework",
    version="1.0.0"
)

# Define request schemas
class ScanRequest(BaseModel):
    target: str = Field(..., example="example.com")
    modules: Optional[List[str]] = Field(default=None, example=["headers", "ssl", "tech", "ports", "dns", "subdomains", "wayback"])
    timeout: Optional[int] = Field(default=10, ge=1, le=60)
    threads: Optional[int] = Field(default=10, ge=1, le=50)

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# API Endpoints
@app.get("/api/health")
def health_check():
    return {"status": "healthy", "service": "WebReconX Engine"}

@app.post("/api/scan")
def trigger_scan(req: ScanRequest):
    try:
        # Instantiate and execute the framework scanner
        scanner = WebReconX(
            target=req.target,
            modules=req.modules,
            output=None,
            timeout=req.timeout or 10,
            threads=req.threads or 10,
            verbose=False
        )
        
        # Execute scan
        results = scanner.run()
        
        # Calculate overall statistics
        duration = 0.0
        if scanner.start_time and scanner.end_time:
            duration = (scanner.end_time - scanner.start_time).total_seconds()
            
        response_data = {
            "duration": f"{duration:.2f}",
            "target": scanner.target,
            "domain": scanner._get_domain(),
        }
        
        # Merge individual modules output
        for key in req.modules or list(WebReconX.MODULES.keys()):
            if key in results:
                response_data[key] = results[key]
            else:
                response_data[key] = {"status": "skipped", "data": {}}
                
        return response_data
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Scan execution failed: {str(e)}")

# Mount static files (serve index.html at root)
app.mount("/static", StaticFiles(directory=BASE_DIR), name="static")

@app.get("/")
def serve_index():
    return FileResponse(os.path.join(BASE_DIR, "index.html"))

@app.get("/style.css")
def serve_css():
    return FileResponse(os.path.join(BASE_DIR, "style.css"))

@app.get("/app.js")
def serve_js():
    return FileResponse(os.path.join(BASE_DIR, "app.js"))

if __name__ == "__main__":
    # Standard local debug server runner
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("server:app", host="0.0.0.0", port=port, reload=True)
