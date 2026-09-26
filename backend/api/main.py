from pathlib import Path
from tempfile import NamedTemporaryFile

from fastapi import FastAPI, File, HTTPException, UploadFile
from pydantic import BaseModel

from backend.ai_engine.traffic_classifier import classify_traffic
from backend.feature_engine.traffic_features import extract_traffic_features
from backend.fusion_engine.pipeline import analyze_pcap
from backend.security_engine.metadata_exposure import assess_metadata_exposure
from backend.security_engine.what_if import simulate_security_change

class SecuritySimulationRequest(BaseModel):
    current_evidence: dict
    changes: dict

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


@app.post("/api/v1/analyze/pcap")
async def analyze_pcap_endpoint(
    file: UploadFile = File(...),
):
    if not file.filename:
        raise HTTPException(
            status_code=400,
            detail="PCAP file is required",
        )

    suffix = Path(file.filename).suffix.lower()

    if suffix not in {".pcap", ".pcapng", ".cap"}:
        raise HTTPException(
            status_code=400,
            detail=(
                "Unsupported file type. "
                "Expected .pcap, .pcapng, or .cap"
            ),
        )

    temporary_path = None

    try:
        with NamedTemporaryFile(
            suffix=suffix,
            delete=False,
        ) as temporary_file:
            temporary_path = Path(temporary_file.name)

            while True:
                chunk = await file.read(1024 * 1024)

                if not chunk:
                    break

                temporary_file.write(chunk)

        result = analyze_pcap(temporary_path)

        result["pcap"]["filename"] = file.filename

        feature_vectors = extract_traffic_features(
            result["esp"]
        )

        traffic_results = []

        for feature_vector in feature_vectors:
            classification = classify_traffic(
                feature_vector
            )

            metadata_exposure = assess_metadata_exposure(
                feature_vector
            )

            traffic_results.append(
                {
                    "features": feature_vector,
                    "classification": classification,
                    "metadata_exposure": metadata_exposure,
                }
            )

        result["traffic_intelligence"] = {
            "flow_count": len(traffic_results),
            "flows": traffic_results,
        }

        return result

    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        ) from exc

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"PCAP analysis failed: {exc}",
        ) from exc

    finally:
        await file.close()

        if temporary_path is not None:
            temporary_path.unlink(
                missing_ok=True,
            )
@app.post("/api/v1/simulate/security")
def simulate_security_endpoint(
    request: SecuritySimulationRequest,
):
    try:
        if "ike" not in request.current_evidence:
            raise HTTPException(
                status_code=400,
                detail="current_evidence must contain an 'ike' object",
            )

        if not request.changes:
            raise HTTPException(
                status_code=400,
                detail="At least one security change is required",
            )

        return simulate_security_change(
            current_evidence=request.current_evidence,
            changes=request.changes,
        )

    except HTTPException:
        raise

    except (TypeError, KeyError, ValueError) as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Security simulation failed: {exc}",
        ) from exc
