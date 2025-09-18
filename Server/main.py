import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response

from Server.settings import settings
from .db.session import init_db
from .db.seed_plans import seed_plans
from .core.password_validator import setup_password_validation
from .routers import auth_router, customer_router, plans_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    setup_password_validation()

    try:
        seed_plans()
    except Exception as e:
        print(f"Error seeding plans: {e}")
    else:
        print("Plans check/seed completed.")

    yield


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    docs_url="/docs",
    redoc_url=None,
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    res = await call_next(request)
    res.headers["X-Content-Type-Options"] = "nosniff"
    res.headers["X-Frame-Options"] = "DENY"
    res.headers["Referrer-Policy"] = "no-referrer"
    res.headers["X-XSS-Protection"] = "1; mode=block"

    # CSP מותאם לSwagger UI
    if request.url.path == "/docs":
        res.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "img-src 'self' data: https:; "
            "font-src 'self' https://cdn.jsdelivr.net;"
        )
    else:
        res.headers[
            "Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"

    return res


logger = logging.getLogger("app")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")


@app.exception_handler(Exception)
async def unhandled_exc_handler(request: Request, exc: Exception):
    logger.error("Unhandled error at %s %s", request.method, request.url.path, exc_info=exc)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


@app.get("/health", tags=["meta"])
def health():
    return {"status": "ok"}


@app.get("/", tags=["meta"])
def root():
    return {
        "message": "CommunicationLTD API",
        "version": settings.APP_VERSION,
        "docs": "/docs"
    }


@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    return Response(status_code=204)


app.include_router(auth_router)
app.include_router(customer_router)
app.include_router(plans_router)

if __name__ == "__main__":
    import uvicorn

    uvicorn.run("Server.main:app", host="0.0.0.0", port=8000, reload=True)
