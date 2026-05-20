from fastapi import APIRouter
from backend.api.routes import idps, steg, honeypot, dashboard

api_router = APIRouter(prefix="/api")
api_router.include_router(idps.router)
api_router.include_router(steg.router)
api_router.include_router(honeypot.router)
api_router.include_router(dashboard.router)
