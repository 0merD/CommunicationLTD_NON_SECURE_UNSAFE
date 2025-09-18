from .auth import router as auth_router
from .customer import router as customer_router
from .plans import router as plans_router

__all__ = ["auth_router", "customer_router", "plans_router"]
