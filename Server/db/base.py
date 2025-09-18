"""
Import ALL models here so SQLAlchemy/SQLModel registers them
before metadata.create_all() / mapper configuration.
This prevents "failed to locate a name 'Password'" errors.
"""

from .models.plan import Plan
from .models.customer import Customer
from .models.user import User
from .models.password import Password
from .models.user_event import UserEvent
