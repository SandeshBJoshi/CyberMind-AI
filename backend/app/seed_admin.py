"""Run once to create the initial admin/owner account:
    python -m app.seed_admin
"""
from .database import SessionLocal, engine, Base
from . import models
from .auth import hash_password
from .config import settings

def main():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    existing = db.query(models.AdminUser).filter(models.AdminUser.username == settings.admin_username).first()
    if existing:
        print(f"Admin '{settings.admin_username}' already exists.")
    else:
        admin = models.AdminUser(
            username=settings.admin_username,
            hashed_password=hash_password(settings.admin_password),
        )
        db.add(admin)
        db.commit()
        print(f"Created admin user '{settings.admin_username}'.")
    db.close()

if __name__ == "__main__":
    main()
