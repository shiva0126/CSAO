from __future__ import annotations

import os
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

try:
    from dotenv import load_dotenv

    load_dotenv(Path(__file__).resolve().parent.parent.parent / ".env")
except ImportError:
    pass


DATABASE_URL_SYNC = os.environ.get(
    "DATABASE_URL_SYNC", "postgresql+psycopg://csao:csao@localhost:5432/csao"
)


class Base(DeclarativeBase):
    pass


sync_engine = create_engine(DATABASE_URL_SYNC, pool_pre_ping=True, future=True)
SyncSessionLocal = sessionmaker(bind=sync_engine, class_=Session, expire_on_commit=False)


def get_sync_session() -> Session:
    return SyncSessionLocal()
