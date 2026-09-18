"""数据库连接与会话管理"""
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from .config import settings

_connect_args = {}
if settings.DATABASE_URL.startswith("sqlite"):
    _connect_args = {"check_same_thread": False, "timeout": 30}

engine = create_engine(
    settings.DATABASE_URL,
    connect_args=_connect_args,
    pool_pre_ping=True,
    echo=False,
)

SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)


class Base(DeclarativeBase):
    pass


def get_db():
    """FastAPI 依赖：请求级会话"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """建表（含首次种子数据由外部脚本执行）+ 轻量列迁移"""
    from . import models  # noqa: F401  确保模型注册
    Base.metadata.create_all(bind=engine)
    _migrate()


def _migrate() -> None:
    """已存在数据库的增量列迁移（create_all 不会补新列）"""
    import sqlalchemy as sa
    insp = sa.inspect(engine)
    try:
        cols = {c["name"] for c in insp.get_columns("assets")}
        if "cookie" not in cols:
            with engine.begin() as conn:
                conn.execute(sa.text("ALTER TABLE assets ADD COLUMN cookie TEXT"))
    except Exception:
        pass
