"""AutoVuln 全局配置（支持环境变量覆盖 + .env 文件）"""
import os
import secrets
from pathlib import Path

# ---- .env 加载（根目录与 backend/ 目录均可，README 已注明） ----
try:
    from dotenv import load_dotenv

    _ROOT_ENV = Path(__file__).resolve().parent.parent.parent / ".env"
    _BACKEND_ENV = Path(__file__).resolve().parent.parent / ".env"
    load_dotenv(_ROOT_ENV)
    load_dotenv(_BACKEND_ENV)
except Exception:
    pass  # 未安装 python-dotenv 时仅依赖环境变量

BASE_DIR = Path(__file__).resolve().parent.parent

# 视为"未配置"的弱默认密钥（命中则回落到持久化密钥文件）
_WEAK_KEYS = {
    "",
    "please-change-me-in-production",
    "please-change-me-in-production-0123456789abcdef",
}


def _load_or_create_secret() -> str:
    """安全密钥：优先环境变量；否则读取/生成持久化密钥文件。

    避免本地每次重启生成随机 key 导致所有 JWT 失效，
    也避免 Docker 默认弱密钥被直接使用。
    """
    env_key = os.environ.get("SECRET_KEY", "").strip()
    if env_key and env_key not in _WEAK_KEYS and not env_key.startswith("dev-only-change-me"):
        return env_key
    key_file = BASE_DIR / "data" / "secret.key"
    try:
        if key_file.exists():
            val = key_file.read_text(encoding="utf-8").strip()
            if len(val) >= 32:
                return val
        val = "autovuln-" + secrets.token_hex(32)
        key_file.parent.mkdir(parents=True, exist_ok=True)
        key_file.write_text(val, encoding="utf-8")
        return val
    except Exception:
        # 极端写失败回退：会话级随机（功能可用，重启后 token 失效）
        return "autovuln-" + secrets.token_hex(32)


def _env(key: str, default: str = "") -> str:
    return os.environ.get(key, default)


class Settings:
    # ---- 基础 ----
    APP_NAME: str = "AutoVuln 自动化漏洞挖掘平台"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = _env("DEBUG", "true").lower() == "true"

    # ---- 安全 ----
    SECRET_KEY: str = _load_or_create_secret()
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(_env("ACCESS_TOKEN_EXPIRE_MINUTES", "720"))
    INVITE_CODE: str = _env("INVITE_CODE", "autovuln2026")
    # CORS：默认仅允许本地开发/同源访问，生产用 CORS_ORIGINS 收紧或放行
    DEFAULT_CORS_ORIGINS = (
        "http://localhost:5173,http://127.0.0.1:5173,"
        "http://localhost:8000,http://127.0.0.1:8000"
    )
    CORS_ORIGINS: list[str] = (
        _env("CORS_ORIGINS", DEFAULT_CORS_ORIGINS).split(",")
        if _env("CORS_ORIGINS") else DEFAULT_CORS_ORIGINS.split(",")
    )

    # ---- 数据库 ----
    # 默认 SQLite 单机模式；生产可切 MySQL: mysql+pymysql://user:pass@host:3306/autovuln
    DATABASE_URL: str = _env("DATABASE_URL", f"sqlite:///{BASE_DIR / 'data' / 'autovuln.db'}")

    # ---- 扫描引擎 ----
    SCAN_CONCURRENCY: int = int(_env("SCAN_CONCURRENCY", "4"))      # 并发任务数
    SCAN_TIMEOUT: int = int(_env("SCAN_TIMEOUT", "15"))              # 单请求超时(秒)
    DEFAULT_RATE_LIMIT: float = float(_env("DEFAULT_RATE_LIMIT", "0.3"))  # 默认请求间隔(秒/请求)
    PORT_SCAN_TIMEOUT: float = float(_env("PORT_SCAN_TIMEOUT", "1.0"))    # 端口连接超时
    COMMON_PORTS: list[int] = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                               993, 995, 1080, 1433, 1521, 2049, 2375, 3000, 3306, 3389,
                               5432, 5601, 5900, 6379, 7001, 8000, 8008, 8009, 8080, 8081,
                               8088, 8443, 8888, 9000, 9092, 9200, 9300, 10000, 11211,
                               27017, 50000]

    # ---- 规则库 ----
    RULES_DIR: Path = BASE_DIR / "app" / "rules_data"
    # 在线规则源（示例，可配置）
    RULE_REMOTE_URLS: list[str] = _env("RULE_REMOTE_URLS", "").split(",") if _env("RULE_REMOTE_URLS") else []

    # ---- 通知 ----
    WEBHOOK_URL: str = _env("WEBHOOK_URL", "")
    SMTP_HOST: str = _env("SMTP_HOST", "")
    SMTP_PORT: int = int(_env("SMTP_PORT", "465"))
    SMTP_USER: str = _env("SMTP_USER", "")
    SMTP_PASSWORD: str = _env("SMTP_PASSWORD", "")
    SMTP_FROM: str = _env("SMTP_FROM", "")

    # ---- 报告 ----
    REPORT_TEMPLATE_DIR: Path = BASE_DIR / "app" / "templates"
    LOGO_PATH: str = _env("LOGO_PATH", "")

    # ---- OAST 带外检测 ----
    # 回调基址：默认本地（演示/内网靶场）；真实渗透配置为公网可达地址，
    # 目标需能访问该地址（如 https://oast.your-domain.com）
    OAST_BASE_URL: str = _env("OAST_BASE_URL", "http://127.0.0.1:8000").rstrip("/")

    # ---- 数据目录 ----
    EVIDENCE_DIR: Path = BASE_DIR / "data" / "evidence"
    EXPORT_DIR: Path = BASE_DIR / "data" / "exports"


settings = Settings()

# 确保数据目录存在
for _p in [settings.RULES_DIR, settings.EVIDENCE_DIR, settings.EXPORT_DIR,
           BASE_DIR / "data"]:
    _p.mkdir(parents=True, exist_ok=True)
