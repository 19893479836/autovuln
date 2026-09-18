"""资产管理层模型：分组 / 资产 / 聚合信息（子域名、端口、指纹、接口）"""
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..database import Base


class AssetGroup(Base):
    """资产分组（按项目/业务/重要级）"""

    __tablename__ = "asset_groups"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    importance: Mapped[str] = mapped_column(String(16), default="medium")  # high/medium/low
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class Asset(Base):
    """资产主体：域名 / IP / URL，自动去重合并"""

    __tablename__ = "assets"
    __table_args__ = (UniqueConstraint("user_id", "value", "kind", name="uq_asset_user_value_kind"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True, nullable=False)
    group_id: Mapped[int | None] = mapped_column(ForeignKey("asset_groups.id"), nullable=True, index=True)
    kind: Mapped[str] = mapped_column(String(16), default="domain")  # domain/ip/url
    value: Mapped[str] = mapped_column(String(256), index=True, nullable=False)  # 规范化后的值
    raw_value: Mapped[str | None] = mapped_column(String(256), nullable=True)     # 原始录入
    tags: Mapped[str] = mapped_column(String(256), default="")                    # 逗号分隔标签
    status: Mapped[str] = mapped_column(String(16), default="active")             # active/offline/unknown
    importance: Mapped[str] = mapped_column(String(16), default="medium")
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    # 认证态扫描：登录会话 Cookie（格式 `k=v; k2=v2`），扫描时随请求携带
    cookie: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    group: Mapped["AssetGroup | None"] = relationship()  # noqa: F821


class AssetRecord(Base):
    """资产聚合信息：子域名 / 端口服务 / 指纹 / 接口 / 目录"""

    __tablename__ = "asset_records"
    __table_args__ = (UniqueConstraint("asset_id", "kind", "key", name="uq_asset_rec_kind_key"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True, nullable=False)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"), index=True, nullable=False)
    kind: Mapped[str] = mapped_column(String(24), nullable=False, index=True)
    # subdomain / port / service / fingerprint / jsapi / path / cert
    key: Mapped[str] = mapped_column(String(512), nullable=False)          # 如端口 8080
    value: Mapped[str | None] = mapped_column(Text, nullable=True)         # 服务名/版本/指纹描述
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)        # JSON 扩展信息
    source: Mapped[str] = mapped_column(String(64), default="manual")      # 发现来源
    discovered_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    asset: Mapped["Asset"] = relationship()  # noqa: F821
