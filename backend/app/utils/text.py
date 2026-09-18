"""通用文本工具"""
def escape_like(s: str) -> str:
    """转义 SQL LIKE 通配符，配合 SQLAlchemy 的 escape 参数使用。

    用法：``col.like(f"%{escape_like(kw)}%", escape="\\\\")``
    """
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
