"""端口与服务识别扫描器：并发 TCP 连接探测 + 服务 Banner 抓取"""
import json
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..config import settings
from .base import BaseScanner


class PortScanScanner(BaseScanner):
    name = "recon_port"
    display_name = "端口与服务识别"

    def run(self):
        asset = self._get_asset()
        if not asset:
            return
        host = self._resolve_host(asset.value)
        if not host:
            self.log("无法解析主机")
            return
        params = self._get_params()
        ports: list[int] = []
        if params.get("ports") == "all":
            ports = list(range(1, 10001))
        elif params.get("ports"):
            for p in str(params["ports"]).split(","):
                p = p.strip()
                if "-" in p:
                    a, b = p.split("-")
                    ports.extend(range(int(a), int(b) + 1))
                elif p:
                    ports.append(int(p))
        if not ports:
            ports = list(settings.COMMON_PORTS)

        timeout = float(params.get("timeout") or settings.PORT_SCAN_TIMEOUT)
        concurrency = min(int(params.get("concurrency") or 100), 200)

        open_ports: list[tuple[int, str]] = []

        def probe(port: int) -> tuple[int, str] | None:
            self.checkpoint()
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            try:
                if s.connect_ex((host, port)) == 0:
                    banner = self._grab_banner(s, port, timeout)
                    return port, banner
            except Exception:
                pass
            finally:
                s.close()
            return None

        total = len(ports)
        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            futures = {pool.submit(probe, p): p for p in ports}
            done = 0
            for fut in as_completed(futures):
                try:
                    r = fut.result()
                    if r:
                        open_ports.append(r)
                except Exception:
                    pass
                done += 1
                if done % 20 == 0:
                    self.set_progress(done, total, f"端口探测中 {done}/{total}")

        self.set_progress(total, total, "写入端口结果")
        for port, banner in sorted(open_ports):
            self.checkpoint()
            self.add_record("port", str(port), value=banner or "",
                            detail={"port": port, "host": host}, source="tcpscan")
            if banner:
                self.add_record("service", f"{port}:{self._service_name(port)}",
                                value=banner, detail={"port": port}, source="banner")
        self.log(f"端口扫描完成：发现 {len(open_ports)} 个开放端口")

    # ---- 工具 ----
    def _resolve_host(self, value: str) -> str | None:
        if value.replace(".", "").isdigit() or ":" in value:
            return value  # IP
        try:
            return socket.gethostbyname(value)
        except Exception:
            return None

    def _grab_banner(self, s: socket.socket, port: int, timeout: float) -> str:
        banner = ""
        try:
            s.sendall(b"\r\n")
            s.settimeout(min(timeout, 2.0))
            data = s.recv(256)
            if data:
                banner = data.decode("utf-8", errors="replace").strip()[:128]
        except Exception:
            pass
        if not banner and port in (80, 443, 8080, 8443, 8000, 8888):
            banner = "http"
        return banner

    @staticmethod
    def _service_name(port: int) -> str:
        table = {21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
                 110: "pop3", 143: "imap", 443: "https", 445: "smb", 3306: "mysql",
                 3389: "rdp", 5432: "postgresql", 6379: "redis", 27017: "mongodb",
                 9200: "elasticsearch", 11211: "memcached", 2375: "docker"}
        return table.get(port, "unknown")

    def _get_asset(self):
        from ..database import SessionLocal
        from ..models import Asset, ScanTask
        with SessionLocal() as db:
            task = db.get(ScanTask, self.task_id)
            return db.get(Asset, task.asset_id) if task else None

    def _get_params(self) -> dict:
        from ..database import SessionLocal
        from ..models import ScanTask
        with SessionLocal() as db:
            task = db.get(ScanTask, self.task_id)
            try:
                return json.loads(task.params or "{}")
            except Exception:
                return {}
