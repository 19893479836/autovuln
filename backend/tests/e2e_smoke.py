"""端到端冒烟测试：注册 → 资产导入 → 扫描 → 漏洞 → 报告 全链路"""
import json
import sys
import time
import urllib.request

BASE = "http://127.0.0.1:8000"


def req(method: str, path: str, body: dict | None = None, token: str | None = None):
    url = BASE + path
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    r = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(r, timeout=60) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def main():
    import time as _t
    suffix = str(int(_t.time()))[-8:]
    admin_name = f"testadmin{suffix}"
    user2_name = f"tenant2{suffix}"
    steps = []
    def step(name, ok, detail=""):
        steps.append((name, ok, detail))
        print(f"[{'PASS' if ok else 'FAIL'}] {name} {detail}")

    # 1. 注册
    code, data = req("POST", "/api/auth/register",
                     {"username": admin_name, "email": f"{admin_name}@t.com", "password": "test123456"})
    step("注册", code == 200, f"code={code}")
    token = data.get("access_token", "")

    # 2. 导入资产
    code, data = req("POST", "/api/assets/import",
                     {"targets": ["example.com", "example.com", "http://example.com",
                                  "192.168.1.1", "not a target"],
                      "tags": "test"}, token)
    step("资产导入+去重", code == 200, json.dumps(data, ensure_ascii=False))
    assert data["added"] >= 1 and data["existed"] >= 1 and data["invalid"] >= 1, "去重逻辑异常"

    # 3. 资产列表
    code, data = req("GET", "/api/assets?page_size=10", token=token)
    step("资产列表", code == 200 and data["total"] >= 2, f"total={data['total']}")
    # 选择域名资产（可联网，便于真实扫描）
    domain_asset = next((a for a in data["items"] if a["kind"] == "domain"), None)
    if not domain_asset:
        domain_asset = data["items"][0]
    asset_id = domain_asset["id"]
    print(f"    扫描目标: {domain_asset['value']} (kind={domain_asset['kind']})")

    # 4. 创建 full 扫描
    code, data = req("POST", "/api/scans",
                     {"asset_id": asset_id, "task_type": "full", "rate_limit": 200}, token)
    step("创建扫描任务", code == 200, f"task_id={data.get('id')} round={data.get('round_no')}")
    task_id = data.get("id")

    # 5. 等待扫描完成
    for i in range(120):
        time.sleep(2)
        code, data = req("GET", f"/api/scans/{task_id}", token=token)
        if data.get("state") in ("completed", "failed", "cancelled"):
            break
    step("扫描完成", data.get("state") == "completed",
         f"state={data.get('state')} progress={data.get('progress')} stage={data.get('stage')}")

    # 6. 漏洞列表
    code, data = req("GET", "/api/vulns?page_size=50", token=token)
    step("漏洞列表", code == 200, f"total={data['total']}")
    first_vuln_id = data["items"][0]["id"] if data["items"] else None
    print(f"    漏洞明细: {json.dumps(data['items'][:3], ensure_ascii=False, default=str)[:500]}")

    # 7. 状态流转
    if first_vuln_id:
        vid = first_vuln_id
        code, d2 = req("POST", f"/api/vulns/{vid}/transition",
                       {"to_state": "confirmed", "comment": "人工复核确认"}, token)
        step("状态流转 pending→confirmed", code == 200, json.dumps(d2, ensure_ascii=False))
        code, d2 = req("POST", f"/api/vulns/{vid}/transition",
                       {"to_state": "verified", "comment": "非法流转测试"}, token)
        step("非法流转被拒绝", code == 400, f"code={code}")

    # 8. 轮次对比（跑第二轮扫描）
    code, data = req("POST", "/api/scans",
                     {"asset_id": asset_id, "task_type": "full", "rate_limit": 200}, token)
    task2 = data.get("id")
    for i in range(120):
        time.sleep(2)
        code, d2 = req("GET", f"/api/scans/{task2}", token=token)
        if d2.get("state") in ("completed", "failed", "cancelled"):
            break
    step("第二轮扫描", d2.get("state") == "completed", f"round={d2.get('round_no')}")
    code, d3 = req("POST", f"/api/vulns/round-compare?asset_id={asset_id}",
                   {"round_a": 1, "round_b": 2}, token)
    step("轮次对比", code == 200, json.dumps(d3.get("summary"), ensure_ascii=False))

    # 9. 报告生成
    for fmt in ("html", "json", "excel", "pdf"):
        code, d4 = req("POST", "/api/reports/generate",
                       {"fmt": fmt, "title": f"测试报告-{fmt}"}, token)
        step(f"报告生成 {fmt}", code == 200, f"id={d4.get('id')}")

    # 10. Dashboard
    code, d5 = req("GET", "/api/dashboard", token=token)
    step("Dashboard", code == 200, f"vulns={d5.get('vuln_total')}")

    # 11. 多租户隔离测试
    code, _ = req("POST", "/api/auth/register",
                  {"username": user2_name, "email": f"{user2_name}@t.com", "password": "test123456"})
    _, d6 = req("POST", "/api/auth/login", {"username": user2_name, "password": "test123456"})
    token2 = d6.get("access_token", "")
    code, d7 = req("GET", "/api/assets", token=token2)
    step("租户隔离：他人看不到我的资产", code == 200 and d7["total"] == 0,
         f"tenant2 total={d7['total']}")
    code, d8 = req("GET", f"/api/vulns/{first_vuln_id or 1}", token=token2)
    step("租户隔离：越权访问被拒", code in (404, 403), f"code={code}")

    # 12. 审计日志
    code, d9 = req("GET", "/api/audit-logs?page_size=5", token=token)
    step("审计日志", code == 200 and d9["total"] >= 5, f"total={d9['total']}")

    # 13. 规则库
    code, d10 = req("GET", "/api/rules/web", token=token)
    step("规则库列表", code == 200 and isinstance(d10, list) and len(d10) > 0,
         f"rules={len(d10) if isinstance(d10, list) else 'n/a'}")
    code, d11 = req("GET", "/api/rules/fingerprint", token=token)
    code, d12 = req("GET", "/api/rules/poc", token=token)
    step("指纹+POC规则", code == 200 and len(d11) > 0 and len(d12) > 0,
         f"fp={len(d11)} poc={len(d12)}")

    failed = [s for s in steps if not s[1]]
    print(f"\n===== 结果: {len(steps)-len(failed)}/{len(steps)} 通过 =====")
    if failed:
        for name, ok, detail in failed:
            print(f"  FAILED: {name} {detail}")
        sys.exit(1)


if __name__ == "__main__":
    main()
