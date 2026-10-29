#!/usr/bin/env python3
"""Monica MDBX vault 的 MCP 服务（stdio）。

设计要点：
- 不直连 SQLite：vault 里的字段是 MDBXFE2/Tiga 加密包，密钥只在解锁后存在于进程内存。
  所以统一走官方 CLI `mdbx`（同一份 storage 代码），由它负责解锁与披露策略。
- 密码只按需取：索引缓存里绝不放 password；只有 show(reveal=True) / totp() 才现场读。
- 一次 CLI 调用约 0.13s，索引用 8 线程扫一遍约 5-8s，之后全部走缓存。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from mcp.server.mcpserver import MCPServer

SERVER_NAME = "monica-mdbx"
CACHE_VERSION = 1

DEFAULT_VAULT_DIR = Path(os.environ.get("MDBX_VAULT_DIR", "~/文档/密码")).expanduser()
DEFAULT_PASSWORD_FILE = Path(
    os.environ.get("MDBX_PASSWORD_FILE", str(DEFAULT_VAULT_DIR / "mdbx_vault_password.txt"))
).expanduser()


# ---------------------------------------------------------------- 配置与调用


def _resolve_cli() -> str:
    cli = os.environ.get("MDBX_CLI")
    if cli:
        return cli
    found = shutil.which("mdbx")
    if found:
        return found
    fallback = Path("~/.local/bin/mdbx").expanduser()
    if fallback.exists():
        return str(fallback)
    raise RuntimeError("找不到 mdbx 可执行文件：设置 MDBX_CLI 环境变量")


def _resolve_vault() -> Path:
    env = os.environ.get("MDBX_VAULT")
    if env:
        return Path(env).expanduser()
    candidates = sorted(DEFAULT_VAULT_DIR.glob("*.mdbx"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not candidates:
        raise RuntimeError(f"{DEFAULT_VAULT_DIR} 下没有 .mdbx vault：设置 MDBX_VAULT")
    return candidates[0]


def _resolve_password() -> str:
    pw = os.environ.get("MDBX_UNLOCK_PASSWORD")
    if pw:
        return pw
    if not DEFAULT_PASSWORD_FILE.exists():
        raise RuntimeError(f"找不到解锁密码：设置 MDBX_UNLOCK_PASSWORD 或 MDBX_PASSWORD_FILE（当前 {DEFAULT_PASSWORD_FILE}）")
    return DEFAULT_PASSWORD_FILE.read_text(encoding="utf-8").strip()


CLI = _resolve_cli()
VAULT = _resolve_vault()
_PASSWORD = _resolve_password()
CACHE_FILE = Path(os.environ.get(
    "MDBX_CACHE_FILE",
    f"~/.cache/{SERVER_NAME}/{hashlib.sha256(str(VAULT).encode()).hexdigest()[:12]}-index.json",
)).expanduser()


def _scrub(text: str) -> str:
    return text.replace(_PASSWORD, "***") if _PASSWORD else text


def cli(*args: str, timeout: int = 120) -> str:
    """跑一次 mdbx CLI，返回 stdout。密码只走 argv，不进日志、不进异常信息。"""
    cmd = [CLI, "--vault", str(VAULT), "--unlock-password", _PASSWORD, *args]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"mdbx {' '.join(args)} 超时（{timeout}s）")
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).strip()
        raise RuntimeError(_scrub(detail) or f"mdbx {' '.join(args)} 失败（退出码 {proc.returncode}）")
    return proc.stdout


# ---------------------------------------------------------------- 输出解析


def parse_projects() -> list[dict]:
    out = cli("project", "list")
    items = []
    for line in out.splitlines():
        line = line.rstrip()
        if not line or line.startswith("("):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            items.append({"project_id": parts[0], "title": parts[1].strip()})
    return items


def project_detail(project_id: str) -> dict:
    detail = {"project_id": project_id, "group": "", "favorite": False, "archived": False, "updated": ""}
    for line in cli("project", "get", project_id).splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key, value = key.strip(), value.strip()
        if key == "Title":
            detail["title"] = value
        elif key == "Group":
            detail["group"] = value
        elif key == "Favorite":
            detail["favorite"] = value == "true"
        elif key == "Archived":
            detail["archived"] = value == "true"
        elif key == "Updated":
            detail["updated"] = value
    return detail


def parse_entries(project_id: str) -> list[dict]:
    out = cli("entry", "list", project_id)
    items = []
    for line in out.splitlines():
        line = line.rstrip()
        if not line or line.startswith("("):
            continue
        parts = line.split(None, 2)
        if len(parts) >= 2:
            items.append({
                "entry_id": parts[0],
                "type": parts[1],
                "title": parts[2].strip() if len(parts) > 2 else "",
                "project_id": project_id,
            })
    return items


HEADER_RE = re.compile(r"^([A-Za-z][A-Za-z ]*):\s?(.*)$")
PAYLOAD_RE = re.compile(r"^  ([A-Za-z0-9_]+):\s?(.*)$")


def entry_revealed(entry_id: str) -> dict:
    """读单条明细（含密码）。返回 header + payload 字段。

    版式：header 顶格 "Key: value"，"Payload:" 之后是两空格缩进的 "key: value"；
    备注这类字段的值里可能有换行，后续行不带两空格缩进，要接回上一个字段。
    """
    header: dict[str, str] = {}
    payload: dict[str, str] = {}
    in_payload = False
    current: str | None = None
    for line in cli("entry", "get", entry_id, "--reveal").splitlines():
        if not in_payload:
            if line.strip() == "Payload:":
                in_payload = True
                continue
            match = HEADER_RE.match(line)
            if match:
                header[match.group(1).strip()] = match.group(2).strip()
            continue
        match = PAYLOAD_RE.match(line)
        if match:
            current = match.group(1)
            payload[current] = match.group(2)
        elif current is not None:
            payload[current] = (payload[current] + "\n" + line).strip("\n")
    return {"header": header, "payload": payload}


# ---------------------------------------------------------------- 索引缓存


def _vault_fingerprint() -> dict:
    stat = VAULT.stat()
    return {"size": stat.st_size, "mtime": int(stat.st_mtime)}


def build_index() -> dict:
    started = time.time()
    projects = parse_projects()
    with ThreadPoolExecutor(max_workers=16) as pool:
        details = list(pool.map(lambda p: project_detail(p["project_id"]), projects))
        entries_per_project = list(pool.map(lambda p: parse_entries(p["project_id"]), projects))

    def enrich(entry: dict) -> dict:
        try:
            data = entry_revealed(entry["entry_id"])
        except RuntimeError:
            data = {"header": {}, "payload": {}}
        payload = data["payload"]
        entry["username"] = payload.get("username", "")
        entry["url"] = payload.get("url", "")
        entry["has_totp"] = bool(payload.get("totp_seed"))
        entry["has_notes"] = bool(payload.get("text", "").strip()) if entry["type"] == "Note" else False
        return entry

    flat = [e for rows in entries_per_project for e in rows]
    with ThreadPoolExecutor(max_workers=16) as pool:
        flat = list(pool.map(enrich, flat))

    index = {
        "version": CACHE_VERSION,
        "vault": str(VAULT),
        "fingerprint": _vault_fingerprint(),
        "built_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "built_seconds": round(time.time() - started, 1),
        "projects": details,
        "entries": flat,
    }
    CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    CACHE_FILE.write_text(json.dumps(index, ensure_ascii=False), encoding="utf-8")
    os.chmod(CACHE_FILE, 0o600)
    return index


def load_index(force: bool = False) -> dict:
    if not force and CACHE_FILE.exists():
        try:
            index = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            index = None
        if index and index.get("version") == CACHE_VERSION and index.get("fingerprint") == _vault_fingerprint():
            return index
    return build_index()


# ---------------------------------------------------------------- 检索与 TOTP


def _norm(text: str) -> str:
    return (text or "").strip().lower()


def find_projects(index: dict, needle: str) -> list[dict]:
    needle = _norm(needle)
    if not needle:
        return []
    projects = index["projects"]
    exact = [p for p in projects if _norm(p["title"]) == needle]
    if exact:
        return exact
    by_id = [p for p in projects if p["project_id"] == needle]
    if by_id:
        return by_id
    starts = [p for p in projects if _norm(p["title"]).startswith(needle)]
    if starts:
        return starts
    contains = [p for p in projects if needle in _norm(p["title"])]
    if contains:
        return contains
    # 退一步用用户名 / URL 匹配
    hits = [e["project_id"] for e in index["entries"]
            if needle in _norm(e.get("username", "")) or needle in _norm(e.get("url", ""))]
    seen, out = set(), []
    for pid in hits:
        if pid not in seen:
            seen.add(pid)
            out.extend(p for p in projects if p["project_id"] == pid)
    return out


def hotp(secret: str, counter: int, digits: int, algorithm: str) -> str:
    key = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
    digest = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}.get(algorithm, hashlib.sha1)
    mac = hmac.new(key, struct.pack(">Q", counter), digest).digest()
    offset = mac[-1] & 0x0F
    code = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)


def totp_now(uri: str) -> dict:
    parsed = urllib.parse.urlparse(uri)
    query = urllib.parse.parse_qs(parsed.query)
    secret = query.get("secret", [""])[0]
    digits = int(query.get("digits", ["6"])[0])
    period = int(query.get("period", ["30"])[0])
    algorithm = query.get("algorithm", ["SHA1"])[0].upper()
    now = int(time.time())
    return {
        "code": hotp(secret, now // period, digits, algorithm),
        "remaining": period - now % period,
        "digits": digits,
        "period": period,
    }


# ---------------------------------------------------------------- MCP 工具

srv = MCPServer(
    name=SERVER_NAME,
    title="Monica MDBX 密码库",
    version="1.0.0",
    instructions=(
        "查询本地 Monica MDBX 密码库。默认不返回密码；需要密码时显式传 reveal=True。"
        "所有数据来自本机 vault 文件，不联网。"
    ),
)


@srv.tool(description="数据库概况：vault 路径、条目/分组数量、索引构建时间。")
def overview() -> str:
    index = load_index()
    groups: dict[str, int] = {}
    for project in index["projects"]:
        key = project.get("group") or "(无分组)"
        groups[key] = groups.get(key, 0) + 1
    logins = sum(1 for e in index["entries"] if e["type"] == "Login")
    notes = sum(1 for e in index["entries"] if e["type"] == "Note")
    totp = sum(1 for e in index["entries"] if e.get("has_totp"))
    stat = VAULT.stat()
    return "\n".join([
        f"vault: {VAULT}",
        f"大小: {stat.st_size / 1024:.0f} KB   最后修改: {time.strftime('%Y-%m-%d %H:%M', time.localtime(stat.st_mtime))}",
        f"条目: {len(index['projects'])} 个（登录 {logins} / 备注 {notes}，带 TOTP {totp}）",
        f"分组: {len(groups)} 个",
        f"索引: 构建于 {index['built_at']}（耗时 {index['built_seconds']}s），缓存 {CACHE_FILE}",
    ])


@srv.tool(description="列出所有分组及每组条目数。")
def list_groups() -> str:
    index = load_index()
    groups: dict[str, int] = {}
    for project in index["projects"]:
        key = project.get("group") or "(无分组)"
        groups[key] = groups.get(key, 0) + 1
    lines = [f"共 {len(index['projects'])} 条，{len(groups)} 个分组"]
    for name in sorted(groups, key=lambda k: (-groups[k], k)):
        lines.append(f"  {groups[name]:3d}  {name}")
    return "\n".join(lines)


@srv.tool(description="按关键词搜索条目，匹配标题、用户名、网址、分组（不含密码）。")
def search(query: str, limit: int = 15) -> str:
    index = load_index()
    needle = _norm(query)
    if not needle:
        return "请给出关键词"
    groups = {p["project_id"]: p.get("group", "") for p in index["projects"]}
    hits: list[tuple[str, str, str, str]] = []
    for project in index["projects"]:
        if needle in _norm(project["title"]):
            hits.append((project["title"], groups.get(project["project_id"], ""), "", "标题"))
    for entry in index["entries"]:
        if entry["type"] != "Login":
            continue
        fields = {
            "用户名": entry.get("username", ""),
            "网址": entry.get("url", ""),
        }
        for label, value in fields.items():
            if needle in _norm(value):
                project_title = next(
                    (p["title"] for p in index["projects"] if p["project_id"] == entry["project_id"]), "?"
                )
                hits.append((project_title, groups.get(entry["project_id"], ""), entry.get("username", ""), label))
    if not hits:
        return f"没有匹配「{query}」的条目"
    seen, lines = set(), [f"匹配「{query}」共 {len(hits)} 条（最多显示 {limit}）"]
    for title, group, username, why in hits:
        marker = (title, group, username)
        if marker in seen:
            continue
        seen.add(marker)
        if len(lines) - 1 >= limit:
            lines.append(f"  ...还有 {len(hits) - limit} 条未显示")
            break
        extra = f" [{group}]" if group else ""
        who = f" ({username})" if username else ""
        lines.append(f"  {title}{extra}{who}  ← {why}")
    return "\n".join(lines)


def _resolve_project(index: dict, name: str) -> dict:
    matches = find_projects(index, name)
    if not matches:
        raise ValueError(f"找不到「{name}」")
    return matches[0]


@srv.tool(description="查看某条目的详情：分组、用户名、网址、备注、有无 TOTP。reveal=True 才返回密码。")
def show(name: str, reveal: bool = False) -> str:
    index = load_index()
    project = _resolve_project(index, name)
    entries = [e for e in index["entries"] if e["project_id"] == project["project_id"]]
    login = next((e for e in entries if e["type"] == "Login"), None)
    note = next((e for e in entries if e["type"] == "Note"), None)

    lines = [f"标题: {project['title']}"]
    if project.get("group"):
        lines.append(f"分组: {project['group']}")
    if project.get("favorite"):
        lines.append("收藏: 是")
    if login is None:
        lines.append("(这条没有登录字段)")
    else:
        data = entry_revealed(login["entry_id"])
        payload = data["payload"]
        lines.append(f"用户名: {payload.get('username', '')}")
        if reveal:
            lines.append(f"密码: {payload.get('password', '')}")
        else:
            has_pw = bool(payload.get("password"))
            lines.append(f"密码: {'已设置（要看请 reveal=True）' if has_pw else '空'}")
        if payload.get("url"):
            lines.append(f"网址: {payload['url']}")
        if payload.get("totp_seed"):
            lines.append("TOTP: 有，用 totp 工具取当前验证码")
    if note is not None:
        data = entry_revealed(note["entry_id"])
        text = data["payload"].get("text", "").strip()
        if text:
            lines.append("备注:")
            lines.extend("  " + row for row in text.splitlines())
    return "\n".join(lines)


@srv.tool(description="取某条目的当前 6 位 TOTP 验证码和剩余秒数。")
def totp(name: str) -> str:
    index = load_index()
    project = _resolve_project(index, name)
    login = next(
        (e for e in index["entries"] if e["project_id"] == project["project_id"] and e["type"] == "Login"), None
    )
    if login is None:
        return f"「{project['title']}」没有登录条目"
    payload = entry_revealed(login["entry_id"])["payload"]
    uri = payload.get("totp_seed", "").strip()
    if not uri:
        return f"「{project['title']}」没有配置 TOTP"
    if uri.startswith("otpauth://"):
        result = totp_now(uri)
        return f"{project['title']}: {result['code']}（{result['digits']} 位，{result['remaining']}s 后刷新）"
    # 裸 base32 密钥的情况
    result = totp_now("otpauth://totp/x?secret=" + urllib.parse.quote(uri))
    return f"{project['title']}: {result['code']}（{result['remaining']}s 后刷新，密钥未带算法信息，按 SHA1/6位/30秒计）"


@srv.tool(description="重建本地索引（vault 改动后用一次，约 5-8 秒）。")
def refresh() -> str:
    index = build_index()
    return f"索引已重建：{len(index['projects'])} 条 / {len(index['entries'])} 个对象，耗时 {index['built_seconds']}s"


@srv.tool(description="跑 mdbx 自带的 vault 健康检查。")
def health() -> str:
    return cli("health").strip() or "健康检查没有输出"


def main() -> None:
    if os.environ.get("MDBX_DEBUG"):
        print(f"[{SERVER_NAME}] vault={VAULT} cli={CLI} cache={CACHE_FILE}", file=sys.stderr)
    srv.run("stdio")


if __name__ == "__main__":
    main()
