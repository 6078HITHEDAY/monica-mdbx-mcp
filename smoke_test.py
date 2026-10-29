#!/usr/bin/env python3
"""冒烟测试：用真正的 MCP 客户端连 server.py（stdio），列工具并逐个调一遍。

跑法：.venv/bin/python smoke_test.py
输出里密码/验证码按需打码，不把明文凭据落进日志文件。
"""
from __future__ import annotations

import asyncio
import os
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

HERE = os.path.dirname(os.path.abspath(__file__))

CALLS = [
    ("overview", {}),
    ("list_groups", {}),
    ("search", {"query": "github", "limit": 5}),
    ("search", {"query": "com.", "limit": 3}),
    ("show", {"name": "my", "reveal": False}),
    ("totp", {"name": "my"}),
    ("health", {}),
    ("refresh", {}),
]


def text_of(result) -> str:
    chunks = []
    for item in getattr(result, "content", []) or []:
        chunks.append(getattr(item, "text", str(item)))
    return "\n".join(chunks) if chunks else str(result)


async def main() -> int:
    params = StdioServerParameters(
        command=os.path.join(HERE, "run.sh"),
        args=[],
        env={**os.environ},
    )
    failures = 0
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            init = await session.initialize()
            print(f"握手: {init.server_info.name} {init.server_info.version}")
            tools = await session.list_tools()
            names = [t.name for t in tools.tools]
            print(f"工具 {len(names)} 个: {', '.join(names)}")
            for name, args in CALLS:
                try:
                    result = await session.call_tool(name, args)
                    body = text_of(result)
                    if name == "totp" and not body.startswith("「"):
                        body = body.split("（")[0] + "（…）"
                    print(f"\n--- {name}({args}) ---")
                    print(body[:1200])
                except Exception as error:  # noqa: BLE001
                    failures += 1
                    print(f"\n--- {name}({args}) --- 失败: {type(error).__name__}: {error}")
            if "show" in names:
                result = await session.call_tool("show", {"name": "my", "reveal": True})
                body = text_of(result)
                masked = []
                for line in body.splitlines():
                    if line.startswith("密码:"):
                        line = "密码: [已取到，长度 %d，此处打码]" % len(line.split("密码:", 1)[1].strip())
                    masked.append(line)
                print("\n--- show(my, reveal=True) 打码预览 ---")
                print("\n".join(masked)[:800])
    print(f"\n结果: {'全部工具可调用' if failures == 0 else f'{failures} 个工具调用失败'}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
