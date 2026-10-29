Monica MDBX 的 MCP 服务
=======================

把本机 Monica MDBX 密码库（*.mdbx vault）接成 MCP 服务，让支持 MCP 的客户端
（Hermes、Claude Desktop 等）能按需查条目、取密码、算 TOTP。

只读：不写库、不改库、不删库。所有数据来自本机文件，不联网。


目录内容
--------
    server.py        MCP 服务本体（stdio），工具都在这里
    run.sh           MCP 客户端把它当 command 用，转去 .venv 里的 python
    pyproject.toml   依赖声明（mcp >= 2）
    smoke_test.py    冒烟测试：用真实 MCP 客户端连上来，逐个调工具
    .venv/           uv 生成的虚拟环境


安装
----
    git clone git@github.com:<你的账号>/monica-mdbx-mcp.git
    cd monica-mdbx-mcp
    uv sync


依赖
----
1) uv
2) Python 3.12（uv 会自己下）
3) mdbx 命令行（Monica-Pass/Mdbx 的 mdbx-cli 构建产物，已装在 ~/.local/bin/mdbx）

装依赖：

    cd monica-mdbx-mcp
    uv sync


配置（都用环境变量，不写配置文件）
----------------------------------
    MDBX_VAULT              vault 文件路径。默认在 MDBX_VAULT_DIR（默认 ~/文档/密码）
                            里挑最新修改的 *.mdbx
    MDBX_VAULT_DIR          vault 所在目录，默认 ~/文档/密码
    MDBX_UNLOCK_PASSWORD    解锁密码，优先级最高
    MDBX_PASSWORD_FILE      密码文件路径，默认 <MDBX_VAULT_DIR>/mdbx_vault_password.txt
    MDBX_CLI                mdbx 可执行文件，默认取 PATH 里的 mdbx
    MDBX_CACHE_FILE         索引缓存路径，默认 ~/.cache/monica-mdbx/<vault哈希>-index.json
    MDBX_DEBUG              设了就在 stderr 打一行启动信息


工具清单
--------
    overview      数据库概况：条目数、登录/备注数、带 TOTP 数、分组数、vault 大小
    list_groups   每个分组的条目数
    search        按关键词搜标题 / 用户名 / 网址 / 分组，不返回密码
    show          条目详情：分组、用户名、网址、备注；reveal=True 才带密码
    totp          取当前 6 位验证码和剩余秒数
    refresh       重建索引（vault 改动后跑一次）
    health        mdbx 自带的健康检查

典型对话流程：search 找到条目 -> show 看详情 -> 要看密码再 reveal -> 要验证码用 totp。


在 Hermes 里注册
----------------
    hermes mcp add monica-mdbx --command "$PWD/run.sh"

注册完用 hermes mcp list 看，hermes mcp test monica-mdbx 验证。
新开一个会话工具才会出现。


冒烟测试
--------
    cd monica-mdbx-mcp
    .venv/bin/python smoke_test.py

会真起一个子进程 server，握手、列工具、逐个调用（totp 和密码打码后再打印）。


设计取舍
--------
为什么走 mdbx CLI 而不直连 SQLite
    vault 里的字段是 MDBXFE2 / Tiga 加密包，密钥只在解锁后存在于进程内存；直接读表拿到
    的是密文，还绕过了客户端的披露策略。走官方 CLI 等于复用同一套解锁、披露与审计逻辑。

为什么密码默认不给
    search / list_groups / overview 连密码字段都不碰；只有 show(reveal=True) 和 totp 才现场
    调 `entry get --reveal`。这样一次普通的翻查不会把整库明文过一遍进程内存。

索引缓存里有什么
    只有 项目 ID / 标题 / 分组 / 收藏标记 / 登录条目的 用户名 / 网址 / 有无 TOTP。
    不放密码、不放 TOTP 密钥、不放备注正文。文件权限 600，vault 大小或 mtime 一变就自动重建。

性能
    单次 CLI 调用约 0.13-0.4 秒（每次都要 Argon2 解锁）。首次建索引 119 条要扫约 400 次调用，
    16 线程并行约 15 秒；之后命中缓存 2 毫秒。vault 没改动就不会重建。


已知限制
--------
- 解锁密码以 --unlock-password 形式出现在命令行参数里，同机其他用户 ps 可见。
  单人桌面无所谓；多用户机器上应该改成从 stdin 喂密码（需要给 mdbx CLI 加 --password-stdin
  这类参数，当前版本只有 import-kdbx 支持）。
- 只读封装：新增/编辑条目不在这套工具里，请用 Monica 客户端或 mdbx CLI 的 entry create/edit。
- 备注是独立 Note 对象，show 只取第一条 Note；多条备注时其余不显示。
- 收件箱式搜索（"搜不到"）：先 refresh 再搜，索引过期时会漏新条目。
- totp 对裸 base32 密钥（不带 otpauth:// 前缀）按 SHA1 / 6 位 / 30 秒算，可能与服务端不符。
