#!/usr/bin/env python3
"""把 proxy.txt 的内容作为正文发一封邮件。

环境变量：
  MAIL_TO          收件人，多个用逗号分隔
  SMTP_HOST        SMTP 服务器，如 smtp.qq.com
  SMTP_PORT        可选，默认 465
  SMTP_USERNAME    登录用户名（通常就是发件邮箱）
  SMTP_PASSWORD    密码 / 授权码（多数邮箱要求用「授权码」而非登录密码）
  MAIL_FROM        可选，默认取 SMTP_USERNAME
  MAIL_SUBJECT     可选，默认 OpenList CI 构建产物
  MAIL_BODY_FILE   正文来源文件，默认 proxy.txt

退出码：
  缺配置 -> 打 notice 后返回 0（fork 或未配置时不应让 workflow 失败）
  发送失败 -> 返回 1（配置了就该发出去，静默失败会让人以为发了）

端口决定加密方式：465 走隐式 SSL（SMTP_SSL），其余走 STARTTLS。
"""

import os
import smtplib
import ssl
import sys
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from pathlib import Path

TIMEOUT = 30


def notice(msg: str) -> None:
    print(f"::notice::{msg}")


def warning(msg: str) -> None:
    print(f"::warning::{msg}")


def error(msg: str) -> None:
    print(f"::error::{msg}")


def main() -> int:
    body_file = os.environ.get("MAIL_BODY_FILE", "proxy.txt")

    to_addrs = [a.strip() for a in os.environ.get("MAIL_TO", "").split(",") if a.strip()]
    host = os.environ.get("SMTP_HOST", "").strip()
    username = os.environ.get("SMTP_USERNAME", "").strip()
    password = os.environ.get("SMTP_PASSWORD", "")
    port_raw = os.environ.get("SMTP_PORT", "465").strip() or "465"
    sender = os.environ.get("MAIL_FROM", "").strip() or username

    # 未配置就跳过：与 upload-webdav.sh 同样的策略，让未配置的人跑同一个
    # workflow 也能通过。
    if not to_addrs or not host or not username or not password:
        notice("邮件未配置完整（需 MAIL_TO / SMTP_HOST / SMTP_USERNAME / SMTP_PASSWORD），跳过发信")
        return 0

    try:
        port = int(port_raw)
    except ValueError:
        error(f"SMTP_PORT 不是数字：{port_raw}")
        return 1

    path = Path(body_file)
    if not path.is_file():
        # 没生成正文文件说明 Release 里没有产物，本来也无内容可发。
        notice(f"正文文件不存在（{body_file}），跳过发信")
        return 0

    body = path.read_text(encoding="utf-8")
    subject = os.environ.get("MAIL_SUBJECT", "").strip() or "OpenList CI 构建产物"

    msg = EmailMessage()
    # EmailMessage 会自动做 RFC 2047 头编码与 UTF-8 正文编码，
    # 中文标题/正文无需手工处理。
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = ", ".join(to_addrs)
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid()
    msg.set_content(body, charset="utf-8")

    context = ssl.create_default_context()

    try:
        if port == 465:
            server = smtplib.SMTP_SSL(host, port, timeout=TIMEOUT, context=context)
        else:
            server = smtplib.SMTP(host, port, timeout=TIMEOUT)
            server.starttls(context=context)

        with server:
            server.login(username, password)
            server.send_message(msg, from_addr=sender, to_addrs=to_addrs)
    except Exception as exc:  # noqa: BLE001 - 要把各种 SMTP 异常都报清楚
        # 常见失败：授权码错误(535)、未开 SMTP(502)、端口被封(超时)、
        # 发件人地址与登录账号不符(553)。
        error(f"发信失败：{type(exc).__name__}: {exc}")
        return 1

    notice(f"邮件已发送至 {', '.join(to_addrs)}（{len(body)} 字节正文）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
