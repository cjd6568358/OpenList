#!/usr/bin/env bash
#
# 把构建产物上传到 WebDAV。
#
# 环境变量：
#   WEBDAV_URL        WebDAV 根地址，如 https://dav.example.com/openlist
#   WEBDAV_USERNAME   用户名
#   WEBDAV_PASSWORD   密码
#   WEBDAV_REMOTE_DIR 可选，远程子目录，可含多级（如 a/b）
#
# 用法：upload-webdav.sh <文件> [文件...]
#
# 未配置 WEBDAV_URL 时打印 notice 并成功退出 —— 这样 fork 出来、
# 或没配 secret 的人跑同一个 workflow 也不会因为上传而失败。

set -euo pipefail

if [ -z "${WEBDAV_URL:-}" ]; then
  echo "::notice::WEBDAV_URL 未配置，跳过 WebDAV 上传"
  exit 0
fi
if [ -z "${WEBDAV_USERNAME:-}" ] || [ -z "${WEBDAV_PASSWORD:-}" ]; then
  echo "::warning::WEBDAV_URL 已配置，但缺少 WEBDAV_USERNAME / WEBDAV_PASSWORD，跳过上传"
  exit 0
fi
if [ "$#" -eq 0 ]; then
  echo "::error::未传入待上传文件"
  exit 1
fi

base="${WEBDAV_URL%/}"
# 允许调用方直接拼 "${{ vars.X }}/${{ matrix.a }}"：vars 为空时会多出前导斜杠，
# 这里统一规整，避免拼出 base//dir。
remote_dir="${WEBDAV_REMOTE_DIR:-}"
remote_dir="${remote_dir#/}"
remote_dir="${remote_dir%/}"

# 凭据写进临时 curl 配置文件，避免出现在 argv / 进程列表里。
rc="$(mktemp)"
trap 'rm -f "$rc"' EXIT
chmod 600 "$rc"
# curl 配置文件是双引号字符串，需转义 \ 和 "
esc() { printf '%s' "$1" | sed 's/[\\"]/\\&/g'; }
printf 'user = "%s:%s"\n' "$(esc "$WEBDAV_USERNAME")" "$(esc "$WEBDAV_PASSWORD")" >"$rc"

# 建目录。405/301/302 表示已存在或已重定向，都不影响后续 PUT，
# 因此只对真正的异常码告警，不中断上传。
# 注意 curl 失败时 -w '%{http_code}' 仍会打印 000，所以只需补 `|| true`
# 压掉非零退出码（否则 set -e 会中断），不能再 echo 一次 000。
mkcol() {
  local url="$1" code
  code=$(curl -sS -o /dev/null -w '%{http_code}' -K "$rc" -X MKCOL "$url" || true)
  case "$code" in
    201) echo "  已创建 $url" ;;
    405|301|302) echo "  已存在 $url ($code)" ;;
    *) echo "::warning::MKCOL $url -> HTTP $code" ;;
  esac
}

# 逐级创建，部分 WebDAV 服务不会自动建父目录。
if [ -n "$remote_dir" ]; then
  acc="$base"
  IFS='/' read -ra parts <<<"$remote_dir"
  for p in "${parts[@]}"; do
    [ -z "$p" ] && continue
    acc="$acc/$p"
    mkcol "$acc"
  done
fi

dest="$base"
[ -n "$remote_dir" ] && dest="$base/$remote_dir"

uploaded=0
for f in "$@"; do
  if [ ! -f "$f" ]; then
    echo "::error::文件不存在：$f"
    exit 1
  fi
  name="$(basename "$f")"
  code=$(curl -sS -o /dev/null -w '%{http_code}' -K "$rc" -T "$f" "$dest/$name" || true)
  case "$code" in
    200|201|204) echo "  已上传 $name -> $dest/$name (HTTP $code)" ;;
    *) echo "::error::上传失败 $f -> $dest/$name (HTTP $code)"; exit 1 ;;
  esac
  uploaded=$((uploaded + 1))
done

echo "WebDAV 上传完成：$uploaded 个文件 -> $dest"
