#!/usr/bin/env bash
#
# 上传文件到 WebDAV，或删除 WebDAV 上的文件。
#
# 环境变量：
#   WEBDAV_URL        WebDAV 根地址，如 https://dav.example.com/openlist
#   WEBDAV_USERNAME   用户名
#   WEBDAV_PASSWORD   密码
#   WEBDAV_REMOTE_DIR 可选，远程子目录，可含多级（如 a/b）
#
# 用法：
#   upload-webdav.sh <本地文件> [本地文件...]        上传，落到远端同名位置
#   upload-webdav.sh --delete <远端名字> [名字...]   删除远端同名文件
#
# 未配置 WEBDAV_URL 时打印 notice 并成功退出 —— 这样 fork 出来、
# 或没配 secret 的人跑同一个 workflow 也不会因为上传/删除而失败。

set -euo pipefail

mode="upload"
if [ "${1:-}" = "--delete" ]; then
  mode="delete"
  shift
fi

if [ -z "${WEBDAV_URL:-}" ]; then
  echo "::notice::WEBDAV_URL 未配置，跳过 WebDAV ${mode}"
  exit 0
fi
if [ -z "${WEBDAV_USERNAME:-}" ] || [ -z "${WEBDAV_PASSWORD:-}" ]; then
  echo "::warning::WEBDAV_URL 已配置，但缺少 WEBDAV_USERNAME / WEBDAV_PASSWORD，跳过 ${mode}"
  exit 0
fi
if [ "$#" -eq 0 ]; then
  if [ "$mode" = "delete" ]; then
    # 清理名单可能为空（例如 Release 里一个 7z 都没有），不是错误。
    echo "::notice::未传入待删除的远端名字，无需操作"
    exit 0
  fi
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

# 删模式不去建目录：要删的前提是目录已存在，真不存在时 DELETE 会 404，
# 下面按「目标不存在」容忍掉即可 —— 顺手 MKCOL 一个空目录是不该有的副作用。
if [ "$mode" = "upload" ] && [ -n "$remote_dir" ]; then
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

done_count=0
for f in "$@"; do
  case "$mode" in
    upload)
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
      ;;
    delete)
      # 这里传进来的就是远端文件名本身，不做 basename 处理，
      # 以免调用方本想删子路径时被静默截断。
      name="$f"
      code=$(curl -sS -o /dev/null -w '%{http_code}' -K "$rc" -X DELETE "$dest/$name" || true)
      case "$code" in
        200|204) echo "  已删除 $dest/$name (HTTP $code)" ;;
        # 404 是预期情况：变体失败时根本没传过 txt。不算错误。
        404) echo "  目标不存在，跳过 $dest/$name (HTTP 404)" ;;
        *) echo "::error::删除失败 $dest/$name (HTTP $code)"; exit 1 ;;
      esac
      ;;
  esac
  done_count=$((done_count + 1))
done

case "$mode" in
  upload) echo "WebDAV 上传完成：$done_count 个文件 -> $dest" ;;
  delete) echo "WebDAV 删除完成：$done_count 个目标 -> $dest" ;;
esac
