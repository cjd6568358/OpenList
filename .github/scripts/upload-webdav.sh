#!/usr/bin/env bash
#
# 上传文件到 WebDAV。
#
# 环境变量：
#   WEBDAV_URL        WebDAV 根地址，如 https://dav.example.com/openlist
#   WEBDAV_USERNAME   用户名
#   WEBDAV_PASSWORD   密码
#   WEBDAV_REMOTE_DIR 可选，远程子目录，可含多级（如 a/b）
#
# 用法：
#   upload-webdav.sh <本地文件> [本地文件...]   上传，落到远端同名位置
#
# 上传会先确保 WEBDAV_REMOTE_DIR 存在再 PUT，因此**不依赖任何前置 job**
#   去预先建目录：每个 job 各自跑本脚本都能成功，无需 needs: 一个建目录的
#   job 来保证顺序。OpenList 的 MKCOL 不会自动补建中间目录（缺父目录直接
#   409），所以脚本自己按需逐级补建 —— 见 ensure_dir 的注释。
#   建目录是幂等的：重跑同一 commit 会拿到 405（已存在），按正常处理。
#
# 未配置 WEBDAV_URL 时打印 notice 并成功退出 —— 这样 fork 出来、
# 或没配 secret 的人跑同一个 workflow 也不会因为上传而失败。
#
# 失败处理：一律硬失败。任何 HTTP 非 201/204 或传输出错都报 error 并退出 1。
#   瞬时 5xx 由 curl --retry 退避吸收；退避后仍失败即为真故障，不该吞掉。

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

# 建目录，使 dest 可用。**不依赖调用方先建好任何目录** —— 每个 job 各自
#   跑本脚本都不会失败，不需要 needs: 一个前置 job 来保证顺序。
#
# 返回码语义（对应 OpenList server/webdav/webdav.go 的 handleMkcol）：
#   201 已创建   —— 正常路径
#   405 已存在   —— RFC 4918 9.3.1 规定 MKCOL 只能作用于未映射的 URL。
#                   重跑时走到这里，属正常，不是错误。
#   409 父目录不存在 —— 服务端不会自动补建中间目录，需逐级补建。
#
# 策略：先试整条路径（1 次请求，稳态下就是 405，最常见）。
#   只有 409 才逐级补建 —— 这样普通路径不会为每层都发一次 MKCOL，
#   而多级路径首次运行时也能自愈，不必人工预建。
#
# 用 --retry 吸收瞬时 5xx（反代限流）。
# 注意 curl 失败时 -w '%{http_code}' 仍会打印 000，所以补 `|| true` 压掉
# 非零退出码（否则 set -e 会中断），不能再 echo 一次 000。
mkcol_once() {
  curl -sS -o /dev/null -w '%{http_code}' -K "$rc" \
    --retry 3 --retry-delay 2 --retry-max-time 60 \
    -X MKCOL "$1" || true
}

ensure_dir() {
  # $1 = base，$2 = 规整后的相对路径（可空）
  local acc="$1" code
  local rel="$2"

  if [ -z "$rel" ]; then
    return 0          # 直接传到 base，无需建任何目录
  fi

  code="$(mkcol_once "$acc/$rel")"
  case "$code" in
    201) echo "  已创建 $acc/$rel"; return 0 ;;
    405) echo "  已存在 $acc/$rel (405)"; return 0 ;;
    409) : ;;         # 父目录缺失，落到下面逐级补建
    *) echo "::error::创建目录失败 $acc/$rel -> HTTP $code"; exit 1 ;;
  esac

  # 逐级补建：从最外层开始，每建好一层再往下走，缺哪层补哪层。
  echo "  父目录缺失，逐级创建：$rel"
  local parts=() p
  IFS='/' read -ra parts <<<"$rel"
  for p in "${parts[@]}"; do
    [ -z "$p" ] && continue
    acc="$acc/$p"
    code="$(mkcol_once "$acc")"
    case "$code" in
      201) echo "  已创建 $acc" ;;
      405) echo "  已存在 $acc (405)" ;;
      409)
        # 连第一层都建不出来，说明缺的不是中间目录而是 base 本身 ——
        # base 是 WEBDAV_URL 指向的挂载根，本脚本不去创建它（那是部署方
        # 的职责），这里报清楚是配置问题，而不是含糊地怪到中间目录头上。
        if [ "$acc" = "$1/${parts[0]}" ]; then
          echo "::error::${1} 不存在（WEBDAV_URL 指向的目录缺失），无法创建 $acc"
        else
          echo "::error::创建目录失败 $acc -> HTTP 409（父目录不存在）"
        fi
        exit 1
        ;;
      *) echo "::error::创建目录失败 $acc -> HTTP $code"; exit 1 ;;
    esac
  done
}

ensure_dir "$base" "$remote_dir"
if [ -n "$remote_dir" ]; then
  dest="$base/$remote_dir"
else
  dest="$base"
fi

for f in "$@"; do
  if [ ! -f "$f" ]; then
    echo "::error::文件不存在：$f"
    exit 1
  fi
  name="$(basename "$f")"
  # --retry 同样吸收瞬时 5xx；4xx（如权限、路径不对）不重试。
  code=$(curl -sS -o /dev/null -w '%{http_code}' -K "$rc" \
    --retry 3 --retry-delay 2 --retry-max-time 120 \
    -T "$f" "$dest/$name" || true)
  case "$code" in
    200|201|204) echo "  已上传 $name -> $dest/$name (HTTP $code)" ;;
    *) echo "::error::上传失败 $f -> $dest/$name (HTTP $code)"; exit 1 ;;
  esac
done

echo "WebDAV 上传完成：$# 个文件 -> $dest"
