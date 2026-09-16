#!/usr/bin/env bash
#
# 生成「代理加速下载地址」txt，按代理域名分组。
#
# 两种用法：
#   1) 单变体（build job 用，上传完 Release 后立刻生成，尽早给出下载地址）
#        gen-proxy-txt.sh <tag> <repo> <out-file> <asset>
#      只列 <asset> 这一个产物，不查 Release —— 这一步紧跟在自己的
#      gh release upload 之后，asset 必然已存在，查一遍是多余的 API 调用。
#
#   2) 全部产物（summarize job 用，末尾汇总）
#        gen-proxy-txt.sh <tag> <repo> <out-file>
#      直接问 GitHub 要该 Release 的 asset 列表。好处是 matrix 增删变体后
#      这里无需同步修改；失败的变体根本没进 Release，也就不会出现在 txt 里。
#
#   tag       Release tag，如 ci-e73bac6
#   repo      owner/repo，如 cjd6568358/OpenList
#   out-file  输出路径
#   asset     可选，单个 7z 文件名；给了就只列它
#
# 需要调用方注入 GH_TOKEN（用法 2 必需；用法 1 不查 Release，可以不设）。
#
# 用法 2 在 release 不存在或没有任何 7z 产物时：打 notice 并成功退出，不生成文件。

set -euo pipefail

tag="${1:?用法: gen-proxy-txt.sh <tag> <repo> <out-file> [asset]}"
repo="${2:?缺少 repo}"
out="${3:?缺少 out-file}"
only="${4:-}"

# 代理列表：增删改这一行即可。
PROXIES="ghfast.top v6.gh-proxy.org hk.gh-proxy.org cdn.gh-proxy.org edgeone.gh-proxy.org"

if [ -n "$only" ]; then
  assets="$only"
  scope_desc="变体 ${only}"
else
  # release 可能不存在（例如所有 build job 都失败在创建 release 之前），
  # 此时 gh 会非零退出，用 || true 压掉以免 set -e 中断。
  assets="$(gh release view "$tag" --repo "$repo" --json assets --jq '.assets[].name' 2>/dev/null \
    | grep '\.7z$' | sort || true)"

  if [ -z "$assets" ]; then
    echo "::notice::release $tag 没有 7z 产物，跳过生成代理链接 txt"
    exit 0
  fi
  scope_desc="全部 $(printf '%s\n' "$assets" | wc -l | tr -d ' ') 个产物"
fi

{
  echo "# OpenList CI 构建产物：代理加速下载地址"
  echo "# release : ${tag}  (${repo})"
  echo "# 范围    : ${scope_desc}"
  echo "# 文件名含义：openlist_<target>_<frontend>_<compress>.7z"
  if [ -n "$only" ]; then
    echo "# 本文件只含该变体。全部变体的汇总见同目录 proxy.txt。"
  else
    echo "# 下面按代理域名分组，每组列出的都是全部产物，取需要的那个即可。"
  fi
  echo

  # 只列代理入口，不给 GitHub 直链：这份文件的用途就是走加速，
  # 直链混在里面反而让人在多个域名间多犹豫一次。
  for p in $PROXIES; do
    echo "=== ${p} ==="
    for a in $assets; do
      echo "https://${p}/https://github.com/${repo}/releases/download/${tag}/${a}"
    done
    echo
  done

  echo "# 链接形式为 https://<代理域名>/https://github.com/... 的裸串直拼。"
  echo "# 若某个域名下全部 404，说明该代理不认这种拼接形式，换其它域名即可。"
} > "$out"

groups="$(printf '%s' "$PROXIES" | wc -w | tr -d ' ')"
echo "已生成 ${out}：${scope_desc} × ${groups} 个代理域名"
