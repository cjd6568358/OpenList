#!/usr/bin/env bash
#
# 生成「代理加速下载地址」txt，按代理域名分组。
#
# 用法：
#   gen-proxy-txt.sh <tag> <repo> <out-file>
#     <tag>       Release tag，如 ci-e73bac6
#     <repo>      owner/repo，如 cjd6568358/OpenList
#     <out-file>  输出路径，如 proxy_<sha>.txt
#
# 产物清单直接问 GitHub 要（gh release view）。好处是 matrix 增删变体后
# 这里无需同步修改；失败的变体根本没进 Release，也就不会出现在 txt 里。
#
# 需要调用方注入 GH_TOKEN。
#
# release 不存在或没有任何 7z 产物时：打 notice 并成功退出，不生成文件。

set -euo pipefail

tag="${1:?用法: gen-proxy-txt.sh <tag> <repo> <out-file>}"
repo="${2:?缺少 repo}"
out="${3:?缺少 out-file}"

# 代理列表：增删改这一行即可。
PROXIES="ghfast.top v6.gh-proxy.org hk.gh-proxy.org cdn.gh-proxy.org edgeone.gh-proxy.org"

# release 可能不存在（例如所有 build job 都失败在创建 release 之前），
# 此时 gh 会非零退出，用 || true 压掉以免 set -e 中断。
assets="$(gh release view "$tag" --repo "$repo" --json assets --jq '.assets[].name' 2>/dev/null \
  | grep '\.7z$' | sort || true)"

if [ -z "$assets" ]; then
  echo "::notice::release $tag 没有 7z 产物，跳过生成代理链接 txt"
  exit 0
fi
scope_desc="全部 $(printf '%s\n' "$assets" | wc -l | tr -d ' ') 个产物"

{
  echo "# OpenList CI 构建产物：代理加速下载地址"
  echo "# release : ${tag}  (${repo})"
  echo "# 范围    : ${scope_desc}"
  echo "# 文件名含义：openlist_<target>_<frontend>_<compress>.7z"
  echo "# 下面按代理域名分组，每组列出的都是全部产物，取需要的那个即可。"
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
