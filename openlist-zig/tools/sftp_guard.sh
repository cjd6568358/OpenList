#!/bin/sh
# =========================================================================
#  /opt/armbian/bin/openlist/sftp_guard.sh —— OpenList(SFTP :15222) 字典爆破守卫
#
#  背景（2026-10-13 实测）：
#    172.232.196.144 等扫描器对 :15222 做用户名字典爆破，每次探测刷
#    1 INFO + 2 ERRO，日志狂涨。OpenList 自带的 5 次/5 分钟限速对其无效 ——
#    失败计数 key 是「IP:端口」（Go server/sftp.go:96 用
#    conn.RemoteAddr().String()），每个新连接源端口都不同 ⇒ 计数永不到 5 ⇒
#    永不锁；none 认证路径（NoClientAuth）更是完全没有限速。
#    这是上游 bug；Web/WebDAV 路径用 c.ClientIP()（纯 IP）所以那边是好的。
#
#  内核能力实测（192.168.1.1 光猫，kernel 4.1.25）：
#    - /proc/net/ip_tables_matches 无 recent；iptables -m recent 插规则报
#      "No chain/target/match by that name" ⇒ xt_recent 方案不可行
#    - ipset 不存在（/proc/net/ip_set也没有）⇒ ipset 方案不可行
#  故用本脚本在 userspace 做计数器，语义等价且自动解封：
#
#    规则：同一 IP 在 1 小时窗口内第 12 次连接尝试起，DROP 其发往 :15222
#          的包；封禁满 1 小时自动删规则解封；封禁期间继续犯则续期 1 小时。
#    计数依据：日志 INFO 行「[SFTP] user(IP:port) tries logging in via …」
#      （每次认证尝试一条；none 认证的 ERRO 行不带 IP，统计不到 —— 实测攻击者
#       两种认证都会发，INFO 行足以命中）。
#
#  状态全在 /tmp（tmpfs，重启清零；iptables 规则重启同样清空，语义自洽）。
#  日志：/tmp/sftp_guard.log（每次封/解封一行）。
#
#  用法（user_init.sh 开机段）：
#    /bin/sh /opt/armbian/bin/openlist/sftp_guard.sh >>/tmp/sftp_guard.log 2>&1 &
#    单实例由 /tmp/sftp_guard.pid 保证；已在跑时重复执行会自行退出。
# =========================================================================

LOG=/tmp/openlist.log      # Go 版 OpenList 日志（config.json: log.name）
PORT=15222                 # config.json: sftp.listen
WIN=3600                   # 统计窗口 == 封禁时长（秒）
THRESH=12                  # 窗口内第 N 次尝试起封
STATE=/tmp/sftp_guard.state
BAN=/tmp/sftp_guard.ban
PIDFILE=/tmp/sftp_guard.pid
LOGF=/tmp/sftp_guard.log

# ---------------- 单实例 ----------------
if [ -f "$PIDFILE" ]; then
  OLD=$(cat "$PIDFILE" 2>/dev/null)
  if [ -n "$OLD" ] && kill -0 "$OLD" 2>/dev/null; then
    exit 0
  fi
fi
echo $$ > "$PIDFILE"
trap 'rm -f "$PIDFILE"; exit 0' INT TERM

[ -f "$STATE" ] || : > "$STATE"
[ -f "$BAN" ]   || : > "$BAN"

while true; do
  NOW=$(date +%s)

  # ---------------- 1) 解封到期 ----------------
  if [ -s "$BAN" ]; then
    : > /tmp/.sg.keep
    while read BIP BTS; do
      if [ -n "$BIP" ] && [ $((NOW - BTS)) -ge "$WIN" ]; then
        iptables -D INPUT -s "$BIP" -p tcp --dport "$PORT" -j DROP 2>/dev/null
        echo "$(date '+%F %T') [unban] $BIP (held ${WIN}s)" >> "$LOGF"
      else
        [ -n "$BIP" ] && echo "$BIP $BTS" >> /tmp/.sg.keep
      fi
    done < "$BAN"
    mv /tmp/.sg.keep "$BAN"
  fi

  # ---------------- 2) 扫日志增量（追加型文件按字节偏移，避免重复计数） ----------------
  OFF=0
  [ -f "$STATE.off" ] && OFF=$(cat "$STATE.off" 2>/dev/null)
  case "$OFF" in ''|*[!0-9]*) OFF=0 ;; esac
  SIZE=$(wc -c < "$LOG" 2>/dev/null)
  case "$SIZE" in ''|*[!0-9]*) SIZE=0 ;; esac
  [ "$OFF" -gt "$SIZE" ] && OFF=0          # 日志被 rotate/截断 ⇒ 从头扫
  NEW=$(tail -c +$((OFF + 1)) "$LOG" 2>/dev/null \
        | grep "tries logging in via" 2>/dev/null \
        | grep -o "([0-9.]*:[0-9]*)" 2>/dev/null \
        | tr -d "()" | cut -d: -f1 \
        | sort | uniq -c)
  echo "$SIZE" > "$STATE.off"

  # ---------------- 3) 合并进 1 小时窗口计数 ----------------
  if [ -n "$NEW" ]; then
    {
      while read SIP SCNT; do
        [ -n "$SIP" ] && printf 'OLD %s\n' "$SIP"
      done < "$STATE"
      printf '%s\n' "$NEW" | while read N IP; do
        [ -n "$IP" ] && printf 'NEW %s %s\n' "$IP" "$N"
      done
    } | awk -v now="$NOW" -v win="$WIN" '
      $1=="OLD" { ip=$2; first[ip]=$3; cnt[ip]=$4; mark[ip]=1; next }
      $1=="NEW" { ip=$2; newn[ip]+=$3; mark[ip]=1; next }
      END {
        for (ip in mark) {
          f = (ip in first) ? first[ip] : 0
          c = ((ip in cnt) ? cnt[ip] : 0) + ((ip in newn) ? newn[ip] : 0)
          if (f > 0 && now - f >= win) { f = now; c = newn[ip]+0 }   # 窗口过期重置
          if (f == 0) f = now
          print ip, f, c
        }
      }' > /tmp/.sg.state
    mv /tmp/.sg.state "$STATE"
  else
    awk -v now="$NOW" -v win="$WIN" '
      { if (now - $2 >= win) { print $1, now, 0 } else print }
    ' "$STATE" > /tmp/.sg.state
    mv /tmp/.sg.state "$STATE"
  fi

  # ---------------- 4) 达阈值 → 封（或续期） ----------------
  while read IP FST CNT; do
    [ -n "$IP" ] || continue
    [ "$CNT" -ge "$THRESH" ] || continue
    if grep -q "^$IP " "$BAN" 2>/dev/null; then
      grep -v "^$IP " "$BAN" > /tmp/.sg.ban.tmp 2>/dev/null
      echo "$IP $NOW" >> /tmp/.sg.ban.tmp
      mv /tmp/.sg.ban.tmp "$BAN"
    else
      if iptables -I INPUT 1 -s "$IP" -p tcp --dport "$PORT" -j DROP 2>>"$LOGF"; then
        echo "$(date '+%F %T') [ban] $IP attempts=$CNT" >> "$LOGF"
        echo "$IP $NOW" >> "$BAN"
      fi
    fi
  done < "$STATE"

  sleep 60
done
