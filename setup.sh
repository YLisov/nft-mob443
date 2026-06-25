#!/usr/bin/env bash
# ═════════════════════════════════════════════════════════════════════
#  mobile443.sh — единый скрипт: данные + автообновление.
#
#  Делает ВСЁ, кроме самих правил nftables (их ставишь вручную / Ansible):
#    • качает blocklist'ы government / antiscanner (CIDR);
#    • резолвит мобильные ASN -> IPv4-префиксы через RIPEstat;
#    • атомарно заливает их в уже существующие named-сеты nftables;
#    • ставит systemd timer (ежедневно) + restore при загрузке.
#
#  Использование:
#    bash <(curl -Ls https://raw.githubusercontent.com/YLisov/nft-mob443/refs/heads/main/setup.sh)            # install (по умолчанию)
#    bash <(curl -Ls https://raw.githubusercontent.com/YLisov/nft-mob443/refs/heads/main/setup.sh) update     # только обновить данные
#    bash <(curl -Ls https://raw.githubusercontent.com/YLisov/nft-mob443/refs/heads/main/setup.sh) remove     # снести всё, что поставил скрипт
#
#  Сеты и цепочку фильтрации создаёшь в своём nftables-конфиге заранее
#  (см. блок mobile443 в table inet filter). Этот скрипт их только наполняет.
# ═════════════════════════════════════════════════════════════════════
set -Eeuo pipefail

VERSION="1.0"

# raw-URL этого файла в репозитории (нужно для install по curl).
# При необходимости переопредели через MOBILE443_SELF_URL.
SELF_URL_DEFAULT="https://raw.githubusercontent.com/YLisov/nft-mob443/refs/heads/main/setup.sh"
SELF_URL="${MOBILE443_SELF_URL:-$SELF_URL_DEFAULT}"

ACTION="${1:-install}"

# ---- пути (можно переопределить env-переменными, удобно для теста) ----
BASE_DIR="${MOBILE443_BASE_DIR:-/opt/mobile443}"
STATE_DIR="${MOBILE443_STATE_DIR:-/var/lib/mobile443}"
BIN_PATH="${MOBILE443_BIN_PATH:-/usr/local/sbin/mobile443}"
UNIT_DIR="${MOBILE443_UNIT_DIR:-/etc/systemd/system}"
CONF_FILE="${BASE_DIR}/mobile443.conf"
ASNS_FILE="${BASE_DIR}/asns.conf"

# ---- дефолты конфига (пишутся в CONF_FILE при install, читаются при update) ----
NFT_TABLE="inet filter"                 # таблица, где живут сеты (твоя основная)
SET_GOV="m443_gov"
SET_ANTI="m443_antiscanner"
SET_MOBILE="m443_mobile_allow"

TRAF_GUARD_BASE_URL="https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public"
GOV_LIST_URL="${TRAF_GUARD_BASE_URL}/government_networks.list"
ANTISCANNER_LIST_URL="${TRAF_GUARD_BASE_URL}/antiscanner.list"

ENABLE_GOV="true"
ENABLE_ANTISCANNER="true"
ENABLE_MOBILE_ALLOW="true"

MIN_MOBILE_PREFIXES=500                  # меньше -> отказ (битый ответ RIPE)
SAFETY_RATIO=70                          # новый < старого*70% -> отказ, оставляем старый
RESTORE_FILE=""                          # default ${STATE_DIR}/restore.nft

log() { echo "[$(date '+%F %T')] $*"; }
die() { echo "[$(date '+%F %T')] ERROR: $*" >&2; exit 1; }

require_root() { [[ "$(id -u)" -eq 0 ]] || die "запусти от root"; }
need_cmd()     { command -v "$1" >/dev/null 2>&1 || die "нет команды: $1"; }

# временные файлы складываем в один каталог и сносим его на выходе.
# (RETURN-trap с локальными переменными под set -u падает в вызывающей функции,
#  а массив, наполняемый внутри $(...), не доходит до родителя — поэтому каталог.)
WORKDIR="$(mktemp -d)"
trap '[[ -n "${WORKDIR:-}" ]] && rm -rf "$WORKDIR"' EXIT
mktmp() { mktemp -p "$WORKDIR"; }

# поставить недостающие зависимости (nftables/jq/curl); coreutils/gawk проверяем
ensure_deps() {
  local -a pkgs=()
  command -v nft  >/dev/null 2>&1 || pkgs+=(nftables)
  command -v jq   >/dev/null 2>&1 || pkgs+=(jq)
  command -v curl >/dev/null 2>&1 || pkgs+=(curl)

  if (( ${#pkgs[@]} > 0 )); then
    log "Ставлю зависимости: ${pkgs[*]}"
    if   command -v apt-get >/dev/null 2>&1; then
      DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null 2>&1 || true
      DEBIAN_FRONTEND=noninteractive apt-get install -y "${pkgs[@]}"
    elif command -v dnf >/dev/null 2>&1; then
      dnf install -y "${pkgs[@]}"
    elif command -v yum >/dev/null 2>&1; then
      yum install -y "${pkgs[@]}"
    else
      die "не нашёл apt/dnf/yum — поставь вручную: ${pkgs[*]}"
    fi
  fi

  # обязательные команды (в т.ч. те, что не ставим — должны быть в базовой системе)
  need_cmd nft; need_cmd jq; need_cmd curl
  need_cmd awk; need_cmd sed; need_cmd sort
}

# подтянуть конфиг (если есть) и вывести производные пути
load_config() {
  # shellcheck disable=SC1090
  [[ -f "$CONF_FILE" ]] && source "$CONF_FILE"
  RESTORE_FILE="${RESTORE_FILE:-${STATE_DIR}/restore.nft}"
  GOV_FILE="${STATE_DIR}/government.list"
  ANTI_FILE="${STATE_DIR}/antiscanner.list"
  MOBILE_FILE="${STATE_DIR}/mobile_allow.list"
}

# ─────────────────────────── данные ───────────────────────────

count_lines() { [[ -f "$1" ]] && awk 'END{print NR+0}' "$1" || echo 0; }

validate_ipv4_cidr() {
  local p="$1" ip mask octet
  local IFS=.
  [[ "$p" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]] || return 1
  ip="${p%/*}"; mask="${p#*/}"
  (( mask >= 0 && mask <= 32 )) || return 1
  for octet in $ip; do
    (( octet >= 0 && octet <= 255 )) || return 1
  done
}

# stdin: сырой список -> stdout: валидные IPv4-CIDR, без комментов, уникально, сортировано
clean_cidr_stream() {
  local line norm
  while IFS= read -r line || [[ -n "$line" ]]; do
    norm="$(sed 's/[[:space:]]*#.*$//; s/^[[:space:]]*//; s/[[:space:]]*$//' <<<"$line")"
    [[ -n "$norm" ]] || continue
    if validate_ipv4_cidr "$norm"; then echo "$norm"; fi
  done | sort -Vu
}

download_list() {
  local url="$1" dest="$2" label="$3" tmp new old min
  tmp="$(mktmp)"
  log "Качаю ${label}: ${url}"
  curl -fsS --retry 3 --retry-delay 2 --connect-timeout 10 --max-time 60 "$url" \
    | clean_cidr_stream > "$tmp" || die "${label}: ошибка загрузки"
  new="$(count_lines "$tmp")"
  (( new > 0 )) || die "${label}: ни одной валидной CIDR-записи"
  old="$(count_lines "$dest")"
  if (( old > 0 )); then
    min=$(( old * SAFETY_RATIO / 100 ))
    (( new >= min )) || die "${label}: подозрительное усыхание ($new < $min), оставляю старый"
  fi
  install -m 0644 "$tmp" "$dest"
  log "${label}: ${new} записей"
}

resolve_mobile_allowlist() {
  [[ -f "$ASNS_FILE" ]] || die "нет файла ASN: $ASNS_FILE"
  local raw clean asn new old min
  raw="$(mktmp)"; clean="$(mktmp)"
  log "Резолвлю мобильные ASN через RIPEstat"
  while IFS= read -r asn || [[ -n "$asn" ]]; do
    asn="$(sed 's/[[:space:]]*#.*$//' <<<"$asn" | tr -cd '0-9')"
    [[ -n "$asn" ]] || continue
    if ! curl -fsS --retry 3 --retry-delay 2 --connect-timeout 10 --max-time 30 \
          "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS${asn}" \
          | jq -r '.data.prefixes[]?.prefix // empty' >> "$raw"; then
      log "WARN AS${asn}: запрос не удался, пропускаю"
    fi
  done < "$ASNS_FILE"
  clean_cidr_stream < "$raw" > "$clean"
  new="$(count_lines "$clean")"
  (( new >= MIN_MOBILE_PREFIXES )) || die "mobile allowlist: слишком мало префиксов ($new < $MIN_MOBILE_PREFIXES)"
  old="$(count_lines "$MOBILE_FILE")"
  if (( old > 0 )); then
    min=$(( old * SAFETY_RATIO / 100 ))
    (( new >= min )) || die "mobile allowlist: подозрительное усыхание ($new < $min), оставляю старый"
  fi
  install -m 0644 "$clean" "$MOBILE_FILE"
  log "mobile allowlist: ${new} префиксов"
}

ensure_table_and_sets() {
  nft list table ${NFT_TABLE} >/dev/null 2>&1 || nft add table ${NFT_TABLE}
  local s
  for s in "$SET_GOV" "$SET_ANTI" "$SET_MOBILE"; do
    nft list set ${NFT_TABLE} "$s" >/dev/null 2>&1 \
      || nft add set ${NFT_TABLE} "$s" { type ipv4_addr\; flags interval\; auto-merge\; }
  done
}

emit_set_block() {
  local set="$1" file="$2" n=0 buf="" p
  echo "flush set ${NFT_TABLE} ${set}"
  [[ -f "$file" ]] || return 0
  while IFS= read -r p || [[ -n "$p" ]]; do
    [[ -n "$p" ]] || continue
    buf+="${buf:+, }$p"; n=$(( n + 1 ))
    if (( n % 1000 == 0 )); then echo "add element ${NFT_TABLE} ${set} { $buf }"; buf=""; fi
  done < "$file"
  [[ -n "$buf" ]] && echo "add element ${NFT_TABLE} ${set} { $buf }"
  return 0
}

apply_to_nft() {
  ensure_table_and_sets
  local f; f="$(mktmp)"
  {
    [[ "$ENABLE_GOV"          == "true" ]] && emit_set_block "$SET_GOV"    "$GOV_FILE"
    [[ "$ENABLE_ANTISCANNER"  == "true" ]] && emit_set_block "$SET_ANTI"   "$ANTI_FILE"
    [[ "$ENABLE_MOBILE_ALLOW" == "true" ]] && emit_set_block "$SET_MOBILE" "$MOBILE_FILE"
  } > "$f"
  log "Заливаю сеты в nftables (атомарно)"
  nft -f "$f"
  install -m 0644 "$f" "$RESTORE_FILE"
  log "nftables-сеты обновлены, кэш: $RESTORE_FILE"
}

# ─────────────────────────── развёртывание ───────────────────────────

write_default_config() {
  [[ -s "$CONF_FILE" ]] && { log "config уже есть, не трогаю: $CONF_FILE"; return; }
  cat > "$CONF_FILE" <<EOF
# /opt/mobile443/mobile443.conf — наполнение nftables-сетов.
# Сеты должны существовать в этой таблице (создаются твоими nft-правилами).
NFT_TABLE="${NFT_TABLE}"
SET_GOV="${SET_GOV}"
SET_ANTI="${SET_ANTI}"
SET_MOBILE="${SET_MOBILE}"

TRAF_GUARD_BASE_URL="${TRAF_GUARD_BASE_URL}"
GOV_LIST_URL="\${TRAF_GUARD_BASE_URL}/government_networks.list"
ANTISCANNER_LIST_URL="\${TRAF_GUARD_BASE_URL}/antiscanner.list"

ENABLE_GOV="${ENABLE_GOV}"
ENABLE_ANTISCANNER="${ENABLE_ANTISCANNER}"
ENABLE_MOBILE_ALLOW="${ENABLE_MOBILE_ALLOW}"

MIN_MOBILE_PREFIXES=${MIN_MOBILE_PREFIXES}
SAFETY_RATIO=${SAFETY_RATIO}
RESTORE_FILE="${STATE_DIR}/restore.nft"
EOF
  log "Записан конфиг: $CONF_FILE"
}

write_default_asns() {
  [[ -s "$ASNS_FILE" ]] && { log "asns.conf уже есть, не трогаю: $ASNS_FILE"; return; }
  cat > "$ASNS_FILE" <<'EOF'
# === Mobile-focused allowlist for Russia ===
# Основные мобильные сети + важные MVNO-пути + Ростелеком.
# Один ASN (число) на строку, комментарии через '#'.

# MTS
8359
13174
21365
30922
34351

# Beeline / VimpelCom
3216
16043
16345
42842

# MegaFon core + related
31133
8263
6854
50928
48615
47395
47218
43841
42891
41976
35298
34552
31268
31224
31213
31208
31205
31195
31163
29648
25290
25159
24866
20663
20632
12396
202804

# T2 regional
12958
15378
42437
48092
48190
41330
13116

# Miranda
201776

# Sberbank-Telecom
206673

# Rostelecom
12389

# Sevastar (Stavropol)
35816

# T-mobile + Alfa-mobile
205638
214257
202498

# Volna-Mobile
203451
203561

# MCS
47204

# MOTIV telecom
31499
EOF
  log "Записан список ASN: $ASNS_FILE"
}

install_self() {
  if [[ -f "$0" && -r "$0" && "$0" != /dev/* && "$0" != /proc/* ]]; then
    install -m 0755 "$0" "$BIN_PATH"
  else
    [[ "$SELF_URL" == *CHANGE_ME* ]] && die "SELF_URL не настроен — впиши raw-URL репозитория в начало скрипта"
    log "Скачиваю себя из $SELF_URL"
    curl -fsSL "$SELF_URL" -o "$BIN_PATH"
    chmod 0755 "$BIN_PATH"
  fi
  log "Установлен бинарь: $BIN_PATH"
}

write_units() {
  local nft_bin; nft_bin="$(command -v nft || echo /usr/sbin/nft)"

  cat > "${UNIT_DIR}/mobile443-update.service" <<EOF
[Unit]
Description=mobile443 — обновление списков и nftables-сетов
After=network-online.target nftables.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${BIN_PATH} update
EOF

  cat > "${UNIT_DIR}/mobile443-update.timer" <<EOF
[Unit]
Description=mobile443 — ежедневное обновление

[Timer]
OnCalendar=*-*-* 00:00:00
RandomizedDelaySec=300
Persistent=true

[Install]
WantedBy=timers.target
EOF

  cat > "${UNIT_DIR}/mobile443-restore.service" <<EOF
[Unit]
Description=mobile443 — восстановление nftables-сетов из кэша при загрузке
After=nftables.service
Wants=nftables.service
ConditionPathExists=${RESTORE_FILE}

[Service]
Type=oneshot
ExecStart=${nft_bin} -f ${RESTORE_FILE}

[Install]
WantedBy=multi-user.target
EOF

  log "Записаны systemd-юниты в ${UNIT_DIR}"
}

# ─────────────────────────── команды ───────────────────────────

cmd_update() {
  require_root
  need_cmd curl; need_cmd jq; need_cmd nft
  need_cmd awk;  need_cmd sed; need_cmd sort
  load_config
  mkdir -p "$STATE_DIR"
  [[ "$ENABLE_GOV"          == "true" ]] && download_list "$GOV_LIST_URL"         "$GOV_FILE"  "government"
  [[ "$ENABLE_ANTISCANNER"  == "true" ]] && download_list "$ANTISCANNER_LIST_URL" "$ANTI_FILE" "antiscanner"
  [[ "$ENABLE_MOBILE_ALLOW" == "true" ]] && resolve_mobile_allowlist
  apply_to_nft
  log "update: готово."
}

cmd_install() {
  require_root
  ensure_deps
  need_cmd systemctl
  mkdir -p "$BASE_DIR" "$STATE_DIR"
  write_default_config
  write_default_asns
  load_config
  install_self
  write_units
  systemctl daemon-reload
  systemctl enable --now mobile443-update.timer
  systemctl enable mobile443-restore.service   # сработает при следующей загрузке
  log "Юниты включены. Делаю первичное наполнение сетов..."
  cmd_update
  cat <<EOF

✅ Установка завершена.
   Проверка:   nft list set ${NFT_TABLE} ${SET_MOBILE} | head
   Таймер:     systemctl list-timers | grep mobile443
   Логи:       journalctl -u mobile443-update.service --no-pager | tail

ℹ️  Правила nftables (table/set/chain mobile443) этот скрипт НЕ ставит —
   они должны уже быть в твоём конфиге. Сеты ${SET_GOV}/${SET_ANTI}/${SET_MOBILE}
   при пустом allowlist режут 443 целиком, поэтому наполняй их сразу после
   каждого 'flush ruleset' (хендлер Ansible -> '${BIN_PATH} update').
EOF
}

cmd_remove() {
  require_root
  systemctl disable --now mobile443-update.timer    2>/dev/null || true
  systemctl disable mobile443-restore.service       2>/dev/null || true
  systemctl stop    mobile443-update.service        2>/dev/null || true
  rm -f "${UNIT_DIR}/mobile443-update.service" \
        "${UNIT_DIR}/mobile443-update.timer" \
        "${UNIT_DIR}/mobile443-restore.service"
  systemctl daemon-reload 2>/dev/null || true
  rm -rf "$BASE_DIR" "$STATE_DIR"
  rm -f "$BIN_PATH"
  log "Удалены файлы и systemd-юниты mobile443."
  cat <<EOF

ℹ️  nftables-правила НЕ тронуты (ими управляешь ты / Ansible).
   Чтобы убрать фильтрацию: удали блок mobile443 (set'ы + chain + jump на 443)
   из своего nft-конфига и применить: nft -f /etc/nftables.conf
EOF
}

usage() {
  cat <<EOF
mobile443.sh v${VERSION}
  install   развернуть: конфиг, ASN, systemd timer + restore, первое наполнение (по умолчанию)
  update    только обновить данные и залить в nftables (её вызывает таймер)
  remove    снести всё, что поставил скрипт (nft-правила не трогает)
EOF
}

main() {
  case "$ACTION" in
    install) cmd_install ;;
    update)  cmd_update ;;
    remove)  cmd_remove ;;
    -h|--help|help) usage ;;
    *) usage; die "неизвестная команда: $ACTION" ;;
  esac
}

# запускаем main только при прямом вызове (не при source — удобно для тестов)
if [[ "${BASH_SOURCE[0]:-$0}" == "${0}" ]]; then
  main "$@"
fi
