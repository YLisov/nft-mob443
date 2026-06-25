# nft-mob443

Фильтр входящего трафика на VPN-порту для нод на базе nftables: на порт `443`
пропускаются только IP из **мобильных ASN**, а сети из блок-листов
`government` / `antiscanner` режутся. Скрипт `setup.sh` отвечает **только за данные** —
качает списки, резолвит ASN в префиксы через RIPEstat и атомарно заливает их в
named-сеты nftables. Сами правила фильтрации ты добавляешь в свой nftables-конфиг
(см. ниже) — скрипт их не трогает.

## Быстрый старт

Сначала добавь правила в `/etc/nftables.conf` (блок [Правила nftables](#правила-nftables)) и применить их.
Затем разверни наполнение сетов:

```bash
bash <(curl -Ls https://raw.githubusercontent.com/YLisov/nft-mob443/refs/heads/main/setup.sh)
```

Эта команда (действие `install` по умолчанию) ставит конфиг, список ASN, systemd
timer + restore-юнит и делает первое наполнение сетов.

## Зависимости

```bash
sudo apt install -y nftables jq curl
```

## Команды

```bash
# установка (конфиг, ASN, systemd timer + restore, первое наполнение)
bash <(curl -Ls https://raw.githubusercontent.com/YLisov/nft-mob443/refs/heads/main/setup.sh)

# только обновить данные и залить в nftables (её же дёргает таймер)
bash <(curl -Ls https://raw.githubusercontent.com/YLisov/nft-mob443/refs/heads/main/setup.sh) update

# снести всё, что поставил скрипт (nft-правила не трогает)
bash <(curl -Ls https://raw.githubusercontent.com/YLisov/nft-mob443/refs/heads/main/setup.sh) remove
```

## Правила nftables

Эти правила нужно вставить **вручную** в свой конфиг. Скрипт создаёт пустые сеты,
если их нет, но цепочку и `jump` на порт не добавляет. Сеты живут внутри основной
таблицы `inet filter`, чтобы их не стирал `flush ruleset`.

```nft
table inet filter {

    # наполняет setup.sh — объявляем пустыми
    set m443_gov          { type ipv4_addr; flag interval; auto-merge; }
    set m443_antiscanner  { type ipv4_addr; flag interval; auto-merge; }
    set m443_mobile_allow { type ipv4_addr; flag interval; auto-merge; }

    chain mobile443 {
        ip saddr @m443_gov          counter drop
        ip saddr @m443_antiscanner  counter drop
        ip saddr @m443_mobile_allow counter accept
        log prefix "mobile443-drop " level info counter drop
    }

    chain input {
        type filter hook input priority -5; policy drop;
        # ... твои существующие правила (lo, ct state, admins и т.д.) ...

        # вместо `tcp dport { 443 } counter accept`:
        tcp dport { 443 } counter jump mobile443
    }
}
```

`flag interval` + `auto-merge` обязательны: RIPEstat отдаёт перекрывающиеся
префиксы, без `auto-merge` заливка упадёт с ошибкой `interval overlaps`.

> ⚠️ **Окно пустого allowlist.** Если в конфиге есть `flush ruleset`, при каждом
> применении правил сеты обнуляются. Пока `m443_mobile_allow` пуст, цепочка
> `mobile443` режет весь не-админский `443`. Наполняй сеты сразу после применения
> правил (`setup.sh update`). Держи доступ к серверу по отдельному порту/IP
> (например `ip saddr $admins accept` **выше** `jump mobile443`), чтобы не
> залочиться.

## Проверка

```bash
nft list set inet filter m443_mobile_allow | head
nft list set inet filter m443_gov | head
systemctl list-timers | grep mobile443
journalctl -u mobile443-update.service --no-pager | tail
```

## Автообновление и перезагрузка

- `mobile443-update.timer` — ежедневно в 00:00 (со случайной задержкой) запускает `setup.sh update`.
- `mobile443-restore.service` — при загрузке восстанавливает наполнение сетов из
  кэша `/var/lib/mobile443/restore.nft` (после `nftables.service`, без обращения к сети).

## Интеграция с Ansible

Наполняй сеты хендлером сразу после перезагрузки nftables:

```yaml
handlers:
  - name: reload nftables
    ansible.builtin.command: nft -f /etc/nftables.conf
    notify: repopulate mobile443

  - name: repopulate mobile443
    ansible.builtin.command: /usr/local/sbin/mobile443 update
```

## Конфигурация

`/opt/mobile443/mobile443.conf` — источники списков, имена сетов, пороги защиты.
`/opt/mobile443/asns.conf` — список мобильных ASN (по одному числу на строку).
Оба файла при повторном `install` не перезаписываются, так что правки сохраняются.

## Что качается и куда ходит

- `stat.ripe.net` — публичный резолв ASN → IPv4-префиксы;
- `raw.githubusercontent.com/shadow-netlab/traffic-guard-lists` — блок-листы `government` / `antiscanner`.

Защита данных: пропуск битых строк, валидация каждого CIDR, отказ от обновления,
если префиксов меньше 500 или новый список усох более чем на 30% относительно прошлого.

## Примечания

- Реализация **IPv4-only**. Для IPv6 нужны отдельные сеты `ipv6_addr` и условие `meta nfproto ipv6`.
- Для нод с транзитным трафиком (роутинг / часть контейнерных схем) добавь аналогичный
  `jump mobile443` в `chain forward`. Для Docker с публикацией портов nftables-фильтр
  может не перехватывать трафик — проверяй на своём стенде.

## Удаление

```bash
bash <(curl -Ls https://raw.githubusercontent.com/YLisov/nft-mob443/refs/heads/main/setup.sh) remove
```

Снимает systemd-юниты, `/opt/mobile443`, `/var/lib/mobile443` и `/usr/local/sbin/mobile443`.
Правила nftables не трогаются — удали блок `mobile443` из конфига и применить
`nft -f /etc/nftables.conf` вручную.
