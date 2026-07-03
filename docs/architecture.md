# Architecture

## Предлагаемый путь

Базовая реализация: один контейнер внутри RouterOS с Web UI и SSH backend.

```text
Browser
  |
  | HTTP inside trusted LAN/admin VPN
  v
wg-mikrotik-easy container
  |
  | SSH, TCP 22
  v
RouterOS
  - /interface/wireguard
  - /interface/wireguard/peers
  - /ip/address
  - /ip/firewall/filter
  - /ip/firewall/nat
```

Контейнер запускается на самом MikroTik. На RouterOS container создается `veth`,
bridge для контейнеров и dst-nat на порт Web UI только со стороны доверенной
LAN/admin VPN. Backend подключается к RouterOS по SSH на gateway контейнерной
сети, по умолчанию `172.17.0.1`.

## Почему не кастомная вкладка WinBox

Кастомную вкладку WinBox не закладываем: публичного стабильного
механизма расширения WinBox под свои UI-вкладки нет. Реалистичные варианты:

1. Web UI в контейнере.
2. Использовать встроенные WireGuard экраны WinBox/WebFig, где RouterOS уже
   поддерживает `show-client-config` и QR для peer при заполнении client-полей.
3. Сгенерировать RouterOS script, который делает минимальную настройку без UI.

## QR и приватные ключи клиента

Есть два рабочих режима.

### RouterOS-native Mode

Создаем peer в RouterOS с `private-key=auto` или через штатный механизм,
заполняем поля:

- `client-address`;
- `client-dns`;
- `client-endpoint`;
- `client-keepalive`;
- `client-allowed-address`.

После этого используем RouterOS 7.21+ `show-client-config` и строим QR на лету.
Клиентские записи и конфиги не хранятся в базе приложения: source of truth для
клиентов - `/interface/wireguard/peers` на MikroTik. Плюс: меньше своего
криптокода, видны peer, созданные вручную, и нет риска рассинхронизации с БД.

### App-generated mode

Backend сам генерирует keypair клиента, в RouterOS записывает только public key,
а клиентский `.conf` и QR собирает сам. Этот режим оставлен как запасной, если
на конкретных RouterOS-сборках `show-client-config` плохо автоматизируется
через SSH.

Плюс: одинаковое поведение на разных RouterOS v7. Минус: нужно решить, хранить
ли private key клиента для повторной выдачи QR. Без хранения QR доступен только
сразу после создания.

## Технологический стек

Текущий стек:

- backend: Go, single static binary;
- frontend: встроенный HTML/JS без сборки;
- хранение: `state.json` на mounted volume только для настроек сервиса;
- RouterOS transport: SSH через Go `x/crypto/ssh`;
- QR: Go-библиотека `go-qrcode`;
- контейнер: `linux/arm64` и `linux/arm/v7`;
- обязательная Web UI авторизация: PBKDF2 password hash, session cookie, CSRF.

Такой стек выбран ради малого RouterOS container image: в runtime-слое нет
shell, Python, OpenSSH client и пакетного менеджера.

## Безопасность

- По умолчанию использовать SSH key auth.
- Создать отдельного RouterOS user с минимально достаточными правами.
- Пароль Web UI хранить как hash.
- Сессии Web UI через HttpOnly/SameSite cookie.
- CSRF token для всех mutating requests.
- Rate limit на HTTP requests.
- Security headers: CSP, X-Frame-Options, X-Content-Type-Options.
- Client config не хранить в приложении. Повторная выдача QR идет через
  `show-client-config` для текущего RouterOS peer.
- Не публиковать Web UI в WAN.

## RouterOS команды, которыми будет управлять backend

Минимальные сущности:

```routeros
/interface/wireguard/add name=wg0 listen-port=13231
/ip/address/add address=10.8.0.1/24 interface=wg0
/interface/wireguard/peers/add interface=wg0 public-key=... allowed-address=10.8.0.2/32
/ip/firewall/filter/add chain=input action=accept protocol=udp dst-port=13231 comment="wg-easy-mikrotik"
```

Для full-tunnel дополнительно:

```routeros
/ip/firewall/filter/add chain=input action=accept src-address=10.8.0.0/24 comment="wg-easy-mikrotik clients"
/ip/firewall/nat/add chain=srcnat action=masquerade src-address=10.8.0.0/24 out-interface-list=WAN comment="wg-easy-mikrotik"
```

Peer создается через RouterOS-native режим:

```routeros
/interface/wireguard/peers/add interface=wg0 name=phone private-key=auto allowed-address=10.8.0.2/32 client-address=10.8.0.2/32 client-dns=10.8.0.1 client-endpoint=vpn.example.com client-keepalive=25 client-allowed-address=0.0.0.0/0
/interface/wireguard/peers/show-client-config *1
```

## Lifecycle клиентов

Новые peer получают уникальный comment `mikrotik-wg-easy:<uuid>`, но список и
операции строятся по RouterOS internal id (`*1`, `*A` и т.п.). Поэтому в UI
появляются и peer, созданные вручную без comment. Приложение выполняет операции:

- disable/enable peer через `/interface/wireguard/peers/set`;
- delete peer через `/interface/wireguard/peers/remove`;
- verify/config/QR через `show-client-config`;
- edit peer через `/interface/wireguard/peers/set`.

При выдаче нового IP приложение учитывает текущие RouterOS peers:
`/interface/wireguard/peers/print terse`.

## Bootstrap/Reconcile

Bootstrap управляет только объектами с comments `mikrotik-wg-easy*`. Если объект
уже найден, приложение обновляет listen port, адрес, firewall filter и NAT
параметры вместо молчаливого сохранения старой версии.
