# MikroTik WireGuard Easy

Проект для упрощенного поднятия WireGuard на MikroTik RouterOS 7.21+:
веб-интерфейс, разворачиваемый внутри RouterOS container. Он подключается к
самому MikroTik по SSH, подтягивает параметры роутера, настраивает WireGuard,
создает клиентов, показывает QR-код и отдает `.conf` для WireGuard-клиента.

## Текущий статус

Репозиторий содержит рабочую Go-версию приложения для RouterOS container:

- `docs/product-brief.md` - цель, production scope и ограничения.
- `docs/architecture.md` - предлагаемая архитектура.
- `cmd/mikrotik-wg-easy/main.go` - web UI и RouterOS SSH-интеграция.
- `Dockerfile` - multi-stage Go build, runtime `scratch`.
- `docs/routeros-deploy.md` - схема развертывания на MikroTik.
- `docs/security.md` - production baseline.
- `scripts/generate_install.py` - генератор RouterOS install script.
- `scripts/hash_password.py` - генератор `APP_PASSWORD_HASH`.
- `scripts/routeros_archive.py` - конвертер Docker archive в формат, который
  принимает RouterOS container.

Попытка инициализации через `ai-factory init` была выполнена, но CLI не смог
завершить установку в `.codex/skills` из-за прав на служебную директорию в
текущем sandbox-профиле. Проектные документы созданы вручную.

## Предварительное решение

Решение делается как Web UI внутри RouterOS container:

- у WinBox нет нормальной публичной модели плагинов для добавления своих
  вкладок;
- RouterOS уже умеет WireGuard и QR для peer-конфига через `show-client-config`;
- Web UI открывается из доверенной LAN/VPN-сети, рядом с WinBox/WebFig;
- приложение работает через SSH к адресу роутера в контейнерной bridge-сети;
- настройки можно подтянуть из MikroTik и затем изменить в UI.

## Локальный запуск для разработки

```bash
docker build -t mikrotik-wg-easy:dev .
docker run --rm -p 8080:8080 \
  -e APP_INSECURE_DEV=1 \
  -e APP_DATA=/tmp/mikrotik-wg-easy \
  mikrotik-wg-easy:dev
```

По умолчанию UI доступен на `http://127.0.0.1:8080`, пароль в dev-режиме:
`admin`.

## Production Defaults

- `APP_PASSWORD` или `APP_PASSWORD_HASH` обязателен, иначе UI заблокирован.
- SSH только по ключу: `ROS_USER=wg-easy`, `ROS_SSH_KEY=/data/id_ed25519`.
- Дефолтный RouterOS host из контейнера: `172.17.0.1`.
- UI нельзя публиковать в WAN. Доступ должен быть только из LAN/admin VPN.
- Встроенный UI работает по HTTP; HTTPS делается внешним reverse proxy.
- `X-Forwarded-For` игнорируется, пока явно не задан
  `APP_TRUST_PROXY_HEADERS=1`.
- Full-tunnel для клиентов: `AllowedIPs = 0.0.0.0/0`.

## Быстрое развертывание

Готовые RouterOS-compatible tar после сборки лежат в `dist/`:

- `dist/mikrotik-wg-easy-arm64.tar` - для `architecture-name=arm64`;
- `dist/mikrotik-wg-easy-armv7.tar` - для `architecture-name=arm`/`armv7`.

Архив выбирается по архитектуре CPU, а не генерируется под каждый MikroTik
отдельно.

```bash
python3 scripts/generate_install.py \
  --lan-address 192.168.88.1 \
  --lan-subnet 192.168.88.0/24 \
  --disk disk1 \
  --image-file mikrotik-wg-easy.tar
```

Когда образ будет опубликован в registry, вместо `--image-file` используйте
`--remote-image registry.example.com/mikrotik-wg-easy:latest`.

Дальше загрузить `deploy/routeros-install.rsc` на MikroTik и выполнить:

```routeros
/import file-name=routeros-install.rsc
```

Подробности: `docs/routeros-deploy.md`.
