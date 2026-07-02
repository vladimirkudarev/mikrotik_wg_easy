# Product Brief

## Цель

Сделать production-ready инструмент уровня `wg-easy`, но адаптированный под
MikroTik RouterOS 7.21+ и запускаемый внутри RouterOS container:
администратор выбирает базовые параметры, нажимает "создать клиента" и получает
QR-код/конфиг для телефона, Windows, macOS или Linux.

## Аналог wg-easy

Из `wg-easy` берем функциональное ядро:

- первичная настройка WireGuard-сервера;
- список клиентов;
- создание, редактирование, отключение и удаление клиентов;
- QR-код клиента;
- скачивание `.conf`;
- статус подключения, `last-handshake`, `rx`, `tx`;
- DNS, AllowedIPs, endpoint, keepalive;
- желательно: срок действия клиента и одноразовая ссылка.

## Production Scope

1. Подключение к RouterOS по SSH.
2. Проверка окружения:
   - RouterOS 7.21+;
   - наличие WireGuard;
   - наличие `container` package, если приложение запускается на самом роутере;
   - включенный SSH;
   - key-based SSH user.
3. Автоподтягивание параметров MikroTik с возможностью ручного изменения:
   - RouterOS version/architecture;
   - identity;
   - DNS;
   - MikroTik Cloud DNS как endpoint, если включен;
   - существующий WireGuard-интерфейс, созданный инструментом.
4. Wizard первичной настройки:
   - имя WG-интерфейса;
   - listen port;
   - subnet для клиентов;
   - endpoint hostname/IP;
   - DNS;
   - full-tunnel `0.0.0.0/0` по умолчанию;
   - WAN-интерфейс или interface-list для firewall/NAT.
5. Создание/обновление RouterOS-конфигурации:
   - `/interface/wireguard`;
   - `/ip/address`;
   - `/interface/wireguard/peers`;
   - firewall input для UDP-порта;
   - NAT/forward правила, если нужен full-tunnel.
6. Клиенты:
   - создать клиента;
   - показать QR;
   - скачать `.conf`;
   - включить/выключить;
   - удалить клиента и peer на MikroTik;
   - пересоздать сохраненный конфиг через RouterOS `show-client-config`;
   - показать handshake/rx/tx.

## Out Of Scope

- HA/кластер нескольких MikroTik.
- Multi-WAN policy routing.
- Сложные site-to-site сценарии.
- Самостоятельное расширение WinBox.
- Управление несколькими роутерами из одного инстанса.
- Поддержка RouterOS ниже 7.21.
- Публикация Web UI в интернет.
