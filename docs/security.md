# Security

MikroTik часто сканируют, поэтому Web UI не должен становиться еще одной
публичной точкой атаки.

## Обязательные правила

- Не публиковать Web UI в WAN.
- Разрешать доступ к UI только из LAN/admin VPN.
- Использовать длинный уникальный `APP_PASSWORD` или `APP_PASSWORD_HASH`.
- Использовать SSH key auth, не password SSH.
- Создать отдельного RouterOS пользователя `wg-easy`.
- Ограничить `/ip/service ssh address=` контейнерной сетью и admin LAN/VPN.
- Хранить `/data` на внешнем диске, потому что там SQLite и SSH private key.
- Делать backup `/data`, так как там хранятся клиентские конфиги.
- Встроенный Web UI слушает HTTP. Для HTTPS нужен reverse proxy с TLS:
  Caddy, Nginx, Traefik или другой gateway в доверенной admin-сети.

## Защита в приложении

- UI заблокирован, если не задан `APP_PASSWORD` или `APP_PASSWORD_HASH`.
- Пароль проверяется через PBKDF2-SHA256.
- Сессия хранится в HttpOnly/SameSite cookie.
- Сессии хранятся в памяти процесса. После рестарта контейнера админы должны
  войти заново.
- POST-запросы требуют CSRF token.
- Включен request rate limit.
- Rate limit по умолчанию использует реальный TCP source IP и не доверяет
  `X-Forwarded-For`. Включать `APP_TRUST_PROXY_HEADERS=1` можно только если
  Web UI стоит за доверенным reverse proxy, который сам перезаписывает этот
  заголовок.
- Выставляются security headers: CSP, X-Frame-Options, X-Content-Type-Options,
  Referrer-Policy.
- Размер JSON/form body ограничен.

## RouterOS user policy

Пользователь `wg-easy` должен уметь читать состояние роутера и менять только
нужные зоны конфигурации:

- `/interface/wireguard`;
- `/interface/wireguard/peers`;
- `/ip/address`;
- `/ip/firewall/filter`;
- `/ip/firewall/nat`;
- `/ip/dns`;
- `/ip/cloud`;
- `/system/resource`;
- `/system/identity`.

RouterOS policy model грубее, чем ACL по path, поэтому полный least privilege
может быть недостижим без компромисса. Нельзя использовать full `admin` без
необходимости; отдельная группа `wg-easy` лучше, даже если ей нужны
`read,write,sensitive,policy,test,ssh`.

## Что еще нужно перед настоящим production

- Добавить TOTP/2FA.
- Добавить аудит действий администратора.
- Добавить preview/diff RouterOS-команд перед применением.
- Уточнить минимальный RouterOS policy set для пользователя `wg-easy`.
- Добавить endpoint для healthcheck без раскрытия настроек.
- Добавить persistent session store, если понадобится переживать рестарт без
  повторного входа.
