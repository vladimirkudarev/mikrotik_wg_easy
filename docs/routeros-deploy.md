# RouterOS Deploy

Целевой сценарий: приложение работает внутри RouterOS container и управляет этим
же MikroTik по SSH.

## Короткий путь

1. Включить container mode:

```routeros
/system/device-mode/update container=yes
```

На многих моделях эта команда требует физического подтверждения device-mode
через кнопку/reset или холодную перезагрузку. Если CLI отработал без понятной
подсказки и container не включился, включите container mode через WinBox/WebFig
и проверьте итоговое состояние:

```routeros
/system/device-mode/print
```

2. Выбрать container image по архитектуре MikroTik:

```routeros
/system/resource/print
```

Используйте:

- `dist/mikrotik-wg-easy-arm64.tar.gz` для `architecture-name=arm64`;
- `dist/mikrotik-wg-easy-armv7.tar.gz` для `architecture-name=arm`.

Это не индивидуальный образ под каждый роутер. Один архив подходит всем
устройствам той же архитектуры.

Распаковать локально:

```bash
gunzip -c dist/mikrotik-wg-easy-arm64.tar.gz > mikrotik-wg-easy.tar
```

Загрузить `mikrotik-wg-easy.tar` в корень диска MikroTik `disk1`.

Проверка на MikroTik:

```routeros
/file/print where name~"mikrotik-wg-easy"
```

Генератор по умолчанию принимает только имя файла, без `disk1/`:

```bash
python3 scripts/generate_install.py \
  --lan-address 192.168.88.1 \
  --lan-subnet 192.168.88.0/24 \
  --disk disk1 \
  --image-file mikrotik-wg-easy.tar
```

Внутри `.rsc` это будет преобразовано в RouterOS file name
`disk1/mikrotik-wg-easy.tar`.

Если нужно указать точное значение из `/file/print`, используйте advanced
override `--image`:

```bash
python3 scripts/generate_install.py \
  --lan-address 192.168.88.1 \
  --lan-subnet 192.168.88.0/24 \
  --disk disk1 \
  --image disk1/some-exact-name.tar
```

Если файл загружен под другим именем, есть два нормальных варианта:

```routeros
/file/set [find where name="disk1/mikrotik-wg-easy-arm64.tar"] name="disk1/mikrotik-wg-easy.tar"
```

или сгенерировать install script под фактическое имя:

```bash
python3 scripts/generate_install.py \
  --lan-address 192.168.88.1 \
  --lan-subnet 192.168.88.0/24 \
  --disk disk1 \
  --image-file mikrotik-wg-easy-arm64.tar
```

Ошибка вида `input does not match any value of file (/container/add (file))`
означает, что RouterOS не нашел файл, указанный в параметре `/container/add
file=...`.

3. Подготовить SSH key для доступа приложения к MikroTik.

Ключ генерируется на вашей локальной машине, не на MikroTik. Например, из корня
этого репозитория:

```bash
ssh-keygen -t ed25519 -f ./wg-easy-id_ed25519 -C "mikrotik-wg-easy"
```

После этого появятся два файла:

```text
wg-easy-id_ed25519      # private key, секретный файл
wg-easy-id_ed25519.pub  # public key, можно загружать на MikroTik
```

Private key нужен контейнеру. Его нужно загрузить на диск MikroTik в папку,
которая будет примонтирована в контейнер как `/data`.

Целевое расположение private key на MikroTik:

```text
disk1/wg-easy-data/id_ed25519
```

То есть локальный файл `wg-easy-id_ed25519` нужно загрузить на MikroTik и
переименовать в `id_ed25519` внутри папки `disk1/wg-easy-data`.

Если папки `disk1/wg-easy-data` еще нет, проще всего создать ее в WinBox:

1. Открыть `Files`.
2. Зайти на диск `disk1`.
3. Нажать `New Folder`.
4. Назвать папку `wg-easy-data`.
5. Загрузить private key внутрь этой папки.
6. Переименовать файл в `id_ed25519`, если он загружен как
   `wg-easy-id_ed25519`.

В WebFig логика такая же: `Files` -> `disk1` -> создать папку/загрузить файл.

Через CLI это может выглядеть так, если ваша версия RouterOS поддерживает
создание directory через `/file`:

```routeros
/file/add name=disk1/wg-easy-data type=directory
```

После этого private key нужно загрузить именно как:

```text
disk1/wg-easy-data/id_ed25519
```

Если CLI-команда создания папки не поддерживается или ведет себя иначе на вашей
версии RouterOS, используйте WinBox/WebFig. Это самый предсказуемый способ.

Проверка private key на MikroTik:

```routeros
/file/print where name~"wg-easy-data"
```

Public key нужен самому RouterOS. Его тоже нужно загрузить на MikroTik как
обычный файл, например в корень `Files`:

```text
wg-easy-id_ed25519.pub
```

Импортировать public key сразу на этом шаге нельзя, потому что пользователь
`wg-easy` создается install script на шаге 5. Поэтому пока только загрузите
`.pub` файл, а импорт будет на шаге 6.

Если хотите проверить ключ заранее, можно временно импортировать public key для
вашего текущего admin-пользователя:

```routeros
/user/ssh-keys/import user=admin public-key-file=wg-easy-id_ed25519.pub
```

И проверить с локальной машины:

```bash
ssh -i ./wg-easy-id_ed25519 admin@192.168.88.1 /system/identity/print
```

После проверки временный ключ у `admin` лучше удалить и затем импортировать его
уже для пользователя `wg-easy` на шаге 6.

4. Сгенерировать install script:

```bash
python3 scripts/generate_install.py \
  --lan-address 192.168.88.1 \
  --lan-subnet 192.168.88.0/24 \
  --disk disk1 \
  --image-file mikrotik-wg-easy.tar \
  --ui-port 8080
```

Если образ уже опубликован в registry, tar можно не загружать:

```bash
python3 scripts/generate_install.py \
  --lan-address 192.168.88.1 \
  --lan-subnet 192.168.88.0/24 \
  --disk disk1 \
  --remote-image registry.example.com/mikrotik-wg-easy:latest \
  --ui-port 8080
```

Скрипт создаст `deploy/routeros-install.rsc` и напечатает стартовый пароль Web
UI.

5. Загрузить `deploy/routeros-install.rsc` на MikroTik и выполнить:

```routeros
/import file-name=routeros-install.rsc
```

6. Импортировать SSH public key для пользователя `wg-easy`.

Этот шаг выполняется после `/import file-name=routeros-install.rsc`, потому что
именно install script создает пользователя `wg-easy`.

```routeros
/user/ssh-keys/import user=wg-easy public-key-file=wg-easy-id_ed25519.pub
```

Проверка:

```routeros
/user/ssh-keys/print where user=wg-easy
```

7. Открыть:

```text
http://192.168.88.1:8080
```

В UI: `Подтянуть из MikroTik`, проверить параметры, `Применить настройку`,
создать клиента.

## Что автоматизирует install script

- `bridge` для контейнеров;
- `veth` для приложения;
- gateway `172.17.0.1/24`;
- outbound masquerade для контейнерной сети;
- dst-nat Web UI только из указанной LAN/admin subnet;
- RouterOS group/user `wg-easy`;
- ограничение SSH service address;
- container env;
- `/data` mount;
- import/start container из tar image.

## Ручная схема

Эта секция оставлена для отладки, если install script нужно выполнить
пошагово.

### Сеть контейнера

```routeros
/interface/veth/add name=veth-wg-easy address=172.17.0.2/24 gateway=172.17.0.1
/interface/bridge/add name=containers comment="container bridge"
/ip/address/add address=172.17.0.1/24 interface=containers comment="container gateway"
/interface/bridge/port/add bridge=containers interface=veth-wg-easy
/ip/firewall/nat/add chain=srcnat action=masquerade src-address=172.17.0.0/24 comment="containers outbound"
```

Web UI публиковать только в доверенную LAN/admin VPN:

```routeros
/ip/firewall/nat/add chain=dstnat action=dst-nat protocol=tcp dst-address=192.168.88.1 dst-port=8080 src-address=192.168.88.0/24 to-addresses=172.17.0.2 to-ports=8080 comment="wg-easy ui lan only"
```

Не делайте dst-nat с WAN на порт UI.

### SSH пользователь

Идея: отдельный пользователь `wg-easy`, вход только ключом, доступ к SSH только
из контейнерной сети.

```routeros
/user/group/add name=wg-easy policy=ssh,read,write,sensitive,policy,test
/user/add name=wg-easy group=wg-easy disabled=no
/ip/service/set ssh address=172.17.0.0/24,192.168.88.0/24
```

Публичный ключ контейнера нужно импортировать в RouterOS для пользователя
`wg-easy`. Конкретная команда зависит от того, как файл ключа загружается на
RouterOS:

```routeros
/user/ssh-keys/import user=wg-easy public-key-file=wg-easy.pub
```

### Container env

Минимальные переменные:

```text
APP_PASSWORD_HASH=<pbkdf2 hash>
ROS_HOST=172.17.0.1
ROS_USER=wg-easy
ROS_SSH_KEY=/data/id_ed25519
WG_CLIENT_CIDR=10.8.0.0/24
WG_ROUTER_ADDRESS=10.8.0.1/24
WG_ALLOWED_IPS=0.0.0.0/0
```

Для первого теста допустимо `APP_PASSWORD=<long random password>`, но в
production предпочтительнее передавать `APP_PASSWORD_HASH`.

### Container add

Схема для remote image:

```routeros
/container/envs/add list=ENV_WG_EASY key=APP_PASSWORD_HASH value="<hash>"
/container/envs/add list=ENV_WG_EASY key=ROS_HOST value="172.17.0.1"
/container/envs/add list=ENV_WG_EASY key=ROS_USER value="wg-easy"
/container/envs/add list=ENV_WG_EASY key=ROS_SSH_KEY value="/data/id_ed25519"
/container/envs/add list=ENV_WG_EASY key=APP_TRUST_PROXY_HEADERS value="0"
/container/mounts/add list=MOUNT_WG_EASY src=disk1/wg-easy-data dst=/data
/container/add remote-image=<registry>/mikrotik-wg-easy:latest interface=veth-wg-easy root-dir=disk1/images/wg-easy mountlists=MOUNT_WG_EASY envlist=ENV_WG_EASY start-on-boot=yes logging=yes
```
