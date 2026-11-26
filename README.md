# 3X-UI Subscription Proxy

Прокси сохраняет ссылку подписки и меняет первый подходящий профиль в JSON-ответе 3x-ui. Он ищет профиль по началу имени и адресу VLESS на порту `443`, затем направляет его TCP- и UDP-трафик через VLESS. Локальные DNS-резолверы используются для разрешения имени VLESS-сервера.

Прокси подключается к HTTPS-порту подписки 3x-ui на `127.0.0.1`. Имя в `--hostname` должно совпадать с именем в сертификате 3x-ui и адресом в профиле VLESS. В `--profile-prefix` укажите начало имени нужного профиля.

Пример запуска для 3x-ui на порту `2097` с публичной подпиской на `2096`.

```sh
python subscription_proxy.py --listen 0.0.0.0 --port 2096 --origin-port 2097 --hostname vpn.example.com --profile-prefix 'Full tunnel |' --cert /path/to/fullchain.pem --key /path/to/privkey.pem
```

Тесты запускаются стандартной библиотекой Python.

```sh
python -B -m unittest -v
```

## Раздача геобаз

Передайте прокси `--geodata-dir /var/lib/3x-ui-subscription-geodata`. Файлы будут
доступны по путям `/geo/geosite.dat` и `/geo/geoip.dat`. Укажите оба публичных HTTPS-адреса
в полях `Geositeurl` и `Geoipurl` профиля Happ. Для такого профиля прокси передаёт
в `LastUpdated` метку последней опубликованной пары.

Для JSON-подписок Happ прокси может выдавать сокращённые базы. Создайте
подкаталог `sets` в каталоге геобаз с правом записи для прокси. В systemd с
`DynamicUser=yes` добавьте `StateDirectory=3x-ui-subscription-geodata/sets` в секцию `[Service]`.

Прокси сверяет категории профиля Happ с фактическим JSON 3x-ui и добавляет
одинаковый `?set=...` к обоим адресам, если пара покрывает подписку.
Пары хранятся в `sets/<идентификатор>/` и доступны после перезапуска.
Обычные адреса продолжают отдавать полные базы.

Скрипт берёт оба файла из `/app/bin/` указанного контейнера. Он проверяет
контрольные суммы и публикует новую пару, если содержимое изменилось.
Первую публикацию можно запустить сразу.

```sh
sudo python3 -B publish_geodata.py CONTAINER /var/lib/3x-ui-subscription-geodata
```

Для запуска по расписанию установите оба файла из `deploy/` в
`/etc/systemd/system/`. Укажите в `/etc/default/3x-ui-geodata-publish`
абсолютный путь к скрипту, имя контейнера и каталог раздачи.

```ini
GEODATA_PUBLISH_SCRIPT=/opt/3x-ui-subscription-proxy/publish_geodata.py
GEODATA_CONTAINER=3x-ui
GEODATA_DIRECTORY=/var/lib/3x-ui-subscription-geodata
```

```sh
sudo systemctl daemon-reload
sudo systemctl start 3x-ui-geodata-publish.service
sudo systemctl enable --now 3x-ui-geodata-publish.timer
```

Таймер публикует копии по субботам в 05:00 МСК. Скачивание исходных баз
настраивается отдельно в Xray.
