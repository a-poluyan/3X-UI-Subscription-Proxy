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
