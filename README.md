# qWDTT

qWDTT — Android-приложение для подключения к собственному VPS через TURN-инфраструктуру звонков VK.

Приложение создаёт системный VPN-туннель на телефоне, передаёт зашифрованный трафик через VK TURN и выпускает его в интернет через ваш сервер. Для сети такое соединение похоже на медиатрафик звонка WebRTC, а не на обычное прямое подключение к VPN-серверу.

## Веб-панель (этот репозиторий)

Два сервиса:

| Unit | Бинарь | Роль |
|------|--------|------|
| `wdtt.service` | `wdtt-server` | VPN (DTLS/WG/raw) + **admin API** `:56002` |
| `qwdtt-panel.service` | `qwdtt-panel` | HTTPS панель `:46102` + **SOCKS5 TPROXY** + мост CSQTT |

Официальные APK (qWDTT / CSQTT) не меняются. Обновление `wdtt-server` с APK больше не затирает панель — unit панели отдельный. CRUD клиентов qWDTT панель делает через admin API; CSQTT — через локальный API `https://127.0.0.1:46002` (логин из `/etc/csqtt/csqtt.env`).

**SOCKS5 UDP** остаётся: один TPROXY на `wdtt0` / `wdttraw0` / `csqtt1` → локальный Xray/sing-box (TCP+UDP, проверка UDP ASSOCIATE как в CSQTT). Включается в **Настройки → qWDTT**. При активации гасится встроенный SOCKS CSQTT.

Панель UI: вкладки Мониторинг / Клиенты / Логи / Настройки. В **Настройки** — общий SOCKS5 UDP и обновление серверов:

- **как из приложения** — stock SpaceNeuroX `wdtt-server` / официальный CSQTT `deploy.sh`;
- **из исходников GitHub** — сборка MaxPain99/qwdtt-panel и cargo CSQTT.

Если вкладка CSQTT «не найден»: `csqtt` запущен, есть `CSQTT_WEB_PASS` в `/etc/csqtt/csqtt.env`, процесс `qwdtt-panel` читает `/etc/csqtt` (при `ProtectSystem=strict` — `ReadOnlyPaths=/etc/csqtt` в `qwdtt-panel.service`).

Установка на VPS:

```bash
curl -fsSL https://raw.githubusercontent.com/MaxPain99/qwdtt-panel/master/install.sh | sudo bash
```

Панель: `https://IP:46102` (self-signed). Учётки: `/etc/wdtt/credentials.txt`.

Обновление: `sudo bash /opt/qwdtt-panel/install.sh update` (ставит оба бинаря и оба unit). После обновления qWDTT **только с APK** перезапустите/проверьте `qwdtt-panel` и что у `wdtt` есть `-admin-listen` + токен (иначе панель не создаст клиентов).

Не пушьте эту ветку в SpaceNeuroX — только в `MaxPain99/qwdtt-panel`.

## Быстрый старт


1. Скачайте APK в разделе [Releases](https://github.com/SpaceNeuroX/proxy-turn-vk-android/releases).
2. Добавьте VPS на вкладке «Серверы» и выполните установку серверной части.
3. Создайте профиль подключения или импортируйте готовую ссылку.
4. Добавьте хеш звонка VK.
5. Нажмите «Подключить» и разрешите Android создать VPN-соединение.

## Сборки

- стабильные подписанные версии публикуются в [GitHub Releases](https://github.com/SpaceNeuroX/proxy-turn-vk-android/releases);
- тестовые debug-сборки ветки `develop` доступны в [GitHub Actions](https://github.com/SpaceNeuroX/proxy-turn-vk-android/actions/workflows/android-debug.yml).

## Обсуждение и поддержка

- [Группа qWDTT в Telegram](https://t.me/darkbit_chat)
- [Поддержать разработку](https://pay.cloudtips.ru/p/64a6c43c)

## Лицензия

Проект распространяется по лицензии [GNU GPL v3](LICENSE).

## Происхождение проекта

При создании qWDTT в качестве технической основы использовались исходники Android-приложения и серверной части оригинального проекта [WDTT](https://github.com/amurcanov/proxy-turn-vk-android). Оригинальный репозиторий сейчас архивирован.

qWDTT — самостоятельное развитие этой кодовой базы: приложение, интерфейс, режимы подключения, управление серверами и значительная часть клиентской и серверной логики развиваются отдельно. Проект не является официальным продолжением или новым релизом оригинального WDTT.
