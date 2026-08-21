# qWDTT

qWDTT — Android-приложение для подключения к собственному VPS через TURN-инфраструктуру звонков VK.

Приложение создаёт системный VPN-туннель на телефоне, передаёт зашифрованный трафик через VK TURN и выпускает его в интернет через ваш сервер. Для сети такое соединение похоже на медиатрафик звонка WebRTC, а не на обычное прямое подключение к VPN-серверу.

## Веб-панель (этот репозиторий)

HTTPS-панель в том же процессе, что и `wdtt-server`. Официальный APK qWDTT не меняется. Клиентов CSQTT панель берёт с локального API `csqtt` (`https://127.0.0.1:46002`): логин из `/etc/csqtt/csqtt.env` (`CSQTT_WEB_USER` / `CSQTT_WEB_PASS`), без отдельной формы подключения. Список, создание, ссылки `csqtt://`, удаление — через тот же API.

SOCKS5 один на оба туннеля: TPROXY с `wdtt0`, `wdttraw0` и `csqtt1` в один локальный Xray/sing-box. При включении панель выключает SOCKS в CSQTT, чтобы не было двух маршрутов.

Если вкладка CSQTT пишет «не найден» или «нет доступа к …/csqtt.env»: убедитесь, что `csqtt` запущен, в `/etc/csqtt/csqtt.env` есть `CSQTT_WEB_PASS`, и процесс `wdtt-server` может читать этот файл (в unit достаточно `ReadOnlyPaths=/etc/csqtt`; `ProtectHome=true` путь `/etc` не закрывает). `install.sh update` unit не переписывает — при необходимости добавьте `ReadOnlyPaths` вручную и `systemctl daemon-reload && systemctl restart wdtt`.

Установка на VPS:

```bash
curl -fsSL https://raw.githubusercontent.com/MaxPain99/qwdtt-panel/master/install.sh | sudo bash
```

Панель: `https://IP:46102` (self-signed). Запуск — рабочий SpaceNeuroX `wdtt.service` плюс только `-web-port 46102` и INPUT TCP 46102. Остальные флаги не трогаем.

Обновление бинарника: кнопка в панели или `sudo bash /opt/qwdtt-panel/install.sh update`. Существующий `wdtt.service` не переписывается. Записать эталонный unit: `install.sh write-unit`.

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
