# omarchy-router

Per-app VPN bypass for Happ on Omarchy: свой sing-box с TUN отправляет выбранные приложения напрямую, остальное — в локальный SOCKS Happ (127.0.0.1:10808, режим TUN в Happ выключен), а nftables-guard не даёт трафику уйти в интернет мимо VPN и исключений. Что и почему — в `CONTEXT.md` и `DESIGN.md`.

## Установка и панель

```
sudo ./omarchy_router.py install     # sing-box, zapret, юниты, sudoers, панель, пункт в меню Omarchy
omarchy-router open                  # SUPER+SHIFT+V: панель http://127.0.0.1:7377
omarchy-router off                   # аварийно снять защиту
omarchy-router zapret-tune           # подобрать стратегию zapret под Discord (то же — кнопка в панели)
python3 check_prototype.py /usr/bin/sing-box   # проверка в изолированном netns, без root
```

Панель (`web.py` + `web.html`, user-сервис `omarchy-router-web`) показывает каждый слой отдельно
(прямой интернет, Happ, VPN, Discord через zapret, Tailscale), чинит упавшее кнопкой «Починить сеть»,
редактирует исключения и управляет zapret. Слушает только 127.0.0.1; API требует токен страницы.

Исключение — путь исполняемого файла из запущенных процессов. Исключения лежат в
`~/.config/omarchy-router/rules.json` (local rule-set sing-box) и применяются без перезапуска: sing-box
сам перечитывает файл, сеть не моргает. Пути, которые меняются от запуска к запуску, хранятся шаблоном:
AppImage — `/tmp/.mount_FreakR*/FreakRating`, Discord — `.../discord/app-*/Discord`. Игры под Proton/Wine
добавляются сборкой целиком (одна строка «Proton - Experimental»).

## zapret для прямого трафика

Трафик исключений выходит напрямую и попадает под DPI. Для него работает `omarchy-zapret.service`:
nfqws (`bin/nfqws`) со стратегией Flowseal из `zapret-discord-youtube-linux/*.bat` (выбор — в
`~/.config/omarchy-router/zapret.json`). Очередь — наша таблица `inet omarchy-zapret` с флагом
`bypass`: упавший, зависший или перезапускаемый nfqws ломает только обход DPI, а не весь интернет.

zapret-rust больше не используется: в его nft-правилах `bypass` не доходит до ядра (поле `"bypass": true`
вместо `flags`), поэтому остановка nfqws роняла все новые соединения на uplink, включая сам VPN, а
очистка оставляла правила (накапливались копии). Ещё он резал `--dpi-desync-fooling=ts,md5sig` по запятой.
`install` останавливает его и удаляет его таблицу.

Guard пропускает пакеты nfqws с меткой `0x40000000`, а TUN не забирает его сырые сокеты (`exclude_uid`).
Uplink определяется по маршруту по умолчанию в `main`. Пакеты tailscaled (метка `0x80000`) zapret не трогает.

## Tailscale рядом

Guard пропускает `tailscale0` и сокеты tailscaled (метка `0x80000/0xff0000`) — пиры соединяются
напрямую. Адреса tailnet исключены из TUN (`route_exclude_address`). DNS приложений остаётся
через VPN (`sudo tailscale set --accept-dns=false`, обычный resolv.conf), а имена `*.ts.net`
sing-box спрашивает у MagicDNS 100.100.100.100.

Проверка, что фейки уходят в сеть (открыть сайт из hostlist приложением-исключением):

```
sudo nft list chain inet omarchy-router egress | grep counter
```
