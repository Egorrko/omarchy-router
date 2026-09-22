# omarchy-router

Per-app VPN bypass for Happ on Omarchy: свой sing-box с TUN отправляет выбранные приложения напрямую, остальное — в локальный SOCKS Happ (127.0.0.1:10808, режим TUN в Happ выключен), а nftables-guard не даёт трафику уйти в интернет мимо VPN и исключений. Что и почему — в `CONTEXT.md` и `DESIGN.md`.

## Установка и меню

```
sudo ./omarchy_router.py install     # ставит sing-box, юниты, sudoers, пункт в меню Omarchy
omarchy-router menu                  # SUPER+SHIFT+V: добавить исключение, сохранить и применить
omarchy-router off                   # аварийно снять защиту
python3 check_prototype.py /usr/bin/sing-box   # проверка в изолированном netns, без root
```

Исключение — путь исполняемого файла из запущенных процессов. Игры под Proton/Wine добавляются сборкой целиком (одна строка «Proton - Experimental»): все игры через неё идут напрямую.

## zapret для прямого трафика

Трафик исключений выходит напрямую и попадает под DPI. Для него рядом работает
[zapret-discord-youtube-rust](https://github.com/Sergeydigl3/zapret-discord-youtube-rust) (`./zapret-rust-linux-x86_64`, бинарник в репо). Guard пропускает его пакеты с меткой `0x40000000`, а TUN не забирает сырые сокеты nfqws (`exclude_uid`). Запускать с `interface=enp5s0`, а не `any`, иначе nfqws обрабатывает ещё `lo` и `orouter0`. Трафик через Happ zapret не трогает.

Проверка, что фейки уходят в сеть (открыть сайт из hostlist приложением-исключением):

```
sudo nft list chain inet omarchy-router egress | grep counter
```
