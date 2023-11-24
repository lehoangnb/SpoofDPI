**⭐Pull Request-ы или любые формы вклада будут признательны⭐**

# SpoofDPI

Можете прочитать на других языках: [🇬🇧English](https://github.com/lehoangnb/SpoofDPI), [🇰🇷한국어](https://github.com/lehoangnb/SpoofDPI/blob/main/readme_ko.md), [🇨🇳简体中文](https://github.com/lehoangnb/SpoofDPI/blob/main/readme_zh-cn.md), [🇷🇺Русский](https://github.com/lehoangnb/SpoofDPI/blob/main/readme_ru.md)

Простое и быстрое программное обеспечение, созданное для обхода **Deep Packet Inspection**  
  
![image](https://user-images.githubusercontent.com/45588457/148035986-8b0076cc-fefb-48a1-9939-a8d9ab1d6322.png)

# Установка
## Бинарник
SpoofDPI будет установлен в директорию `~/.spoof-dpi/bin`.  
Чтобы запустить SpoofDPI в любой директории, добавьте строку ниже в `~/.bashrc || ~/.zshrc || ...`
```
export PATH=$PATH:~/.spoof-dpi/bin
```

### curl
Установите последний бинарник с помощью curl
- OSX
```
curl -fsSL https://raw.githubusercontent.com/lehoangnb/SpoofDPI/main/install.sh | bash -s osx
```
- Linux
```
curl -fsSL https://raw.githubusercontent.com/lehoangnb/SpoofDPI/main/install.sh | bash -s linux
```
### wget
Установите последний бинарник с помощью wget
- OSX
```
wget -O - https://raw.githubusercontent.com/lehoangnb/SpoofDPI/main/install.sh | bash -s osx 
```
- Linux
```
wget -O - https://raw.githubusercontent.com/lehoangnb/SpoofDPI/main/install.sh | bash -s linux 
```
## Go
Вы также можете установить SpoofDPI с помощью **go install**  
`$ go install github.com/lehoangnb/SpoofDPI/cmd/spoof-dpi`  
  > Не забудьте, что $GOPATH должен быть установлен в Вашем $PATH

## Git
Вы также можете собрать SpoofDPI

`$ git clone https://github.com/lehoangnb/SpoofDPI.git`  
`$ cd SpoofDPI`  
`$ go build ./cmd/...`  

# Использование
```
Usage: spoof-dpi [options...]
--addr=<addr>       | default: 127.0.0.1
--dns=<addr>        | default: 8.8.8.8
--port=<number>     | default: 8080
--debug=<bool>      | default: false
--no-banner=<bool>  | default: false
--timeout=<number>  | default: 0
                    | Enforces specific connection timeout. Set 0 to turn off
--url=<url>         | Can be used multiple times. If set, 
                    | it will bypass DPI only for this url. 
                    | Example: --url=google.com --url=github.com
--pattern=<regex>   | If set, it will bypass DPI only for packets 
                    | that matches this regex pattern.
                    | Example: --pattern="google|github"
```
**Перевод:**
```
Использование: spoof-dpi [параметры...]
--addr=<адрес>       | Адрес. По умолчанию 127.0.0.1
--dns=<адрес>        | Адрес DNS-сервера. По умолчанию 8.8.8.8
--port=<порт>        | Порт. По умолчанию 8080
--debug=<булев>      | Включать ли режим отладки. По умолчанию false
--banner=<булев>     | По умолчанию true
--url=<url>          | Можно использовать несколько раз. Если 
                     | задано, будет применятся
                     | обход только для данного url.
                     | Пример: --url=google.com --url=github.com
--pattern=<regex>    | Если задано, будет применятся обход
                     | только для пакетов, которые соответствуют
                     | этому регулярному выражению.
                     | Пример: --pattern="google|github"
```
> Если Вы используете любые "VPN"-расширения по типу Hotspot Shield в браузере  
  Chrome, зайдите в Настройки > Расширения и отключите их.

### OSX
Выполните `$ spoof-dpi` и прокси автоматически установится

### Linux
Выполните `$ spoof-dpi` и откройте свой любимый браузер с параметром прокси
`google-chrome --proxy-server="http://127.0.0.1:8080"`

# Как это работает
### HTTP
Поскольку большинство веб-сайтов в мире теперь поддерживают HTTPS, SpoofDPI не обходит Deep Packet Inspection для HTTP-запросов, однако он по-прежнему обеспечивает прокси-соединение для всех HTTP-запросов.

### HTTPS
Хотя TLS 1.3 шифрует каждый процесс рукопожатия, имена доменов по-прежнему отображаются в виде открытого текста в пакете Client Hello. Другими словами, когда кто-то другой смотрит на пакет, он может легко догадаться, куда направляется пакет. Доменное имя может предоставлять значительную информацию во время обработки DPI, и мы можем видеть, что соединение блокируется сразу после отправки пакета Client Hello. Я попробовал несколько способов обойти это, и обнаружил, что, похоже, только первый фрагмент проверяется, когда мы отправляем пакет Client Hello, разделенный на фрагменты. Чтобы обойти это, SpoofDPI отправляет на сервер первый 1 байт запроса, а затем отправляет все остальное.
 > SpoofDPI не расшифровывает Ваши HTTPS-запросы, так что нам не нужны SSL-сертификаты.

# Вдохновлено
[Green Tunnel](https://github.com/SadeghHayeri/GreenTunnel) от @SadeghHayeri  
[GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI) от @ValdikSS
