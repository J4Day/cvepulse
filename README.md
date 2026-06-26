# CVE//PULSE

Персональная автономная лента CVE и security-ресёрча. Дизайн в стиле Nothing.
Без сервера: агрегатор крутится в GitHub Actions, приложение — PWA, ставится на телефон как APK.

```
GitHub Actions (cron, каждый час)
        │  тянет 11 источников: CISA KEV, NVD, Synacktiv, Krebs, watchTowr…
        ▼
   docs/feed.json  ──published──►  GitHub Pages (бесплатный CDN)
        ▲                                  │
        │                                  ▼
   sources.yml                      PWA / APK (читалка, офлайн-кэш)
```

## Что внутри

```
cvepulse/
├─ aggregator.py          # сборщик: RSS + NVD + CISA KEV → feed.json
├─ sources.yml            # ← СЮДА добавляешь источники
├─ requirements.txt
├─ .github/workflows/
│   └─ aggregate.yml      # cron каждый час + ручной запуск
└─ docs/                  # это раздаётся как GitHub Pages
    ├─ index.html         # само приложение (один файл)
    ├─ manifest.json      # PWA-манифест (иконка, фуллскрин)
    ├─ sw.js              # service worker (офлайн)
    ├─ icon-192.png
    ├─ icon-512.png
    └─ feed.json          # генерится автоматически
```

---

## Запуск за 5 шагов

### 1. Создай репозиторий
Залей все файлы в новый GitHub-репо (можно приватный — Pages всё равно отдаст).

### 2. Включи GitHub Pages
`Settings → Pages → Source: Deploy from a branch → Branch: main, папка /docs → Save`
Через минуту приложение будет на `https://ТВОЙ_НИК.github.io/ИМЯ_РЕПО/`

### 3. Включи Actions
`Settings → Actions → General → Workflow permissions → Read and write permissions → Save`
(нужно, чтобы бот мог коммитить feed.json)

### 4. Запусти первый сбор
`Actions → aggregate-feed → Run workflow`
Через ~1 мин в `docs/feed.json` появятся данные. Дальше — автоматически каждый час.

### 5. Открой на телефоне → «Установить приложение»
Chrome покажет «Добавить на главный экран». Готово — иконка, фуллскрин, офлайн.

> **Важно:** в `docs/index.html` переменная `FEED_URL = "feed.json"` работает, т.к. файл лежит рядом. Менять не надо.

---

## Превратить в настоящий .apk

PWA уже ставится как приложение. Если нужен именно файл `.apk` (например, чтобы раздать или поставить без браузера):

**Вариант A — PWABuilder (без установки, в браузере):**
1. Зайди на https://www.pwabuilder.com
2. Вставь URL своего GitHub Pages
3. `Package For Stores → Android → Generate` → скачаешь `.apk` + `.aab`

**Вариант B — Bubblewrap (CLI, локально):**
```bash
npm i -g @bubblewrap/cli
bubblewrap init --manifest https://ТВОЙ_НИК.github.io/ИМЯ_РЕПО/manifest.json
bubblewrap build          # на выходе app-release-signed.apk
```
Закинь .apk на телефон, открой, поставь (разреши «установку из неизвестных источников»).

---

## Добавить источник

Открой `sources.yml`, добавь блок в `research:`. Пересборка приложения **не нужна** — следующий прогон Actions подхватит.

**Обычный сайт с RSS:**
```yaml
  - name: "Assetnote"
    type: rss
    tag: RESEARCH
    url: "https://blog.assetnote.io/feed.xml"
```

**Сайт блокирует фид (Cloudflare 403) или фида нет** — тянем через Google News:
```yaml
  - name: "Какой-то блог"
    type: gnews
    tag: RESEARCH
    domain: "example.com"
```

**Поменять чувствительность NVD** (например, ловить и MEDIUM):
```yaml
  - name: "NVD"
    type: nvd
    lookback_days: 3
    min_severity: MEDIUM    # LOW | MEDIUM | HIGH | CRITICAL
```

`tag` управляет подписью: `KEV`, `RESEARCH`, `NEWS`, `NVD`.

---

## Жесты в приложении

| Действие | Жест |
|---|---|
| Открыть статью/CVE | тап по карточке |
| Сохранить в SAVED | долгое нажатие (~0.5с) на карточку |
| Обновить ленту | потянуть вниз вверху списка |
| Фильтры | вкладки ALL / KEV / CRIT / RSRCH |

Лента сама тихо обновляется раз в 5 минут, плюс кэшируется офлайн.

---

## Ускорить NVD (опционально)

Без ключа NVD лимитит до ~5 запросов / 30 сек. Бесплатный ключ снимает это:
1. Получи на https://nvd.nist.gov/developers/request-an-api-key
2. `Settings → Secrets and variables → Actions → New repository secret`
   Имя: `NVD_API_KEY`, значение: твой ключ.
Агрегатор подхватит автоматически.

---

## Частота обновления

Сейчас cron стоит на каждый час (`0 * * * *`). Хочешь чаще — поменяй в
`.github/workflows/aggregate.yml`, например каждые 30 мин: `*/30 * * * *`.
(GitHub Actions free tier: 2000 минут/мес, один прогон ~30 сек → запас огромный.)
