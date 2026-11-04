# KasperskyOS CE 2.0 × QEMU-Wasm

Статический сайт с каталогом примеров KasperskyOS Community Edition 2.0 и их запуском
прямо в браузере: `qemu-system-aarch64`, собранный в WebAssembly
([ktock/qemu-wasm](https://github.com/ktock/qemu-wasm)), грузит предсобранные образы
примеров SDK (ядро `image` + `vendor_romfs.romfs` + `rootfs.img`) в xterm.js-терминал.

## Структура

- `index.html`, `assets/` — каталог примеров, архитектура KasperskyOS, конвейер сборки.
- `run/index.html` — страница-раннер (`?example=<имя>`, например `?example=hello`).
- `run/runtime/` — `qemu-system-aarch64.wasm` (66 МБ), `out.js`, worker, xterm, общее ядро.
- `run/images/<пример>/` — `rootfs.img.gz` и `vendor_romfs.romfs.gz` каждого примера.

## Деплой на GitHub Pages

```bash
git add -A
git commit -m "KasperskyOS CE 2.0 examples in browser via qemu-wasm"
git push origin main
```

Затем в репозитории: **Settings → Pages → Source: Deploy from a branch → main / (root)**.
Сайт будет доступен по адресу `https://simi4.github.io/kasperskyos-ce-qemu-wasm/`.

### Важные детали

- **COOP/COEP.** QEMU-Wasm нужен `SharedArrayBuffer` (pthread), а GitHub Pages не отдаёт
  произвольные заголовки. Поэтому в `run/` подключён
  [coi-serviceworker](https://github.com/gzuidhof/coi-serviceworker): при первом открытии
  раннера страница один раз перезагрузится сама — это нормально, дальше всё работает.
- **Размер.** Общий объём ~433 МБ (31 образ примера), самый большой файл —
  `qemu-system-aarch64.wasm`, 66 МБ (лимит GitHub — 100 МБ на файл).
- `.nojekyll` отключает Jekyll-обработку, чтобы Pages отдавал файлы как есть.
- `*.gz` отдаются без `Content-Encoding` — страница распаковывает их сама
  через `DecompressionStream`.
