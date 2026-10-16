# Brand assets

Source of truth: the ServanaGo asset pack, `original-concept` files (the pack's SVGs are hand-drawn approximations and are not shipped).

- `servanago-wordmark.png`: `logo/servanago-original-concept-wordmark.png`, unmodified (opaque dark background). Used by the README.
- `internal/web/static/{favicon-16,favicon-32,mark-64,mark-192}.png`: derived from `preview/original-concept-icon-panel.png`.
- `internal/web/static/apple-touch-icon.png`: same tile, 180px, flattened onto the UI ink color `#10191B` (iOS has no transparency).

Why derived: every `original-concept-*` icon PNG in the pack is opaque (a light `#F0F1F3` surround is baked in), and the 512px export is cropped on the right. The icon panel is the only file with the whole tile, so `keyout.py` crops it, makes the surround transparent with a flood fill from the border, centers the tile and exports the sizes:

```sh
python3 -I docs/brand/keyout.py <pack>/preview/original-concept-icon-panel.png <out-dir>   # writes 16/32/64/192.png and full.png (the keyed tile)
```

Replace these with traced vector artwork when the mark is redrawn (tracked follow-up).
