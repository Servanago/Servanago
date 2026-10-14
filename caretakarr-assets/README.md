# Caretakarr Brand Asset Pack

This pack contains the generated Caretakarr concept artwork plus practical assets for the web UI.

## Contents
- `logo/caretakarr-hero.png` — full promotional/banner artwork.
- `logo/caretakarr-lockup.png` — cropped wordmark/tagline area from the concept artwork.
- `logo/caretakarr-mascot.png` — mascot crop for about pages and empty states.
- `logo/caretakarr-mark.svg` — clean, scalable shield-and-lock UI mark.
- `icons/` — square PNG crops at common icon sizes. These retain the dark background.
- `webui/caretakarr-hero-web.png` — resized hero image for web use.
- `tokens/caretakarr.css` — CSS custom properties for the Caretakarr dark UI theme.
- `tokens/caretakarr.tokens.json` — design tokens in JSON.
- `tokens/tailwind-caretakarr.js` — Tailwind theme extension.

## Recommended UI direction
Use a dark navy canvas (`--ct-bg`) with raised navy panels, cyan for primary actions/focus, and green for secure/healthy HTTPS states. Reserve orange for occasional Cloudflare-related accents. Avoid using the full hero artwork as the application header; use the SVG mark and a simple text wordmark in normal navigation.

## Suggested integration
1. Copy `logo/caretakarr-mark.svg` to your web UI's static/public assets directory.
2. Import `tokens/caretakarr.css` globally, or merge its variables into your existing stylesheet.
3. Merge `tokens/tailwind-caretakarr.js` into the existing Tailwind config if applicable. Do not replace your existing config wholesale.
4. Keep status colors semantically consistent: green = secure/healthy, amber = attention, red = error, cyan = informational/interactive.

## Notes
The hero/lockup/mascot/icon PNGs are crops from the generated concept image and are raster artwork, not independently typeset vector logos. For production UI, the included SVG shield mark is the crispest scalable asset. The image artwork includes Cloudflare and ecosystem references as illustrative context; this is not an official affiliation claim.
