"""Key the baked-in light background out of the original-concept icon and export transparent sizes.

The source stays untouched; only the flat light surround is made transparent. Tile pixels (everything
the flood fill from the border cannot reach) are copied unchanged.
"""
import sys
from PIL import Image
import numpy as np

SRC = sys.argv[1]
OUT = sys.argv[2]

im = Image.open(SRC).convert("RGB").crop((85, 85, 500, 500))  # panel: full tile, junk at the far left excluded
a = np.asarray(im).astype(np.float32)
lum = 0.2126 * a[..., 0] + 0.7152 * a[..., 1] + 0.0722 * a[..., 2]

TILE = np.array([20, 29, 31], np.float32)  # tile ink, sampled inside the tile edge
t_lum = 0.2126 * TILE[0] + 0.7152 * TILE[1] + 0.0722 * TILE[2]
b_lum = float(np.median(lum[0:4, :]))  # flat background level along the top border

# Candidate = clearly brighter than the tile's edge; flood from the corner over candidates only.
cand = lum > t_lum + 8
region = np.zeros(cand.shape, bool)
stack = [(0, 0)]
h, w = cand.shape
while stack:
    y, x = stack.pop()
    if y < 0 or x < 0 or y >= h or x >= w or region[y, x] or not cand[y, x]:
        continue
    region[y, x] = True
    stack.extend(((y + 1, x), (y - 1, x), (y, x + 1), (y, x - 1)))

alpha = np.full(lum.shape, 255, np.float32)
rgb = a.copy()
alpha_bg = np.clip((b_lum - lum) / (b_lum - t_lum), 0, 1) * 255
alpha[region] = alpha_bg[region]
rgb[region] = TILE  # boundary pixels are tile-edge color blended with the background

rgba = np.dstack([rgb, alpha]).astype(np.uint8)
big = Image.fromarray(rgba, "RGBA")
# The tile is off-center in the source: crop to its solid bounds, then pad to a centered square.
x0, y0, x1, y1 = Image.fromarray((alpha > 128).astype(np.uint8) * 255).getbbox()
tile = big.crop((x0, y0, x1, y1))
side = max(tile.size)
big = Image.new("RGBA", (side, side), (0, 0, 0, 0))
big.paste(tile, ((side - tile.size[0]) // 2, (side - tile.size[1]) // 2))
print("tile bbox", (x0, y0, x1, y1), "square", side)
print("transparent px:", int((alpha == 0).sum()), "partial:", int(((alpha > 0) & (alpha < 255)).sum()))

for n in (16, 32, 64, 192):
    # premultiplied resize avoids light fringes at the soft edge
    small = big.convert("RGBa").resize((n, n), Image.LANCZOS).convert("RGBA")
    small.save(f"{OUT}/{n}.png", optimize=True)
big.save(f"{OUT}/full.png", optimize=True)
