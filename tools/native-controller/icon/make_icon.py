"""Regenerate the controller icon: app.png (window icon), app.icns, app.ico.

Needs Pillow; app.icns also needs macOS iconutil. Run from anywhere:
    python3 tools/native-controller/icon/make_icon.py
"""
import os
import shutil
import subprocess
import tempfile

from PIL import Image, ImageDraw

HERE = os.path.dirname(os.path.abspath(__file__))
SIZE = 1024
SS = 4  # supersampling factor for smooth edges


def lerp(a, b, t):
    return tuple(round(x + (y - x) * t) for x, y in zip(a, b))


def draw(size=SIZE):
    n = size * SS
    s = n / 1024  # design units are 1024 px

    def box(x0, y0, x1, y1):
        return [x0 * s, y0 * s, x1 * s, y1 * s]

    # Rounded-square tile with a vertical blue gradient (macOS grid: 824 px tile).
    grad = Image.new("RGBA", (n, n))
    gd = ImageDraw.Draw(grad)
    for y in range(n):
        gd.line([(0, y), (n, y)], fill=lerp((38, 99, 235), (17, 39, 112), y / n) + (255,))
    mask = Image.new("L", (n, n), 0)
    ImageDraw.Draw(mask).rounded_rectangle(box(100, 100, 924, 924), radius=185 * s, fill=255)
    img = Image.new("RGBA", (n, n), (0, 0, 0, 0))
    img.paste(grad, (0, 0), mask)
    d = ImageDraw.Draw(img)

    # Security key: USB-A plug on top, rounded body, touch ring with a check.
    d.rounded_rectangle(box(437, 168, 587, 330), radius=14 * s, fill=(203, 213, 225))
    d.rectangle(box(470, 205, 500, 240), fill=(100, 116, 139))
    d.rectangle(box(524, 205, 554, 240), fill=(100, 116, 139))
    d.rounded_rectangle(box(362, 300, 662, 856), radius=120 * s, fill=(248, 250, 252))
    cx, cy, r = 512, 600, 104
    d.ellipse(box(cx - r, cy - r, cx + r, cy + r), fill=(22, 163, 74))
    d.line([(cx - 50) * s, (cy + 2) * s, (cx - 14) * s, (cy + 40) * s, (cx + 54) * s, (cy - 38) * s],
           fill=(255, 255, 255), width=round(30 * s), joint="curve")
    for x, y in ((cx - 50, cy + 2), (cx + 54, cy - 38)):
        rr = 15
        d.ellipse(box(x - rr, y - rr, x + rr, y + rr), fill=(255, 255, 255))
    d.ellipse(box(492, 390, 532, 430), fill=(148, 163, 184))  # lanyard hole
    return img.resize((size, size), Image.LANCZOS)


def main():
    master = draw()
    master.resize((256, 256), Image.LANCZOS).save(os.path.join(HERE, "app.png"))
    master.save(os.path.join(HERE, "app.ico"), sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
    if shutil.which("iconutil"):
        with tempfile.TemporaryDirectory() as tmp:
            iconset = os.path.join(tmp, "app.iconset")
            os.mkdir(iconset)
            for px in (16, 32, 128, 256, 512):
                master.resize((px, px), Image.LANCZOS).save(os.path.join(iconset, f"icon_{px}x{px}.png"))
                master.resize((px * 2, px * 2), Image.LANCZOS).save(os.path.join(iconset, f"icon_{px}x{px}@2x.png"))
            subprocess.run(["iconutil", "-c", "icns", iconset, "-o", os.path.join(HERE, "app.icns")], check=True)
    else:
        print("iconutil not found; app.icns left unchanged")


if __name__ == "__main__":
    main()
