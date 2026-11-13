"""生成 PWA 图标（纯标准库手写 PNG，无需 Pillow）。运行： python tools/make_icons.py"""
import math
import pathlib
import struct
import zlib

OUT = pathlib.Path(__file__).resolve().parents[1] / 'icons'
OUT.mkdir(parents=True, exist_ok=True)


def clamp(v, a=0.0, b=1.0):
    return max(a, min(b, v))


def sd_round_rect(x, y, cx, cy, hw, hh, r):
    qx = abs(x - cx) - (hw - r)
    qy = abs(y - cy) - (hh - r)
    return math.hypot(max(qx, 0.0), max(qy, 0.0)) + min(max(qx, qy), 0.0) - r


def coverage(sd, feather):
    """sd 为归一化距离，feather 为 1 像素对应的归一化长度"""
    return clamp(0.5 - sd / feather)


def blend(dst, src, a):
    return tuple(d * (1 - a) + s * a for d, s in zip(dst, src))


def render(size, maskable=False):
    feather = 1.35 / size
    rows = bytearray()
    # 内容缩放：maskable 图标把主体收进 80% 安全区
    scale = 0.76 if maskable else 1.0

    def tf(v):
        return 0.5 + (v - 0.5) * scale

    for py in range(size):
        row = bytearray()
        for px in range(size):
            u = (px + 0.5) / size
            v = (py + 0.5) / size
            # 背景渐变
            t = clamp((u * 0.45 + v * 0.55))
            bg = (59 + (29 - 59) * t, 130 + (78 - 130) * t, 246 + (216 - 246) * t)
            if maskable:
                bg_alpha = 1.0
            else:
                bg_alpha = coverage(sd_round_rect(u, v, 0.5, 0.5, 0.5, 0.5, 0.225), feather)

            # 锁体（白色圆角矩形）
            body = coverage(sd_round_rect(u, v, 0.5, tf(0.595), 0.205 * scale, 0.155 * scale, 0.045 * scale), feather)
            # 锁梁（上半圆环）
            cx, cy = 0.5, tf(0.475)
            dist = math.hypot(u - cx, v - cy)
            outer, inner = 0.145 * scale, 0.092 * scale
            ring = coverage(max(dist - outer, inner - dist, v - cy), feather)
            # 锁梁下端延续到锁体（两侧短柱）
            left_post = coverage(sd_round_rect(u, v, cx - (outer + inner) / 2, tf(0.49), (outer - inner) / 2, 0.035 * scale, 0.008), feather)
            right_post = coverage(sd_round_rect(u, v, cx + (outer + inner) / 2, tf(0.49), (outer - inner) / 2, 0.035 * scale, 0.008), feather)
            white = clamp(max(body, ring, left_post, right_post))

            # 锁孔（挖空回背景色）
            key_r = 0.031 * scale
            keyhole = coverage(math.hypot(u - 0.5, v - tf(0.575)) - key_r, feather)
            stem = coverage(sd_round_rect(u, v, 0.5, tf(0.625), 0.017 * scale, 0.045 * scale, 0.008), feather)
            white = clamp(white - max(keyhole, stem))

            rgb = blend(bg, (255, 255, 255), white)
            row += bytes((round(rgb[0]), round(rgb[1]), round(rgb[2]), round(bg_alpha * 255)))
        rows += b'\x00' + row
    return bytes(rows)


def write_png(path, size, raw):
    def chunk(tag, data):
        return struct.pack('>I', len(data)) + tag + data + struct.pack('>I', zlib.crc32(tag + data) & 0xffffffff)

    png = (b'\x89PNG\r\n\x1a\n'
           + chunk(b'IHDR', struct.pack('>IIBBBBB', size, size, 8, 6, 0, 0, 0))
           + chunk(b'IDAT', zlib.compress(raw, 9))
           + chunk(b'IEND', b''))
    path.write_bytes(png)
    print(f'{path.name}: {size}x{size}, {len(png)} bytes')


write_png(OUT / 'icon-192.png', 192, render(192))
write_png(OUT / 'icon-512.png', 512, render(512))
write_png(OUT / 'icon-maskable-512.png', 512, render(512, maskable=True))
