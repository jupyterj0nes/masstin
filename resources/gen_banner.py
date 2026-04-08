from PIL import Image
import colorsys

img = Image.open('D:/c00pr/tools/masstin/resources/masstin_logo.png').convert('RGBA')
w, h = img.size
img_cropped = img.crop((int(w*0.05), int(h*0.01), int(w*0.95), int(h*0.65)))

target_w = 65
target_h = 28
img_resized = img_cropped.resize((target_w, target_h), Image.LANCZOS)

chars = ' .:-=+*#%@'

for y in range(target_h):
    line = ''
    dominant_c = 0
    dominant_p = 0
    for x in range(target_w):
        r, g, b, a = img_resized.getpixel((x, y))
        brightness = (0.299*r + 0.587*g + 0.114*b)
        if brightness < 20:
            line += ' '
        else:
            idx = min(int(brightness / 255 * (len(chars)-1)), len(chars)-1)
            line += chars[idx]
            if max(r,g,b) > 0:
                h_val, s, v = colorsys.rgb_to_hsv(r/255, g/255, b/255)
                hue_deg = h_val * 360
                if s > 0.2:
                    if 140 <= hue_deg <= 220:
                        dominant_c += 1
                    elif hue_deg > 270 or hue_deg < 30:
                        dominant_p += 1

    stripped = line.rstrip()
    if not stripped.strip():
        continue

    if dominant_c > dominant_p and dominant_c > 2:
        color = 'C'
    elif dominant_p > dominant_c and dominant_p > 2:
        color = 'P'
    elif dominant_c > 0 and dominant_p > 0:
        color = 'M'
    else:
        color = 'W'

    escaped = stripped.replace('\\', '\\\\').replace('"', '\\"')
    print(f'    ("{escaped}", \'{color}\'),')
