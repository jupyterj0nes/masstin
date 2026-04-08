from PIL import Image

img = Image.open('D:/c00pr/tools/masstin/resources/masstin_logo.png').convert('RGBA')
w, h = img.size

# Full logo including dog + graph + text area
img_full = img.crop((int(w*0.02), int(h*0.01), int(w*0.98), int(h*0.95)))

# Characters that render well on ANY terminal (light to dense)
chars = ' .,:;+*?%#@'

def generate(target_w, target_h, label):
    resized = img_full.resize((target_w, target_h), Image.LANCZOS)
    gray = resized.convert('L')

    print(f"\n// ===== {label} ({target_w}x{target_h}) =====")
    lines = []
    for y in range(target_h):
        line = ''
        for x in range(target_w):
            pixel = gray.getpixel((x, y))
            idx = int(pixel / 255 * (len(chars) - 1))
            line += chars[idx]
        lines.append(line.rstrip())

    # Skip leading/trailing empty lines
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()

    for line in lines:
        print(f'    "{line}",')

    print(f"\n// Total: {len(lines)} lines, max width: {max(len(l) for l in lines)} chars")

# Compact version (for terminals < 120 chars)
generate(70, 35, "COMPACT")

# Large version (for terminals >= 150 chars)
generate(140, 60, "LARGE")
