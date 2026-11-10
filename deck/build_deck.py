"""Writes deck/index.html (self-contained, offline). Optional: pip install qrcode for the QR code."""
import os, sys
URL = sys.argv[1] if len(sys.argv) > 1 else "https://github.com/izzetp/airlock"
qr = ""
try:
    import qrcode, qrcode.image.svg, io
    b = io.BytesIO(); qrcode.make(URL, image_factory=qrcode.image.svg.SvgPathImage, box_size=10, border=0).save(b)
    qr = b.getvalue().decode().split("?>", 1)[-1]
except ImportError:
    pass
here = os.path.dirname(os.path.abspath(__file__))
html = open(os.path.join(here, "template.html"), encoding="utf-8").read().replace("<!--QR-->", qr).replace("__URL__", URL.replace("https://", ""))
open(os.path.join(here, "index.html"), "w", encoding="utf-8").write(html)
print("wrote deck/index.html")
