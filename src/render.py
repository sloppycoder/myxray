"""HTML rendering for the QR-code output (?mode=qr).

The QR is generated server-side as an inline SVG data URI with `segno` (a pure
Python, dependency-free library). Nothing is fetched from a third party, so the
share URL — which contains the user's UUID — never leaves the Worker.
"""

import html as _html

import segno


def qr_html_page(url: str, title: str = "xray") -> str:
    """A minimal, self-contained HTML page showing a scannable QR for `url`."""
    qr = segno.make(url, error="m")
    data_uri = qr.svg_data_uri(scale=4, border=2)  # fully %-encoded; safe in src=""
    safe_title = _html.escape(title)
    safe_url = _html.escape(url)
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{safe_title}</title>
<style>
  body {{ font-family: system-ui, sans-serif; margin: 0; padding: 24px;
          display: flex; flex-direction: column; align-items: center; gap: 16px;
          background: #fff; color: #111; }}
  h1 {{ font-size: 18px; margin: 0; }}
  img.qr {{ width: min(86vw, 340px); height: auto; }}
  .url {{ max-width: 90vw; word-break: break-all; font-size: 12px;
          color: #555; text-align: center; }}
</style>
</head>
<body>
  <h1>{safe_title}</h1>
  <img class="qr" alt="Xray config QR code" src="{data_uri}">
  <div class="url">{safe_url}</div>
</body>
</html>"""
