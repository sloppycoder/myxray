"""HTML rendering for the QR route (GET /<pin>/qr).

Two states:
  * qr_running_page — the VM is up; show a scannable QR for the share URL.
  * qr_start_page   — the VM is stopped; show a "Start" button that boots it
                      (POST /<pin>/boot), polls GET /<pin> until it is ready, then
                      reloads to render the QR.

The QR is generated server-side as an inline SVG data URI with `segno` (a pure
Python, dependency-free library). Nothing is fetched from a third party, so the
share URL — which contains the user's UUID — never leaves the Worker.
"""

import html as _html

import segno

_STYLE = """
  body { font-family: system-ui, sans-serif; margin: 0; padding: 24px;
         display: flex; flex-direction: column; align-items: center; gap: 16px;
         background: #fff; color: #111; }
  h1 { font-size: 18px; margin: 0; }
  img.qr { width: min(86vw, 340px); height: auto; }
  .url { max-width: 90vw; word-break: break-all; font-size: 12px;
         color: #555; text-align: center; }
  button { font-size: 16px; padding: 12px 28px; border: 0; border-radius: 8px;
           background: #111; color: #fff; cursor: pointer; }
  button:disabled { background: #999; cursor: default; }
  .status { font-size: 13px; color: #555; min-height: 1.2em; text-align: center; }
"""


def qr_running_page(url: str, title: str = "xray") -> str:
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
<style>{_STYLE}</style>
</head>
<body>
  <h1>{safe_title}</h1>
  <img class="qr" alt="Xray config QR code" src="{data_uri}">
  <div class="url">{safe_url}</div>
</body>
</html>"""


def qr_start_page(title: str = "xray") -> str:
    """A page with a Start button: boots the VM, polls until ready, then reloads.

    The current page lives at /<pin>/qr, so the boot endpoint is the sibling
    "../<pin>/boot" and the readiness probe is "../<pin>" — both derived from the
    current path in JS, so no PIN needs to be embedded in the HTML.
    """
    safe_title = _html.escape(title)
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{safe_title}</title>
<style>{_STYLE}</style>
</head>
<body>
  <h1>{safe_title}</h1>
  <p class="status">Server is stopped.</p>
  <button id="start">Start server</button>
  <div class="status" id="status"></div>
<script>
  // /<pin>/qr -> base "/<pin>"
  var base = window.location.pathname.replace(/\\/qr\\/?$/, "");
  var btn = document.getElementById("start");
  var status = document.getElementById("status");
  var DEADLINE_MS = 120000;   // give the VM up to 2 min to come up
  var POLL_MS = 4000;

  btn.addEventListener("click", function () {{
    btn.disabled = true;
    status.textContent = "Starting…";
    fetch(base + "/boot", {{ method: "POST" }})
      .then(function () {{ poll(Date.now() + DEADLINE_MS); }})
      .catch(function () {{ fail("Could not start the server."); }});
  }});

  function poll(deadline) {{
    if (Date.now() > deadline) {{ return fail("Timed out waiting for the server."); }}
    // GET /<pin> is the readiness probe: 200 when running, 404 while booting.
    fetch(base, {{ cache: "no-store" }})
      .then(function (res) {{
        if (res.ok) {{ window.location.reload(); return; }}
        if (res.status === 404) {{ setTimeout(function () {{ poll(deadline); }}, POLL_MS); return; }}
        fail("Server error (" + res.status + ").");
      }})
      .catch(function () {{ setTimeout(function () {{ poll(deadline); }}, POLL_MS); }});
  }}

  function fail(msg) {{ status.textContent = msg; btn.disabled = false; }}
</script>
</body>
</html>"""
