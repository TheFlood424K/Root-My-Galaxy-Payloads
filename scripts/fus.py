"""Samsung FUS (Firmware Update Service) client.

Downloads AP firmware packages from Samsung's NeoFUS endpoint using only
Python stdlib + curl_cffi for TLS impersonation.

Samsung's NeoFUS server performs TLS ClientHello fingerprinting and sends
a TCP RST (WinError 10054 on Windows, ECONNRESET on Linux) for connections
that don't look like a real browser or Android device.  curl_cffi wraps
libcurl compiled with BoringSSL and impersonates a Chrome TLS fingerprint,
bypassing the block.

Dependencies
  pip install curl_cffi pycryptodome

CLI usage
---------
  python3 fus.py latest   MODEL REGION
  python3 fus.py download MODEL REGION VERSION OUTDIR
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import sys
import time
import urllib.parse

try:
    from curl_cffi import requests as _creq
    _SESSION = _creq.Session(impersonate="chrome120")
    _USE_CURL_CFFI = True
except ImportError:
    _USE_CURL_CFFI = False
    import urllib.error
    import urllib.request

FUS_HOST = "https://neofus.samsungmobile.com"
USER_AGENT = (
    "Dalvik/2.1.0 (Linux; U; Android 12; SM-G991B Build/SP1A.210812.016)"
)

_K1 = "vicopx7dqu06em2f"
_K2 = "waxd789d2eonk84g"

_MAX_RETRIES = 3
_RETRY_BACKOFF = [5, 15, 30]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _derive(nonce: str) -> str:
    key = ""
    for i in range(16):
        x = ord(nonce[i])
        key += _K1[x % 16] if i % 2 == 0 else _K2[x % 16]
    return key


def _getauth(nonce: str) -> str:
    key = _derive(nonce)
    digest = hmac.new(key.encode(), nonce.encode(), hashlib.md5).digest()
    token = base64.b64encode(digest).decode()
    return "nonce={};signature={};nc=1;type=2;".format(
        nonce, urllib.parse.quote(token)
    )


def _post(path: str, body: str, auth: str = "", timeout: int = 60) -> tuple[str, str]:
    """POST XML body to FUS, return (response_text, nonce_header).

    Uses curl_cffi (Chrome TLS impersonation) when available;
    falls back to stdlib urllib otherwise.
    """
    url = FUS_HOST + path
    headers = {
        "Content-Type": "application/xml",
        "User-Agent": USER_AGENT,
    }
    if auth:
        headers["Authorization"] = auth

    last_exc: Exception = RuntimeError("No attempts made")
    for attempt in range(_MAX_RETRIES):
        if attempt > 0:
            wait = _RETRY_BACKOFF[attempt - 1]
            print(
                "  [fus] network error on attempt {}/{}; retrying in {}s...".format(
                    attempt, _MAX_RETRIES, wait
                ),
                flush=True,
            )
            time.sleep(wait)
        try:
            if _USE_CURL_CFFI:
                r = _SESSION.post(
                    url,
                    content=body.encode(),
                    headers=headers,
                    timeout=timeout,
                )
                r.raise_for_status()
                nonce = r.headers.get("NONCE", "")
                text = r.text
            else:
                req = urllib.request.Request(
                    url, data=body.encode(), method="POST"
                )
                for k, v in headers.items():
                    req.add_header(k, v)
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    nonce = resp.getheader("NONCE", "")
                    text = resp.read().decode(errors="replace")
            return text, nonce
        except Exception as exc:
            last_exc = exc
            print("  [fus] attempt {} failed: {}".format(attempt + 1, exc), flush=True)

    raise RuntimeError(
        "FUS request to {} failed after {} attempts. Last error: {}".format(
            path, _MAX_RETRIES, last_exc
        )
    )


def _stream_get(url: str, auth: str, out_path: str, filesize: int) -> None:
    """Streaming GET for the large binary download.

    Uses curl_cffi session when available for the same TLS impersonation;
    falls back to urllib for the binary stream.
    """
    headers = {
        "Authorization": auth,
        "User-Agent": USER_AGENT,
    }
    chunk = 1 << 20
    downloaded = 0
    last_pct = -1

    if _USE_CURL_CFFI:
        with _SESSION.stream(
            "GET", url, headers=headers, timeout=600
        ) as r:
            r.raise_for_status()
            with open(out_path, "wb") as f:
                for buf in r.iter_content(chunk_size=chunk):
                    if not buf:
                        break
                    f.write(buf)
                    downloaded += len(buf)
                    if filesize:
                        pct = downloaded * 100 // filesize
                        if pct != last_pct and pct % 10 == 0:
                            print(
                                "  {}%  ({}/{} MB)".format(
                                    pct,
                                    downloaded // 1024 // 1024,
                                    filesize // 1024 // 1024,
                                ),
                                flush=True,
                            )
                            last_pct = pct
    else:
        import urllib.request as _ur
        req = _ur.Request(url)
        for k, v in headers.items():
            req.add_header(k, v)
        with _ur.urlopen(req, timeout=600) as r, open(out_path, "wb") as f:
            while True:
                buf = r.read(chunk)
                if not buf:
                    break
                f.write(buf)
                downloaded += len(buf)
                if filesize:
                    pct = downloaded * 100 // filesize
                    if pct != last_pct and pct % 10 == 0:
                        print(
                            "  {}%  ({}/{} MB)".format(
                                pct,
                                downloaded // 1024 // 1024,
                                filesize // 1024 // 1024,
                            ),
                            flush=True,
                        )
                        last_pct = pct


def _xml(text: str, tag: str) -> str:
    m = re.search(r"<{tag}>(.*?)</{tag}>".format(tag=tag), text, re.S)
    return m.group(1).strip() if m else ""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_nonce() -> str:
    body = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        "<FUSMsg>"
        "<FUSHdr><ProDType>Smart Switch</ProDType></FUSHdr>"
        "<FUSBody/>"
        "</FUSMsg>"
    )
    resp, nonce = _post("/NF_DownloadGenerateNonce.do", body)
    if not nonce:
        nonce = _xml(resp, "NONCE")
    if not nonce:
        raise RuntimeError(
            "Could not obtain FUS nonce -- Samsung may have changed their API"
        )
    return nonce


def get_latest_version(model: str, region: str) -> str:
    nonce = get_nonce()
    auth = _getauth(nonce)
    body = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        "<FUSMsg>"
        "<FUSHdr><ProDType>Smart Switch</ProDType></FUSHdr>"
        "<FUSBody><Put>"
        "<ACCESS_MODE><Data>2</Data></ACCESS_MODE>"
        "<BINARY_NATURE><Data>1</Data></BINARY_NATURE>"
        "<CLIENT_PRODUCT><Data>Smart Switch</Data></CLIENT_PRODUCT>"
        "<DEVICE_MODEL_BLUETOOTH><Data>{model}</Data></DEVICE_MODEL_BLUETOOTH>"
        "<DEVICE_MODEL_TYPE><Data>1</Data></DEVICE_MODEL_TYPE>"
        "<COUNTRY_CODE><Data>{region}</Data></COUNTRY_CODE>"
        "<LOGIC_CHECK><Data></Data></LOGIC_CHECK>"
        "</Put></FUSBody></FUSMsg>"
    ).format(model=model, region=region)
    resp, _ = _post("/NF_DownloadBinaryInform.do", body, auth)
    v = _xml(resp, "LATEST_FW_VERSION") or _xml(resp, "CURRENT_OS_VERSION")
    return v.strip("/ \n")


def get_binary_info(model: str, region: str, version: str) -> dict:
    nonce = get_nonce()
    auth = _getauth(nonce)
    suffix = version[-16:] if len(version) >= 16 else version
    lc = "".join(
        chr(ord(a) ^ ord(b)) for a, b in zip(suffix, nonce[: len(suffix)])
    )
    body = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        "<FUSMsg>"
        "<FUSHdr><ProDType>Smart Switch</ProDType></FUSHdr>"
        "<FUSBody><Put>"
        "<ACCESS_MODE><Data>2</Data></ACCESS_MODE>"
        "<BINARY_NATURE><Data>1</Data></BINARY_NATURE>"
        "<CLIENT_PRODUCT><Data>Smart Switch</Data></Client_PRODUCT>"
        "<DEVICE_MODEL_BLUETOOTH><Data>{model}</Data></DEVICE_MODEL_BLUETOOTH>"
        "<DEVICE_MODEL_TYPE><Data>1</Data></DEVICE_MODEL_TYPE>"
        "<DEVICE_LOCAL_CODE><Data>{region}</Data></DEVICE_LOCAL_CODE>"
        "<DEVICE_FW_VERSION><Data>{version}</Data></DEVICE_FW_VERSION>"
        "<BINARY_FILE_TYPE><Data>AP</Data></BINARY_FILE_TYPE>"
        "<LOGIC_CHECK><Data>{lc}</Data></LOGIC_CHECK>"
        "</Put></FUSBody></FUSMsg>"
    ).format(model=model, region=region, version=version, lc=lc)
    resp, new_nonce = _post("/NF_DownloadBinaryInform.do", body, auth)
    filename = _xml(resp, "BINARY_NAME")
    filepath = _xml(resp, "MODEL_PATH")
    filesize = _xml(resp, "BINARY_BYTE_SIZE")
    if not filename:
        raise RuntimeError(
            "BinaryInform returned no filename:\n" + resp[:600]
        )
    new_auth = _getauth(new_nonce) if new_nonce else auth
    return {
        "filename": filename,
        "path": filepath,
        "size": int(filesize or 0),
        "auth": new_auth,
    }


def download_ap(model: str, region: str, version: str, outdir: str) -> str:
    info = get_binary_info(model, region, version)
    fname = info["filename"]
    fpath = info["path"]
    filesize = info["size"]
    auth = info["auth"]

    os.makedirs(outdir, exist_ok=True)
    enc_path = os.path.join(outdir, fname)
    out_path = (
        enc_path.rsplit(".", 1)[0]
        if fname.endswith((".enc4", ".enc2"))
        else enc_path
    )

    print(
        "Downloading {}  ({} MB)...".format(fname, filesize // 1024 // 1024),
        flush=True,
    )

    init_body = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        "<FUSMsg>"
        "<FUSHdr><ProDType>Smart Switch</ProDType></FUSHdr>"
        "<FUSBody><Put>"
        "<ACCESS_MODE><Data>2</Data></ACCESS_MODE>"
        "<BINARY_FILE_TYPE><Data>AP</Data></BINARY_FILE_TYPE>"
        "<BINARY_NATURE><Data>1</Data></BINARY_NATURE>"
        "<CLIENT_PRODUCT><Data>Smart Switch</Data></CLIENT_PRODUCT>"
        "<DEVICE_MODEL_BLUETOOTH><Data>{model}</Data></DEVICE_MODEL_BLUETOOTH>"
        "<DEVICE_LOCAL_CODE><Data>{region}</Data></DEVICE_LOCAL_CODE>"
        "<DEVICE_FW_VERSION><Data>{version}</Data></DEVICE_FW_VERSION>"
        "<FILENAME><Data>{fname}</Data></FILENAME>"
        "<MODEL_PATH><Data>{fpath}</Data></MODEL_PATH>"
        "<LOGIC_CHECK><Data></Data></LOGIC_CHECK>"
        "</Put></FUSBody></FUSMsg>"
    ).format(
        model=model, region=region, version=version, fname=fname, fpath=fpath
    )
    _post("/NF_DownloadBinaryInitForMass.do", init_body, auth)

    dl_url = FUS_HOST + "/NF_DownloadBinaryForMass.do?" + urllib.parse.urlencode(
        {"file": fpath + fname}
    )
    _stream_get(dl_url, auth, enc_path, filesize)
    print("Download complete: " + enc_path, flush=True)

    if fname.endswith(".enc4"):
        from Crypto.Cipher import AES
        key = (
            hashlib.md5(version[-16:].encode()).digest()
            + hashlib.md5(version[:16].encode()).digest()
        )
        iv = key[:16]
        with open(enc_path, "rb") as f:
            data = f.read()
        with open(out_path, "wb") as f:
            f.write(AES.new(key, AES.MODE_CBC, iv).decrypt(data))
        os.remove(enc_path)
        print("Decrypted enc4 -> " + out_path, flush=True)

    elif fname.endswith(".enc2"):
        from Crypto.Cipher import AES
        KEY = bytes(range(32))
        with open(enc_path, "rb") as f:
            data = f.read()
        with open(out_path, "wb") as f:
            f.write(AES.new(KEY, AES.MODE_ECB).decrypt(data))
        os.remove(enc_path)
        print("Decrypted enc2 -> " + out_path, flush=True)

    return out_path


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if not _USE_CURL_CFFI:
        print(
            "[fus] WARNING: curl_cffi not installed. "
            "Samsung may reject connections due to TLS fingerprinting.\n"
            "  Install with: pip install curl_cffi",
            file=sys.stderr,
        )
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "latest" and len(sys.argv) == 4:
        _model, _region = sys.argv[2], sys.argv[3]
        print(get_latest_version(_model, _region))
    elif cmd == "download" and len(sys.argv) == 6:
        _, _, _model, _region, _version, _outdir = sys.argv
        download_ap(_model, _region, _version, _outdir)
    else:
        print("Usage: python3 fus.py latest   MODEL REGION")
        print("       python3 fus.py download MODEL REGION VERSION OUTDIR")
        sys.exit(1)
