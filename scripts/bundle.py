#!/usr/bin/env python3
"""The official installer: one file per system that installs everything.

It is a client package (crates/retail-proto/src/package.rs) without an
invite: the tray app with the other programs appended, then the manifest.
Run, it installs retail; joining a network comes after, from the tray app.

  bundle.py OUT TRAY NAME=PATH...        the installer
  bundle.py --app OUT.zip INSTALLER      macOS: wrapped as retail.app in a zip,
                                         which keeps it runnable after a download

Layout: tray | payloads | manifest JSON | u64 LE manifest length | MAGIC.
"""

import json
import os
import struct
import sys
import zipfile

MAGIC = b"RETAIL-PACKAGE-1"

INFO_PLIST = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>retail</string>
<key>CFBundleIdentifier</key><string>dev.retail.installer</string>
<key>CFBundleName</key><string>retail</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>LSUIElement</key><true/>
</dict></plist>
"""

# Where the installer sits in the zip; the daemon and server look for it there
APP_EXECUTABLE = "retail.app/Contents/MacOS/retail"


def bundle(out, tray, files):
    with open(out, "wb") as o:
        with open(tray, "rb") as t:
            data = t.read()
        o.write(data)
        offset = len(data)
        packed = []
        for name, path in files:
            with open(path, "rb") as f:
                data = f.read()
            o.write(data)
            packed.append({"name": name, "offset": offset, "len": len(data)})
            offset += len(data)
        base_len = os.path.getsize(tray)
        manifest = json.dumps({"invite": "", "network": "", "files": packed, "base_len": base_len}, separators=(",", ":")).encode()
        o.write(manifest)
        o.write(struct.pack("<Q", len(manifest)))
        o.write(MAGIC)
    os.chmod(out, 0o755)


def entry(name, mode):
    info = zipfile.ZipInfo(name, date_time=(2024, 1, 1, 0, 0, 0))
    info.create_system = 3  # Unix, so the permission bits below count
    info.external_attr = (mode & 0xFFFF) << 16
    info.compress_type = zipfile.ZIP_STORED
    return info


def app_zip(out, installer):
    # Stored, not compressed: the daemon reads the installer straight out of it
    with zipfile.ZipFile(out, "w", zipfile.ZIP_STORED) as z:
        z.writestr(entry("retail.app/Contents/Info.plist", 0o100644), INFO_PLIST)
        with open(installer, "rb") as f:
            z.writestr(entry(APP_EXECUTABLE, 0o100755), f.read())


def main(argv):
    if len(argv) == 3 and argv[0] == "--app":
        app_zip(argv[1], argv[2])
        return
    if len(argv) < 2:
        sys.exit(__doc__)
    files = []
    for a in argv[2:]:
        name, sep, path = a.partition("=")
        if not sep or not name or "/" in name or "\\" in name:
            sys.exit(f"expected NAME=PATH, got {a}")
        files.append((name, path))
    bundle(argv[0], argv[1], files)


if __name__ == "__main__":
    main(sys.argv[1:])
