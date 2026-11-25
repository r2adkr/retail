#!/usr/bin/env python3
"""The official installer: one file per system that installs everything.

It is a client package (crates/retail-proto/src/package.rs) without an
invite: the tray app with the other programs appended, then the manifest.
Run, it installs retail; joining a network comes after, from the tray app.

  bundle.py OUT TRAY NAME=PATH...        the installer
  bundle.py --app OUT.app INSTALLER TRAY macOS: retail.app, with the plain tray
                                         app as its program and the installer
                                         as a resource (so it can be signed)
  bundle.py --zip OUT.zip DIR            DIR in a zip, uncompressed, keeping
                                         permissions (so the app runs after a
                                         download, and the daemon reads it in place)

Layout: tray | payloads | manifest JSON | u64 LE manifest length | MAGIC.
"""

import json
import os
import shutil
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


def app(out, installer, tray):
    """retail.app: Contents/MacOS/retail is the tray app, which finds the
    installer at Contents/Resources/retail.package (APP_PACKAGE in package.rs)"""
    contents = os.path.join(out, "Contents")
    os.makedirs(os.path.join(contents, "MacOS"))
    os.makedirs(os.path.join(contents, "Resources"))
    with open(os.path.join(contents, "Info.plist"), "w") as f:
        f.write(INFO_PLIST)
    shutil.copyfile(tray, os.path.join(contents, "MacOS", "retail"))
    os.chmod(os.path.join(contents, "MacOS", "retail"), 0o755)
    shutil.copyfile(installer, os.path.join(contents, "Resources", "retail.package"))


def zip_dir(out, top):
    base = os.path.dirname(os.path.abspath(top))
    with zipfile.ZipFile(out, "w", zipfile.ZIP_STORED) as z:
        for root, dirs, files in os.walk(top):
            dirs.sort()
            for name in sorted(files):
                path = os.path.join(root, name)
                info = zipfile.ZipInfo(os.path.relpath(path, base).replace(os.sep, "/"), date_time=(2024, 1, 1, 0, 0, 0))
                info.create_system = 3  # Unix, so the permission bits below count
                info.external_attr = (os.stat(path).st_mode & 0xFFFF) << 16
                info.compress_type = zipfile.ZIP_STORED
                with open(path, "rb") as f:
                    z.writestr(info, f.read())


def main(argv):
    if len(argv) == 4 and argv[0] == "--app":
        app(argv[1], argv[2], argv[3])
        return
    if len(argv) == 3 and argv[0] == "--zip":
        zip_dir(argv[1], argv[2])
        return
    if len(argv) < 2 or argv[0].startswith("--"):
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
