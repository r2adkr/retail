#!/usr/bin/env python3
"""The official installer: one file per system that installs everything.

It is a client package (crates/retail-proto/src/package.rs) without an
invite: the tray app with the other programs appended, then the manifest.
Run, it installs retail; joining a network comes after, from the tray app.

  bundle.py OUT TRAY NAME=PATH...        the installer
  bundle.py --app OUT.app INSTALLER TRAY macOS: retail.app, with the plain tray
                                         app as its program and the installer
                                         as a resource (so it can be signed)
  bundle.py --dmg OUT.dmg INSTALLER IMG  macOS: the disk image IMG (made with
                                         hdiutil) with INSTALLER in front of its
                                         data, where daemons and servers read it

Layout: tray | payloads | manifest JSON | u64 LE manifest length | MAGIC.
"""

import json
import os
import shutil
import struct
import sys

MAGIC = b"RETAIL-PACKAGE-1"

INFO_PLIST = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>retail</string>
<key>CFBundleIdentifier</key><string>dev.retail.installer</string>
<key>CFBundleName</key><string>retail</string>
<key>CFBundlePackageType</key><string>APPL</string>
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


def dmg(out, installer, image):
    """A disk image ends in a 512-byte "koly" record whose offsets say where
    its data, resource fork and XML plist are. Putting bytes in front and
    moving those offsets keeps it a valid image; the package's own length is
    then the record's data offset (dmg_prefix in package.rs)."""
    with open(installer, "rb") as f:
        front = f.read()
    with open(image, "rb") as f:
        data = bytearray(f.read())
    koly = len(data) - 512
    if data[koly:koly + 4] != b"koly":
        sys.exit(f"{image} is not a disk image")
    for at in (24, 40, 216):  # data fork, resource fork, XML plist offsets
        (value,) = struct.unpack_from(">Q", data, koly + at)
        if value or at == 24:
            struct.pack_into(">Q", data, koly + at, value + len(front))
    with open(out, "wb") as o:
        o.write(front)
        o.write(data)


def main(argv):
    if len(argv) == 4 and argv[0] == "--app":
        app(argv[1], argv[2], argv[3])
        return
    if len(argv) == 4 and argv[0] == "--dmg":
        dmg(argv[1], argv[2], argv[3])
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
