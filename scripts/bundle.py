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
  bundle.py --deb OUT.deb INSTALLER ARCH VERSION
                                         Linux: a Debian package (ARCH amd64,
                                         arm64 or armhf) that runs INSTALLER when
                                         installed; its data is not compressed,
                                         so daemons and servers read it in place

Layout: tray | payloads | manifest JSON | u64 LE manifest length | MAGIC.
"""

import io
import json
import os
import shutil
import struct
import sys
import tarfile
import time

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


# Where the installer goes; DEB_INSTALLER in package.rs
DEB_INSTALLER = "usr/lib/retail/retail-installer"

POSTINST = """#!/bin/sh
# Installs retail with the installer in this package: the programs in
# /usr/local/bin, the daemon started at boot. Administrators (the sudo,
# admin and wheel groups) may control it from their tray app.
set -e
case "$1" in
configure)
    if ! getent group retail >/dev/null; then
        groupadd --system retail
    fi
    for g in sudo admin wheel; do
        for u in $(getent group "$g" | cut -d: -f4 | tr , " "); do
            usermod -aG retail "$u" || true
        done
    done
    # Without systemd (a container) the programs are still put in place
    /usr/lib/retail/retail-installer --yes --no-autostart || echo "retail: start retaild yourself (no systemd?)"
    ;;
esac
exit 0
"""

PRERM = """#!/bin/sh
# Removing the package removes retail; an upgrade keeps it running
set -e
case "$1" in
remove|purge)
    if [ -x /usr/local/bin/retail-tray ]; then
        /usr/local/bin/retail-tray --uninstall --yes || true
    fi
    ;;
esac
exit 0
"""

DESKTOP = """[Desktop Entry]
Type=Application
Name=retail
Comment=Your devices in one private network
Exec=/usr/local/bin/retail-tray --show
Icon=/usr/local/share/icons/hicolor/256x256/apps/retail.png
Categories=Network;
"""

AUTOSTART = """[Desktop Entry]
Type=Application
Name=retail
Exec=/usr/local/bin/retail-tray
X-GNOME-Autostart-enabled=true
NoDisplay=true
"""


def tar_bytes(entries, compress):
    """entries: (path, mode, bytes or None for a directory)"""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz" if compress else "w", format=tarfile.GNU_FORMAT) as t:
        for path, mode, data in entries:
            info = tarfile.TarInfo(path)
            info.mode = mode
            info.mtime = int(time.time())
            info.uname = info.gname = "root"
            if data is None:
                info.type = tarfile.DIRTYPE
                t.addfile(info)
            else:
                info.size = len(data)
                t.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def deb(out, installer, arch, version):
    with open(installer, "rb") as f:
        inst = f.read()
    data = tar_bytes([
        ("./", 0o755, None),
        ("./usr/", 0o755, None),
        ("./usr/lib/", 0o755, None),
        ("./usr/lib/retail/", 0o755, None),
        ("./" + DEB_INSTALLER, 0o755, inst),
        ("./usr/share/", 0o755, None),
        ("./usr/share/applications/", 0o755, None),
        ("./usr/share/applications/retail.desktop", 0o644, DESKTOP.encode()),
        ("./etc/", 0o755, None),
        ("./etc/xdg/", 0o755, None),
        ("./etc/xdg/autostart/", 0o755, None),
        ("./etc/xdg/autostart/retail-tray.desktop", 0o644, AUTOSTART.encode()),
    ], compress=False)
    control = (
        "Package: retail\n"
        f"Version: {version}\n"
        f"Architecture: {arch}\n"
        "Maintainer: retail <https://github.com/r2adkr/retail>\n"
        f"Installed-Size: {len(inst) // 1024 + 4}\n"
        "Section: net\n"
        "Priority: optional\n"
        "Homepage: https://github.com/r2adkr/retail\n"
        "Description: self-hosted mesh VPN\n"
        " retail connects your devices into one private network. This package\n"
        " installs the daemon, the tray app and the retail command.\n"
    )
    ctl = tar_bytes([
        ("./", 0o755, None),
        ("./control", 0o644, control.encode()),
        ("./postinst", 0o755, POSTINST.encode()),
        ("./prerm", 0o755, PRERM.encode()),
    ], compress=True)
    now = int(time.time())

    def member(name, body):
        head = f"{name:<16}{now:<12}{0:<6}{0:<6}{0o100644:<8o}{len(body):<10}`\n".encode()
        assert len(head) == 60
        return head + body + (b"\n" if len(body) % 2 else b"")

    with open(out, "wb") as o:
        o.write(b"!<arch>\n")
        o.write(member("debian-binary", b"2.0\n"))
        o.write(member("control.tar.gz", ctl))
        o.write(member("data.tar", data))


def main(argv):
    if len(argv) == 4 and argv[0] == "--app":
        app(argv[1], argv[2], argv[3])
        return
    if len(argv) == 5 and argv[0] == "--deb":
        deb(argv[1], argv[2], argv[3], argv[4])
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
