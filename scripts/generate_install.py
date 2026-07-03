#!/usr/bin/env python3
import argparse
import secrets
import string
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "deploy" / "routeros-install.rsc.tpl"


def random_password(length=28):
    alphabet = string.ascii_letters + string.digits + "-_"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def main():
    parser = argparse.ArgumentParser(description="Generate RouterOS installer script.")
    parser.add_argument("--lan-address", default="192.168.88.1", help="MikroTik LAN address used to open Web UI.")
    parser.add_argument("--lan-subnet", default="192.168.88.0/24", help="Subnet allowed to access Web UI.")
    parser.add_argument("--disk", default="disk1", help="RouterOS disk name for data/root dirs.")
    parser.add_argument("--data-dir", default="wg-easy-data", help="RouterOS Files directory mounted as /data.")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--image-file", default="mikrotik-wg-easy.tar", help="Container image filename on --disk.")
    source.add_argument("--image", default="", help="Exact RouterOS /file name for the container image. Advanced override.")
    source.add_argument("--remote-image", default="", help="Registry image, for example registry.example.com/mikrotik-wg-easy:latest.")
    parser.add_argument("--ui-port", default="8080", help="LAN TCP port for Web UI dst-nat.")
    parser.add_argument("--password", default="", help="Initial Web UI password. Generated if omitted.")
    parser.add_argument("--out", default="deploy/routeros-install.rsc", help="Output .rsc path.")
    args = parser.parse_args()

    password = args.password or random_password()
    if args.remote_image:
        container_source = f'remote-image="{args.remote_image}"'
        image_preflight = "# remote-image mode: no local image file preflight"
    else:
        image_name = args.image or f"{args.disk.rstrip('/')}/{args.image_file.lstrip('/')}"
        container_source = f"file={image_name}"
        image_preflight = (
            f':local image "{image_name}"\n'
            ':if ([:len [/file/find where name=$image]] = 0) do={\n'
            '  :error ("Container image file not found: " . $image . ". Check /file/print and regenerate installer with --image-file filename or --image exact-name")\n'
            '}'
        )
    content = TEMPLATE.read_text()
    replacements = {
        "__LAN_ADDRESS__": args.lan_address,
        "__LAN_SUBNET__": args.lan_subnet,
        "__DISK__": args.disk,
        "__DATA_DIR__": args.data_dir,
        "__UI_PORT__": str(args.ui_port),
        "__APP_PASSWORD__": password,
        "__CONTAINER_ADD_SOURCE__": container_source,
        "__IMAGE_PREFLIGHT__": image_preflight,
    }
    for key, value in replacements.items():
        content = content.replace(key, value)

    out = ROOT / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(content)
    print(f"Wrote {out}")
    print(f"Initial Web UI password: {password}")
    print("Keep this password out of chat/logs for real production installs.")


if __name__ == "__main__":
    main()
