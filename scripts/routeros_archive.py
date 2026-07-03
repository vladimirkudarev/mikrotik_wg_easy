#!/usr/bin/env python3
import argparse
import io
import json
import tarfile
from pathlib import Path


def add_bytes(tar, name, data, mode=0o644):
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = mode
    tar.addfile(info, io.BytesIO(data))


def add_dir(tar, name):
    info = tarfile.TarInfo(name.rstrip("/") + "/")
    info.type = tarfile.DIRTYPE
    info.mode = 0o755
    tar.addfile(info)


def convert(input_archive, output_archive, repo_tag):
    with tarfile.open(input_archive, "r:*") as src:
        manifest = json.load(src.extractfile("manifest.json"))
        if len(manifest) != 1:
            raise SystemExit("expected exactly one image in manifest.json")
        image = manifest[0]
        config_path = image["Config"]
        config_name = config_path.split("/")[-1] + ".json"
        config_data = src.extractfile(config_path).read()

        layers = []
        layer_payloads = []
        for index, layer_path in enumerate(image["Layers"]):
            digest = layer_path.split("/")[-1]
            layer_id = f"{index:03d}-{digest}"
            layer_name = f"{layer_id}/layer.tar"
            layers.append(layer_name)
            layer_payloads.append((layer_id, src.extractfile(layer_path).read()))

    legacy_manifest = [
        {
            "Config": config_name,
            "RepoTags": [repo_tag],
            "Layers": layers,
        }
    ]
    repositories = {repo_tag.split(":", 1)[0]: {repo_tag.split(":", 1)[1]: layers[-1].split("/", 1)[0]}}

    with tarfile.open(output_archive, "w") as dst:
        add_bytes(dst, "manifest.json", json.dumps(legacy_manifest).encode())
        add_bytes(dst, "repositories", json.dumps(repositories).encode())
        add_bytes(dst, config_name, config_data)
        for layer_id, payload in layer_payloads:
            add_dir(dst, layer_id)
            add_bytes(dst, f"{layer_id}/VERSION", b"1.0")
            add_bytes(dst, f"{layer_id}/json", json.dumps({"id": layer_id}).encode())
            # RouterOS rejects OCI blob paths. It accepts Docker save style layer paths.
            # Keep the original compressed layer payload to avoid archives too large for
            # small MikroTik storage.
            add_bytes(dst, f"{layer_id}/layer.tar", payload)


def main():
    parser = argparse.ArgumentParser(description="Convert BuildKit OCI-ish archive to RouterOS-friendly Docker archive.")
    parser.add_argument("input_archive")
    parser.add_argument("output_archive")
    parser.add_argument("--repo-tag", default="mikrotik-wg-easy:latest")
    args = parser.parse_args()
    convert(Path(args.input_archive), Path(args.output_archive), args.repo_tag)


if __name__ == "__main__":
    main()
