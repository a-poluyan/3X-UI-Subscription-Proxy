"""Publish the GeoSite and GeoIP databases from a running 3x-ui container."""

import argparse
import hashlib
import subprocess
import time
from pathlib import Path
from tempfile import TemporaryDirectory

from subscription_proxy import GEODATA_FIELDS, geodata_version


def docker_hashes(container):
    paths = [f"/app/bin/{name}" for name in GEODATA_FIELDS]
    result = subprocess.run(
        ["docker", "exec", container, "sha256sum", *paths],
        check=True, capture_output=True, text=True,
    )
    return result.stdout.split()


def checksum(file_path):
    with file_path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def publish(container, directory):
    expected = docker_hashes(container)
    current = geodata_version(directory)
    with TemporaryDirectory(dir=directory) as temporary:
        stage = Path(temporary)
        version = max(int(time.time()), current + 1)
        while (directory / str(version)).exists():
            version += 1
        files = stage / str(version)
        files.mkdir(mode=0o755)
        for name in GEODATA_FIELDS:
            subprocess.run(
                ["docker", "cp", f"{container}:/app/bin/{name}", str(files / name)],
                check=True,
            )

        actual = []
        for name in GEODATA_FIELDS:
            file_path = files / name
            if file_path.stat().st_size == 0:
                raise RuntimeError(f"{name} is empty")
            file_path.chmod(0o644)
            actual.extend((checksum(file_path), f"/app/bin/{name}"))
        if actual != expected or actual != docker_hashes(container):
            raise RuntimeError("Geo files changed during copying. Try again after the Xray update.")

        old_files = directory / str(current)
        if current and all(
            (old_files / name).is_file() and checksum(old_files / name) == checksum(files / name)
            for name in GEODATA_FIELDS
        ):
            print(f"Geo files unchanged ({current}).")
            return current

        files.rename(directory / str(version))
        marker = stage / "current"
        marker.write_text(f"{version}\n", encoding="ascii")
        marker.chmod(0o644)
        marker.replace(directory / "current")
        print(f"Published GeoSite and GeoIP ({version}).")
        return version


def main():
    import fcntl

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("container")
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    args.directory.mkdir(parents=True, exist_ok=True, mode=0o755)
    with (args.directory / ".publish.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        publish(args.container, args.directory)


if __name__ == "__main__":
    main()
