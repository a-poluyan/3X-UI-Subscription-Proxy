"""Build immutable GeoSite/GeoIP subsets from published Xray data."""

import hashlib
import json
import re
import threading
import time
from functools import lru_cache
from pathlib import Path
from tempfile import TemporaryDirectory


GEODATA_FIELDS = {"geosite.dat": "Geositeurl", "geoip.dat": "Geoipurl"}
SET_ID = re.compile(r"[0-9a-f]{64}")
TAG = re.compile(r"[A-Za-z0-9_.-]+")
revision_lock = threading.Lock()


def references(document):
    tags = {name: set() for name in GEODATA_FIELDS}
    items = [document]
    while items:
        item = items.pop()
        if isinstance(item, dict):
            items.extend(item)
            items.extend(item.values())
        elif isinstance(item, list):
            items.extend(item)
        elif isinstance(item, str):
            kind, _, code = item.partition(":")
            kind = kind.lower()
            if kind in {"ext", "ext-ip"}:
                filename, _, code = code.partition(":")
                if filename not in GEODATA_FIELDS or (kind == "ext-ip" and filename != "geoip.dat"):
                    raise ValueError("External geodata file")
            elif kind in {"geosite", "geoip"}:
                filename = kind + ".dat"
            else:
                continue
            code = code.lstrip("!") if filename == "geoip.dat" else code.split("@", 1)[0]
            if not TAG.fullmatch(code):
                raise ValueError("Invalid geodata category")
            tags[filename].add(code.upper())
    return tags


def varint(data, offset):
    value = 0
    for shift in range(0, 70, 7):
        if offset == len(data):
            break
        byte = data[offset]
        offset += 1
        value |= (byte & 127) << shift
        if byte < 128:
            return value, offset
    raise ValueError("Invalid geodata varint")


def length_delimited(tag, data):
    length = len(data)
    prefix = bytearray([tag])
    while length >= 128:
        prefix.append((length & 127) | 128)
        length >>= 7
    prefix.append(length)
    return bytes(prefix) + data


@lru_cache(maxsize=4)
def section_index(path):
    # Both Xray lists encode each section as field 1, with the section code in its field 1.
    data = path.read_bytes()
    ranges = {}
    offset = 0
    while offset < len(data):
        start = offset
        field, offset = varint(data, offset)
        length, offset = varint(data, offset)
        end = offset + length
        if field != 10 or offset >= end or end > len(data):
            raise ValueError("Invalid geodata section")
        field, cursor = varint(data, offset)
        size, cursor = varint(data, cursor)
        if field != 10 or not size or cursor + size > end:
            raise ValueError("Invalid geodata section code")
        name = data[cursor:cursor + size].decode("ascii").upper()
        if name in ranges:
            raise ValueError("Duplicate geodata section")
        ranges[name] = (start, end - start)
        offset = end
    return ranges


@lru_cache(maxsize=32)
def publish_set(sets, source, categories):
    parts = {}
    digest = hashlib.sha256()
    for name, tags in zip(GEODATA_FIELDS, categories):
        path = source / name
        index = section_index(path)
        with path.open("rb") as file:
            frames = []
            for offset, length in sorted(index[tag] for tag in tags):
                file.seek(offset)
                frame = file.read(length)
                if len(frame) != length:
                    raise ValueError("Truncated geodata source")
                frames.append(frame)
        data = b"".join(frames)
        if len(data) <= 1024:
            length, start = varint(data, 1)
            end = start + length
            # Pad inside the first entry using an unknown protobuf field.
            padding_size = max(0, 1023 - len(data))
            if length < 128 and padding_size >= 128:
                padding_size -= 1  # The entry's length prefix also grows.
            padding = length_delimited(0x7A, bytes(padding_size))
            data = length_delimited(0x0A, data[start:end] + padding) + data[end:]
        parts[name] = data
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)

    identifier = digest.hexdigest()
    destination = sets / identifier
    if not destination.is_dir():
        with TemporaryDirectory(prefix=".building-", dir=sets) as temporary:
            staging = Path(temporary) / "pair"
            staging.mkdir()
            for name, data in parts.items():
                (staging / name).write_bytes(data)
            try:
                staging.rename(destination)
            except OSError:
                if not destination.is_dir():
                    raise
    return identifier


def compatible_set(sets, source, profile, body):
    try:
        configs = json.loads(body)
        configs = configs if isinstance(configs, list) else [configs]
        if not configs or any(
            not isinstance(config, dict)
            or not isinstance(config.get("outbounds"), list)
            or not isinstance(config.get("routing"), dict)
            for config in configs
        ):
            return None
        from_profile = references(profile)
        from_json = references(configs)
        # Happ's UseChunkFiles can drop categories absent from the routing profile.
        if any(not tags or not from_json[name] <= tags for name, tags in from_profile.items()):
            return None
        categories = tuple(tuple(sorted(tags)) for tags in from_profile.values())
        return publish_set(sets, source, categories)
    except (KeyError, OSError, ValueError, RecursionError):
        return None


def selection_revision(sets, subscription_path, selection, baseline):
    # Keep only a hash of the subscription path. A return to an older set still advances the revision.
    key = hashlib.sha256(subscription_path.encode()).hexdigest()
    state = sets / (".revision-" + key)
    with revision_lock:
        try:
            old_set, old_timestamp = state.read_text(encoding="ascii").split()
            old_timestamp = int(old_timestamp)
        except FileNotFoundError:
            if selection.startswith("full:"):
                return baseline
            old_set, old_timestamp = "", 0
        if old_set == selection and old_timestamp >= baseline:
            return old_timestamp

        timestamp = max(baseline, old_timestamp)
        if old_set != selection:
            timestamp = max(timestamp, old_timestamp + 1, int(time.time()))
        with TemporaryDirectory(prefix=".revision-", dir=sets) as temporary:
            staged = Path(temporary) / "revision"
            staged.write_text(f"{selection} {timestamp}\n", encoding="ascii")
            staged.replace(state)
        return timestamp
