import shutil
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from publish_geodata import checksum, publish
from subscription_proxy import GEODATA_FIELDS, geodata_version


class PublishGeodataTest(unittest.TestCase):
    def test_switches_only_after_a_complete_changed_copy(self):
        with TemporaryDirectory() as temporary:
            source = Path(temporary) / "source"
            target = Path(temporary) / "target"
            source.mkdir()
            target.mkdir()
            for name in GEODATA_FIELDS:
                (source / name).write_bytes(name.encode())

            def hashes(_container):
                return [
                    field for name in GEODATA_FIELDS
                    for field in (checksum(source / name), f"/app/bin/{name}")
                ]

            def copy(args, *, check):
                name = args[-2].rsplit("/", 1)[-1]
                shutil.copyfile(source / name, args[-1])

            with patch("publish_geodata.docker_hashes", side_effect=hashes):
                with patch("publish_geodata.subprocess.run", side_effect=copy):
                    version = publish("test", target)
                    self.assertEqual(geodata_version(target), version)
                    self.assertEqual(publish("test", target), version)

                    (source / "geoip.dat").write_bytes(b"")
                    with self.assertRaisesRegex(RuntimeError, "is empty"):
                        publish("test", target)
                    self.assertEqual(geodata_version(target), version)

                    (source / "geoip.dat").write_bytes(b"updated")
                    latest = publish("test", target)
                    self.assertGreater(latest, version)
                    self.assertEqual(geodata_version(target), latest)
                    self.assertEqual((target / str(latest) / "geoip.dat").read_bytes(), b"updated")
                    self.assertEqual((target / str(version) / "geoip.dat").read_bytes(), b"geoip.dat")
