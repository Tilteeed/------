"""Synthetic profiles only: no Docker, host inspection, mount or quota changes."""
from dataclasses import FrozenInstanceError
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


def valid_profile():
    """Deliberately synthetic site identity and limits, not a deployment default."""
    return {
        'schema_version': 1,
        'profile_version': 'unit-site-v1',
        'mode': 'final',
        'storage': {
            'backend': 'xfs_project_quota',
            'mountpoint': '/mnt/unit-agent-data',
            'expected_uuid': '11111111-2222-4333-8444-555555555555',
        },
        'agent_limits': {
            'ram_bytes': 2048,
            'cpu_millicores': 1000,
            'pids_limit': 256,
            'disk_bytes': 100 * 1024**2,
        },
    }


class ProfileTests(unittest.TestCase):
    def test_explicit_site_profile_becomes_immutable_snapshot(self):
        from supervisor.config import validate_profile
        data = valid_profile()
        profile = validate_profile(data)
        self.assertEqual(profile.schema_version, 1)
        self.assertEqual(profile.profile_version, 'unit-site-v1')
        self.assertEqual(profile.mode, 'final')
        self.assertEqual(profile.storage.mountpoint, '/mnt/unit-agent-data')
        self.assertEqual(profile.storage.expected_uuid, data['storage']['expected_uuid'])
        self.assertEqual(profile.agent_limits.cpu_millicores, 1000)
        self.assertEqual(profile.agent_limits.disk_bytes, 100 * 1024**2)
        data['storage']['mountpoint'] = '/mnt/changed'
        self.assertEqual(profile.storage.mountpoint, '/mnt/unit-agent-data')
        with self.assertRaises(FrozenInstanceError):
            setattr(profile, 'mode', 'lab')
        with self.assertRaises(FrozenInstanceError):
            setattr(profile.storage, 'mountpoint', '/mnt/changed')
        with self.assertRaises(FrozenInstanceError):
            setattr(profile.agent_limits, 'ram_bytes', 1)

    def test_closed_schema_rejects_missing_unknown_or_non_object_sections(self):
        from supervisor.config import validate_profile
        for extra in ('threshold_percent', 'disk_quota_verified', 'image', 'owner_id'):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                validate_profile(valid_profile() | {extra: 99})
        for section in (None, 'storage', 'agent_limits'):
            source = valid_profile() if section is None else valid_profile()[section]
            for key in source:
                data = valid_profile()
                target = data if section is None else data[section]
                del target[key]
                with self.subTest(section=section, missing=key), self.assertRaises(ValueError):
                    validate_profile(data)
            for replacement in (None, [], 'invalid', True, source | {'extra': 1}):
                data = valid_profile()
                if section is None:
                    data = replacement
                else:
                    data[section] = replacement
                with self.subTest(section=section, replacement=replacement), self.assertRaises(ValueError):
                    validate_profile(data)

    def test_limits_are_explicit_positive_int64_without_coercion(self):
        from supervisor.config import validate_profile
        invalid = (None, True, False, 0, -1, 1.0, '1024', 2**63, float('nan'), float('inf'))
        for field in valid_profile()['agent_limits']:
            for value in invalid:
                data = valid_profile()
                data['agent_limits'][field] = value
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    validate_profile(data)
            for value in (1, 2**63 - 1):
                data = valid_profile()
                data['agent_limits'][field] = value
                self.assertEqual(getattr(validate_profile(data).agent_limits, field), value)

    def test_only_known_versioned_server_profile_is_accepted(self):
        from supervisor.config import validate_profile
        invalid = {
            'schema_version': (None, True, '1', 1.0, 0, 2),
            'profile_version': (None, '', 'a b', 'a\n', '../x', 'x' * 65, 1),
            'mode': (None, True, [], 'FINAL', 'unknown'),
        }
        for field, values in invalid.items():
            for value in values:
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    validate_profile(valid_profile() | {field: value})
        for mode in ('lab', 'final'):
            self.assertEqual(validate_profile(valid_profile() | {'mode': mode}).mode, mode)

    def test_storage_requires_explicit_canonical_identity_without_repair(self):
        from supervisor.config import validate_profile
        uuid = valid_profile()['storage']['expected_uuid']
        invalid = {
            'backend': (None, [], 'ext4', 'auto', 'XFS', 'xfs_project_quota\n'),
            'mountpoint': (None, '', '/', '//srv/data', 'relative', 'C:/data',
                           '/srv/../data', '/srv/./data', '/srv//data', '/srv/data/',
                           '/srv/data\n', '/srv/a b', '/srv/\x00data', '/srv/' + 'x' * 4096),
            'expected_uuid': (None, '', True, uuid.replace('-', ''), '{' + uuid + '}',
                              uuid + '\n', 'not-a-uuid', uuid[:-1] + 'g'),
        }
        for field, values in invalid.items():
            for value in values:
                data = valid_profile()
                data['storage'][field] = value
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    validate_profile(data)
        data = valid_profile()
        data['storage'].update(mountpoint='/data/agent-state_1',
                               expected_uuid='AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE')
        storage = validate_profile(data).storage
        self.assertEqual(storage.expected_uuid, data['storage']['expected_uuid'])
        self.assertEqual(storage.mountpoint, data['storage']['mountpoint'])


class ProfileFileTests(unittest.TestCase):
    def test_load_file_is_read_only_and_returns_validated_profile(self):
        from supervisor.config import load_profile, validate_profile
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'site.json'
            original = json.dumps(valid_profile()).encode('utf-8')
            path.write_bytes(original)
            self.assertEqual(load_profile(path), validate_profile(valid_profile()))
            self.assertEqual(path.read_bytes(), original)
            self.assertEqual(sorted(p.name for p in Path(directory).iterdir()), ['site.json'])

    def test_json_is_utf8_unambiguous_and_finite(self):
        from supervisor.config import load_profile
        encoded = json.dumps(valid_profile()).encode('utf-8')
        invalid = [
            encoded.replace(b'"mode": "final"', b'"mode": "lab", "mode": "final"'),
            encoded.replace(b'"mountpoint":', b'"mountpoint": "/bad", "mountpoint":'),
            encoded.replace(b'"ram_bytes":', b'"ram_bytes": 1, "ram_bytes":'),
            encoded.decode('utf-8').encode('utf-16'), b'\xff', b'', b'{',
            encoded + b' {}', b'[' * 1200 + b']' * 1200,
        ]
        for number in (b'NaN', b'Infinity', b'-Infinity', b'1e309'):
            invalid.append(encoded.replace(b'2048', number))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'site.json'
            for number, blob in enumerate(invalid):
                path.write_bytes(blob)
                with self.subTest(case=number), self.assertRaises(ValueError):
                    load_profile(path)

    def test_profile_size_limit_is_checked_before_json_parsing(self):
        from supervisor.config import load_profile
        blob = json.dumps(valid_profile()).encode('utf-8')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'site.json'
            path.write_bytes(blob + b' ' * (65536 - len(blob)))
            self.assertEqual(load_profile(path).mode, 'final')
            with path.open('ab') as stream:
                stream.write(b' ')
            with self.assertRaises(ValueError):
                load_profile(path)


class ProfileCliTests(unittest.TestCase):
    def test_cli_distinguishes_valid_config_from_runtime_readiness(self):
        root = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'PRIVATE_SITE_FILENAME.json'
            command = [sys.executable, '-X', 'utf8', '-m', 'supervisor.config', '--check', str(path)]
            path.write_text(json.dumps(valid_profile()), encoding='utf-8')
            result = subprocess.run(command, cwd=root, capture_output=True, text=True,
                                    encoding='utf-8', timeout=10, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(),
                             'Deployment profile valid; storage and runtime are NOT verified.')
            self.assertEqual(result.stderr, '')
            for blob in (b'{}', b'{PRIVATE_CONFIG_CONTENT', None):
                if blob is None:
                    path.unlink()
                else:
                    path.write_bytes(blob)
                result = subprocess.run(command, cwd=root, capture_output=True, text=True,
                                        encoding='utf-8', timeout=10, check=False)
                with self.subTest(blob=blob):
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(result.stdout, '')
                    self.assertNotIn('PRIVATE_SITE_FILENAME', result.stderr)
                    self.assertNotIn('PRIVATE_CONFIG_CONTENT', result.stderr)
                    self.assertNotIn('Traceback', result.stderr)
            result = subprocess.run(command[:-1] + [directory], cwd=root,
                                    capture_output=True, text=True, encoding='utf-8',
                                    timeout=10, check=False)
            self.assertEqual(result.returncode, 2)


class ProfileExampleTests(unittest.TestCase):
    def test_example_cannot_validate_until_all_site_values_are_explicit(self):
        from supervisor.config import load_profile, validate_profile
        root = Path(__file__).resolve().parents[2]
        template_path = root / 'supervisor/deployment.example.json'
        template = json.loads(template_path.read_text(encoding='utf-8'))
        required = (('storage', 'mountpoint'), ('storage', 'expected_uuid'),
                    ('agent_limits', 'disk_bytes'))
        for section, field in required:
            self.assertIsNone(template[section][field])
        with self.assertRaises(ValueError):
            load_profile(template_path)
        for missing_section, missing_field in required:
            data = json.loads(json.dumps(template))
            for section, field in required:
                if (section, field) != (missing_section, missing_field):
                    data[section][field] = valid_profile()[section][field]
            with self.subTest(missing=missing_field), self.assertRaises(ValueError):
                validate_profile(data)
        for section, field in required:
            template[section][field] = valid_profile()[section][field]
        self.assertEqual(validate_profile(template).storage.expected_uuid,
                         valid_profile()['storage']['expected_uuid'])


if __name__ == '__main__':
    unittest.main()
