"""Read-only ext4 project-quota discovery; never verifies enforcement."""
import json
import os
import re
import subprocess
import sys

DOCKER_FORMAT = '{"Driver":{{json .Driver}},"DockerRootDir":{{json .DockerRootDir}}}'


def safe_path(value):
    """Conservative POSIX path syntax, not a filesystem/symlink attestation."""
    return (isinstance(value, str) and 0 < len(value) <= 4096
            and (value == "/" or (re.fullmatch(r"/[a-zA-Z0-9_.+/-]+", value) is not None
                 and all(part not in ("", ".", "..") for part in value.split("/")[1:]))))


def json_object(text):
    """Reject duplicate keys and return no raw diagnostic on invalid JSON."""
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate key")
            value[key] = item
        return value
    try:
        value = json.loads(text, object_pairs_hook=unique)
    except (ValueError, RecursionError):
        return None
    return value if isinstance(value, dict) else None


def inspect(*, runner=subprocess.run):
    """Return only whitelisted discovery data. runner is injectable for tests."""
    report = {"status": "incomplete", "errors": [],
              "driver": None, "docker_root_dir": None,
              "filesystem": None, "device": None, "mountpoint": None,
              "features": {"project": None, "quota": None},
              "prjquota_visible": None, "enforcement_verified": False}
    if sys.platform != "linux":
        report["errors"].append("unsupported_platform")
        return report
    env = dict(os.environ, LC_ALL="C")

    def run(argv):
        stage = argv[0]
        try:
            result = runner(argv, capture_output=True, text=True, encoding="utf-8",
                            errors="replace", timeout=10, env=env, shell=False,
                            check=False)
        except subprocess.TimeoutExpired:
            report["errors"].append(stage + "_timeout")
            return None
        except OSError:
            report["errors"].append(stage + "_unavailable")
            return None
        if type(result.returncode) is not int:
            report["errors"].append(stage + "_invalid_output")
            return None
        if result.returncode != 0:
            report["errors"].append(stage + "_failed")
            return None
        if not isinstance(result.stdout, str) or len(result.stdout) > 1048576:
            report["errors"].append(stage + "_invalid_output")
            return None
        return result.stdout

    text = run(["docker", "info", "--format", DOCKER_FORMAT])
    if text is None:
        return report
    docker = json_object(text)
    if (docker is None or not isinstance(docker.get("Driver"), str)
            or not re.fullmatch(r"[a-zA-Z0-9_.+-]{1,64}", docker["Driver"])
            or not safe_path(docker.get("DockerRootDir"))):
        report["errors"].append("docker_invalid_metadata")
        return report
    report["driver"] = docker["Driver"]
    report["docker_root_dir"] = docker["DockerRootDir"]
    text = run(["findmnt", "--json", "--target", docker["DockerRootDir"],
                "--output", "SOURCE,FSTYPE,OPTIONS,TARGET"])
    if text is None:
        return report
    mounts = json_object(text)
    filesystems = mounts.get("filesystems") if mounts is not None else None
    if (not isinstance(filesystems, list) or len(filesystems) != 1
            or not isinstance(filesystems[0], dict)):
        report["errors"].append("findmnt_invalid_metadata")
        return report
    mount = filesystems[0]
    fstype, target, options = (mount.get(key) for key in ("fstype", "target", "options"))
    if (not isinstance(fstype, str) or not re.fullmatch(r"[a-zA-Z0-9_.+-]{1,64}", fstype)
            or not safe_path(target)
            or not (target == "/" or docker["DockerRootDir"] == target
                    or docker["DockerRootDir"].startswith(target + "/"))
            or not isinstance(options, str) or not 0 < len(options) <= 65536
            or any(ord(char) < 33 or ord(char) > 126 for char in options)
            or any(not option for option in options.split(","))
            or mount.get("children") not in (None, [])):
        report["errors"].append("findmnt_invalid_metadata")
        return report
    report.update(filesystem=fstype, mountpoint=target,
                  prjquota_visible="prjquota" in options.split(","))
    if fstype != "ext4":
        report["errors"].append("unsupported_filesystem")
        return report
    source = mount.get("source")
    if (not safe_path(source) or not source.startswith("/dev/")
            or source == "/dev/"):
        report["errors"].append("unsafe_device")
        return report
    report["device"] = source
    text = run(["tune2fs", "-l", source])
    if text is None:
        return report
    lines = [line.split(":", 1)[1].split() for line in text.splitlines()
             if line.startswith("Filesystem features:")]
    if (len(lines) != 1 or not lines[0]
            or any(not re.fullmatch(r"[a-zA-Z0-9_]+", item) for item in lines[0])):
        report["errors"].append("tune2fs_invalid_features")
        return report
    features = lines[0]
    report["features"] = {name: name in features for name in ("project", "quota")}
    report["status"] = "complete"
    return report


def main(argv=None):
    """No CLI flags, device overrides, fixture mode, or mutating operations."""
    args = sys.argv[1:] if argv is None else argv
    if args:
        report = {"status": "incomplete", "errors": ["invalid_arguments"],
                  "enforcement_verified": False}
    else:
        report = inspect()
    print(json.dumps(report, ensure_ascii=True, sort_keys=True))
    return 0 if report["status"] == "complete" else 2


if __name__ == "__main__":
    raise SystemExit(main())
