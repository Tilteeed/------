"""Validate normalized Compose JSON without installing a YAML parser.

Docker Compose performs YAML parsing/interpolation. Its output can contain secrets:
keep it in memory, never print it or forward raw diagnostics.
"""
import argparse
import json
import math
import subprocess
from pathlib import Path

DEFAULT_IMAGE = 'openclaw-stage2:7c12438929e5'
PROJECT = 'personal-agent-stage2'
MOUNTS = {
    '/home/node/.openclaw': 'state',
    '/home/node/.openclaw/workspace': 'workspace',
    '/home/node/.config/openclaw': 'auth_secrets',
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def positive(value: object) -> bool:
    if isinstance(value, str) and value.isdecimal():
        value = int(value)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    return math.isfinite(value) and value > 0


def validate_spec(spec, expected_image=DEFAULT_IMAGE):
    require(isinstance(spec, dict), 'Compose root must be an object')
    require(spec.get('name', PROJECT) == PROJECT, 'Unexpected Compose project name')
    services = spec.get('services')
    require(isinstance(services, dict) and set(services) == {'gateway', 'cli'}, 'Unexpected service set')
    tokens = []
    for name in ('gateway', 'cli'):
        service = services[name]
        require(isinstance(service, dict), 'Service must be an object')
        require(service.get('image') == expected_image, 'Unexpected image')
        require(not service.get('privileged') and not service.get('cap_add'), 'Elevated privileges forbidden')
        require(not service.get('pid') and not service.get('ipc') and not service.get('devices'), 'Extra namespaces/devices forbidden')
        require(not service.get('build') and not service.get('volumes_from'), 'Unexpected build or inherited mounts')
        dropped = service.get('cap_drop', [])
        require(isinstance(dropped, list) and {'NET_ADMIN', 'NET_RAW'} <= set(dropped), 'Required capability drops missing')
        options = service.get('security_opt', [])
        require(isinstance(options, list) and any(x in options for x in ('no-new-privileges:true', 'no-new-privileges=true')), 'no-new-privileges missing')
        mounts = service.get('volumes')
        require(isinstance(mounts, list) and len(mounts) == len(MOUNTS), 'Unexpected mounts')
        seen = set()
        for mount in mounts:
            require(isinstance(mount, dict), 'Normalized volume object required')
            target = mount.get('target')
            require(isinstance(target, str) and target in MOUNTS and target not in seen, 'Unexpected/duplicate mount target')
            require(mount.get('type') == 'volume' and mount.get('source') == MOUNTS[target], 'Only dedicated named volumes allowed')
            require(not mount.get('read_only'), 'Stage 2 state must be writable')
            seen.add(target)
        env = service.get('environment')
        require(isinstance(env, dict), 'Normalized environment required')
        token = env.get('OPENCLAW_GATEWAY_TOKEN')
        require(isinstance(token, str) and bool(token.strip()), 'Gateway token missing')
        tokens.append(token)
        require(env.get('OPENCLAW_STATE_DIR') == '/home/node/.openclaw', 'Unexpected state path')
        require(env.get('OPENCLAW_CONFIG_PATH') == '/home/node/.openclaw/openclaw.json', 'Unexpected config path')
        require(env.get('OPENCLAW_WORKSPACE_DIR') == '/home/node/.openclaw/workspace', 'Unexpected workspace path')
        if name == 'gateway':
            require(not service.get('network_mode') and service.get('entrypoint') is None, 'Gateway must retain image entrypoint and isolated network')
        else:
            require(service.get('network_mode') == 'service:gateway' and not service.get('ports'), 'CLI must share Gateway network without published ports')
            require(service.get('entrypoint') == ['node', 'dist/index.js'], 'Unexpected CLI entrypoint')
    require(tokens[0] == tokens[1], 'Gateway and CLI credentials differ')
    gateway = services['gateway']
    require(gateway.get('command') == ['node', 'dist/index.js', 'gateway', '--bind', 'lan', '--port', '18789'], 'Unexpected Gateway command')
    ports = gateway.get('ports')
    require(isinstance(ports, list) and len(ports) == 1 and isinstance(ports[0], dict), 'Exactly one normalized Gateway port required')
    port = ports[0]
    require(port.get('host_ip') == '127.0.0.1' and port.get('target') == 18789 and port.get('protocol', 'tcp') == 'tcp', 'Only loopback TCP publication allowed')
    published = str(port.get('published', ''))
    require(published.isdecimal() and 1 <= int(published) <= 65535, 'Invalid published port')
    for key in ('mem_limit', 'cpus', 'pids_limit'):
        require(positive(gateway.get(key)), 'Gateway resource limit missing or invalid')
    health = gateway.get('healthcheck')
    require(isinstance(health, dict) and not health.get('disable') and health.get('test') == ['CMD', 'node', 'dist/docker-healthcheck.js'], 'Gateway healthcheck missing or changed')
    volumes = spec.get('volumes')
    require(isinstance(volumes, dict) and set(volumes) == set(MOUNTS.values()), 'Unexpected volume definitions')
    for name, volume in volumes.items():
        require(isinstance(volume, dict), 'Normalized volume definition required')
        require(not volume.get('external') and not volume.get('driver_opts') and volume.get('driver', 'local') == 'local', 'External or redirected storage forbidden')
        require(volume.get('name', f'{PROJECT}_{name}') == f'{PROJECT}_{name}', 'Foreign volume name forbidden')
    networks = spec.get('networks', {})
    require(isinstance(networks, dict) and set(networks) <= {'default'}, 'Unexpected networks')
    for network in networks.values():
        require(isinstance(network, dict) and not network.get('external') and not network.get('driver_opts') and network.get('driver', 'bridge') == 'bridge', 'External or host networks forbidden')
        require(network.get('name', f'{PROJECT}_default') == f'{PROJECT}_default', 'Foreign network name forbidden')
    require(set(gateway.get('networks', {})) <= {'default'}, 'Unexpected Gateway network attachment')


def render_config(directory, *, env=None, env_file=None):
    directory = Path(directory).resolve()
    command = ['docker', 'compose', '--project-directory', str(directory)]
    if env_file is not None:
        command += ['--env-file', str(env_file)]
    command += ['-f', str(directory / 'compose.yaml'), '--profile', 'manual', 'config', '--format', 'json']
    try:
        result = subprocess.run(command, env=env, capture_output=True, text=True, encoding='utf-8', timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError('Docker Compose unavailable or timed out; no configuration output disclosed') from None
    if result.returncode:
        raise ValueError('Docker Compose rendering failed; raw output suppressed because it may contain secrets')
    try:
        return json.loads(result.stdout)
    except ValueError:
        raise ValueError('Docker Compose did not return valid JSON; raw output suppressed') from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-image', default=DEFAULT_IMAGE)
    options = parser.parse_args()
    try:
        validate_spec(render_config(Path(__file__).resolve().parent), options.expected_image)
    except (ValueError, TypeError, KeyError) as error:
        # All validation messages are fixed text, not values taken from configuration.
        parser.exit(1, f'Stage 2 validation failed: {error}\n')
    print('Stage 2 Compose structure validated; secrets were not printed. No containers started.')


if __name__ == '__main__':
    main()
