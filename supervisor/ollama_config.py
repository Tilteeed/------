"""Trusted native Ollama provider configuration for pinned OpenClaw.

This is administrative site configuration, never a browser/user setting. The
network route is separately enforced by the host firewall; this module only
validates and serializes the provider policy.
"""
from dataclasses import dataclass
import ipaddress
from urllib.parse import urlsplit


MODEL_NAMES = {
    'qwen3.5:9b': 'Qwen3.5 9B',
    'hf.co/DavidAU/Qwen3.5-9B-The-Defiant-Fable-Uncensored-Heretic-NEO-IMATRIX-MAX-MTP-GGUF:Q4_K_M':
        'Qwen3.5 The Defiant Fable Uncensored',
}
OLLAMA_PORT = 11434
OLLAMA_API_KEY_MARKER = 'ollama-local'
_MAX_URL_LENGTH = 300
_SUPPORTED_CONTEXT_TOKENS = frozenset({8192, 16384})
_RFC1918 = tuple(ipaddress.IPv4Network(value) for value in (
    '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))


@dataclass(frozen=True, slots=True)
class OllamaConfig:
    base_url: str
    default_model_id: str
    context_tokens: int
    max_tokens: int
    think: bool


def validate_ollama_config(value) -> OllamaConfig:
    """Validate the closed, trusted host policy for one shared Ollama service."""
    required = {'base_url', 'default_model_id', 'context_tokens', 'max_tokens', 'think'}
    if type(value) is not dict or set(value) != required:
        raise ValueError('Invalid Ollama configuration fields')

    base_url = value['base_url']
    if type(base_url) is not str or not 1 <= len(base_url) <= _MAX_URL_LENGTH:
        raise ValueError('Invalid Ollama API address')
    try:
        parsed = urlsplit(base_url)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        raise ValueError('Invalid Ollama API address') from None
    if (parsed.scheme != 'http' or not hostname or parsed.username is not None
            or parsed.password is not None or parsed.path or parsed.query or parsed.fragment
            or port != OLLAMA_PORT or parsed.netloc != f'{hostname}:{OLLAMA_PORT}'):
        raise ValueError('Invalid Ollama API address')
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        raise ValueError('Ollama API address must be an explicit private IPv4 address') from None
    if (address.version != 4 or not any(address in network for network in _RFC1918)
            or address.is_loopback or address.is_link_local or address.is_multicast
            or address.is_unspecified or str(address) != hostname):
        raise ValueError('Ollama API address must be an explicit private IPv4 address')

    model_id = value['default_model_id']
    if type(model_id) is not str or model_id not in MODEL_NAMES:
        raise ValueError('Unsupported Ollama model')
    context_tokens, max_tokens = value['context_tokens'], value['max_tokens']
    if (type(context_tokens) is not int or context_tokens not in _SUPPORTED_CONTEXT_TOKENS
            or type(max_tokens) is not int or not 1 <= max_tokens <= context_tokens):
        raise ValueError('Invalid Ollama context or generation limit')
    if type(value['think']) is not bool:
        raise ValueError('Invalid Ollama think setting')
    return OllamaConfig(base_url, model_id, context_tokens, max_tokens, value['think'])


def build_openclaw_ollama_config(value):
    """Build the pinned OpenClaw native provider config from trusted site policy."""
    config = validate_ollama_config(value)
    models = [{
        'id': config.default_model_id,
        'name': MODEL_NAMES[config.default_model_id],
        'contextWindow': config.context_tokens,
        'maxTokens': config.max_tokens,
        'params': {
            'num_ctx': config.context_tokens,
            'think': config.think,
        },
    }]
    return {
        'models': {
            'providers': {
                'ollama': {
                    'baseUrl': config.base_url,
                    'apiKey': OLLAMA_API_KEY_MARKER,
                    'api': 'ollama',
                    'models': models,
                },
            },
        },
        'agents': {
            'defaults': {
                'model': {'primary': 'ollama/' + config.default_model_id},
            },
        },
    }
