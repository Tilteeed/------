"""Pure policies. Validation is neither authentication nor a Docker operation."""
from dataclasses import dataclass
import math
import re


@dataclass(frozen=True, slots=True)
class CreateRequest:
    idempotency_key: str
    settings_revision: int


def validate_create(payload) -> CreateRequest:
    if not isinstance(payload, dict) or set(payload) != {'action', 'idempotency_key', 'settings_revision'}:
        raise ValueError('Only create request fields are accepted')
    if payload['action'] != 'create':
        raise ValueError('Create action required')
    key, revision = payload['idempotency_key'], payload['settings_revision']
    if not isinstance(key, str) or re.fullmatch(r'[A-Za-z0-9_-]{1,128}', key) is None:
        raise ValueError('Invalid idempotency key')
    if type(revision) is not int or not 0 <= revision <= 2**63 - 1:
        raise ValueError('Revision must be a bounded non-negative integer')
    return CreateRequest(key, revision)


@dataclass(frozen=True, slots=True)
class Admission:
    allowed: bool
    reasons: tuple[str, ...]
    would_deny: tuple[str, ...]


def evaluate_admission(*, mode, now, sampled_at, cpu_window_seconds,
                       total_ram_bytes, available_ram_bytes, cpu_percent,
                       requested_ram_bytes, free_disk_bytes, requested_disk_bytes,
                       disk_floor_bytes, disk_quota_verified) -> Admission:
    """Pure decision only; requires trusted observations and separate atomic budgets."""
    if not isinstance(mode, str) or mode not in {'lab', 'final'}:
        raise ValueError('Unknown server policy mode')
    for value in (total_ram_bytes, requested_ram_bytes, requested_disk_bytes):
        if type(value) is not int or not 0 < value <= 2**63 - 1:
            raise ValueError('Positive bounded integer resource amount required')
    for value in (available_ram_bytes, free_disk_bytes, disk_floor_bytes):
        if type(value) is not int or not 0 <= value <= 2**63 - 1:
            raise ValueError('Non-negative bounded integer resource amount required')
    if available_ram_bytes > total_ram_bytes:
        raise ValueError('Available RAM exceeds total RAM')
    for value in (now, sampled_at, cpu_window_seconds, cpu_percent):
        if type(value) not in (int, float):
            raise ValueError('Finite non-negative metric required')
        try:
            valid = math.isfinite(value) and value >= 0
        except OverflowError:
            valid = False
        if not valid:
            raise ValueError('Finite non-negative metric required')
    if cpu_percent > 100 or type(disk_quota_verified) is not bool:
        raise ValueError('Invalid CPU measurement or quota evidence flag')
    thresholds = []
    if (total_ram_bytes - available_ram_bytes) * 2 >= total_ram_bytes:
        thresholds.append('memory_threshold')
    if cpu_percent >= 50:
        thresholds.append('cpu_threshold')
    reasons = list(thresholds) if mode == 'final' else []
    if sampled_at > now:
        reasons.append('future_metrics')
    elif now - sampled_at > 10:
        reasons.append('stale_metrics')
    if cpu_window_seconds < 60:
        reasons.append('cpu_window_incomplete')
    if available_ram_bytes < requested_ram_bytes:
        reasons.append('insufficient_ram')
    if free_disk_bytes < requested_disk_bytes + disk_floor_bytes:
        reasons.append('insufficient_disk')
    if not disk_quota_verified:
        reasons.append('disk_quota_unverified')
    return Admission(not reasons, tuple(reasons), tuple(thresholds) if mode == 'lab' else ())
