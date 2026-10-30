"""Trusted in-process create coordination, not an HTTP API or Docker executor.

Providers must return quick in-memory observations in one clock/units basis.
No host collector, quota setter or service authentication is implemented here.
"""
from dataclasses import asdict, dataclass
import hashlib
import json
from typing import Callable

from .config import DeploymentProfile, validate_profile
from .policy import Admission, evaluate_admission, validate_create
from .registry import Registry, ReservationCapacity


@dataclass(frozen=True, slots=True)
class ResourceObservation:
    """Trusted cache snapshot, never client input or automatic proof of quota.

    Disk totals/free space refer to the configured data pool. Capacity fields are
    total reservation ceilings after platform/model/retained-data budgeting, not
    residual amounts with existing instance reservations subtracted a second time.
    Physical totals provide upper bounds, not defaults for those reserved budgets.
    """
    sampled_at: float
    cpu_window_seconds: float
    total_ram_bytes: int
    available_ram_bytes: int
    cpu_percent: float
    free_disk_bytes: int
    disk_floor_bytes: int
    disk_quota_verified: bool
    capacity_ram_bytes: int
    capacity_cpu_millicores: int
    capacity_disk_bytes: int
    total_cpu_millicores: int
    total_disk_bytes: int


@dataclass(frozen=True, slots=True)
class CreateResult:
    operation_id: str
    instance_id: str
    status: str
    replayed: bool
    admission: Admission | None


class AdmissionDenied(Exception):
    def __init__(self, decision):
        self.decision = decision
        super().__init__('Create admission denied')


class SettingsRevisionConflict(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class CreateCoordinator:
    registry: Registry
    profile: DeploymentProfile
    observe: Callable[[], ResourceObservation]
    clock: Callable[[], float]

    def __post_init__(self):
        if (not isinstance(self.registry, Registry) or type(self.profile) is not DeploymentProfile
                or not callable(self.observe) or not callable(self.clock)):
            raise ValueError('Explicit trusted registry, profile, observation provider and clock required')
        # Dataclass annotations alone are not validation of manually constructed profiles.
        object.__setattr__(self, 'profile', validate_profile(asdict(self.profile)))

    def create(self, actor_id, payload, *, current_settings_revision) -> CreateResult:
        """Actor/current revision/providers belong to the trusted service, not JSON.

        The revision is a trusted snapshot, not a cross-database lock on DraftStore.
        An eventual executor must validate its exact settings/profile and admission
        again before side effects; a queued reservation is not a runtime permit.
        """
        request = validate_create(payload)
        limits = self.profile.agent_limits
        profile_fingerprint = hashlib.sha256(json.dumps(
            asdict(self.profile), sort_keys=True, separators=(',', ':'),
            ensure_ascii=True, allow_nan=False).encode('ascii')).hexdigest()
        decision = None

        def admit():
            nonlocal decision
            if (type(current_settings_revision) is not int
                    or not 0 <= current_settings_revision <= 2**63 - 1):
                raise ValueError('Trusted settings revision must be a bounded integer')
            if request.settings_revision != current_settings_revision:
                raise SettingsRevisionConflict('Draft revision changed before reservation')
            sample = self.observe()
            if type(sample) is not ResourceObservation:
                raise ValueError('Typed trusted resource observation required')
            decision = evaluate_admission(
                mode=self.profile.mode, now=self.clock(), sampled_at=sample.sampled_at,
                cpu_window_seconds=sample.cpu_window_seconds,
                total_ram_bytes=sample.total_ram_bytes,
                available_ram_bytes=sample.available_ram_bytes, cpu_percent=sample.cpu_percent,
                requested_ram_bytes=limits.ram_bytes, free_disk_bytes=sample.free_disk_bytes,
                requested_disk_bytes=limits.disk_bytes, disk_floor_bytes=sample.disk_floor_bytes,
                disk_quota_verified=sample.disk_quota_verified,
            )
            for value in (sample.total_cpu_millicores, sample.total_disk_bytes):
                if type(value) is not int or not 0 < value <= 2**63 - 1:
                    raise ValueError('Positive bounded physical resource totals required')
            for value in (sample.capacity_ram_bytes, sample.capacity_cpu_millicores,
                          sample.capacity_disk_bytes):
                if type(value) is not int or not 0 <= value <= 2**63 - 1:
                    raise ValueError('Non-negative bounded reservation ceilings required')
            if (sample.capacity_ram_bytes > sample.total_ram_bytes
                    or sample.capacity_cpu_millicores > sample.total_cpu_millicores
                    or sample.capacity_disk_bytes > sample.total_disk_bytes
                    or sample.free_disk_bytes > sample.total_disk_bytes):
                raise ValueError('Reservation ceiling or free space exceeds physical total')
            if not decision.allowed:
                raise AdmissionDenied(decision)
            # Registry CPU units for this coordinator are millicores, not whole cores.
            return ReservationCapacity(sample.capacity_ram_bytes, sample.capacity_cpu_millicores,
                                       sample.capacity_disk_bytes)

        operation = self.registry.reserve_create(
            actor_id, idempotency_key=request.idempotency_key,
            settings_revision=request.settings_revision, profile_version=self.profile.profile_version,
            ram_bytes=limits.ram_bytes, cpu_units=limits.cpu_millicores, disk_bytes=limits.disk_bytes,
            profile_fingerprint=profile_fingerprint, admit=admit,
        )
        return CreateResult(operation['id'], operation['instance_id'], operation['status'],
                            decision is None, decision)
