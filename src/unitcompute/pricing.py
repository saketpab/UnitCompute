"""Versioned price snapshot used for previews. This is an estimate, never a live quote."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal

from unitcompute.schemas import CostEstimate, CostLine


@dataclass(frozen=True)
class PriceSnapshot:
    version: str
    region: str
    recorded_on: str
    hours_per_month: int
    t3_micro_hourly: Decimal
    public_ipv4_hourly: Decimal
    gp3_gib_month: Decimal
    sources: tuple[str, ...]


PRICE_SNAPSHOT = PriceSnapshot(
    version="us-east-1/2026-10-29.1",
    region="us-east-1",
    recorded_on="2026-10-29",
    hours_per_month=730,
    t3_micro_hourly=Decimal("0.0104"),
    public_ipv4_hourly=Decimal("0.005"),
    gp3_gib_month=Decimal("0.08"),
    sources=(
        "https://aws.amazon.com/ec2/pricing/on-demand/",
        "https://aws.amazon.com/vpc/pricing/",
        "https://aws.amazon.com/ebs/pricing/",
    ),
)

EXCLUDED = [
    "taxes",
    "data transfer",
    "EBS snapshots",
    "CloudWatch, SSM and other control-plane usage",
    "T3 unlimited surplus credits (instances use cpu_credits=standard)",
]

DISCLAIMER = (
    "Estimate from a recorded on-demand price snapshot for a full 730-hour month; actual "
    "charges vary. No Free Tier eligibility is assumed or guaranteed. AWS budget alerts "
    "notify but do not cap spending."
)

_CENT = Decimal("0.01")


def _usd(value: Decimal) -> str:
    return str(value.quantize(_CENT, rounding=ROUND_HALF_UP))


def estimate_monthly_cost(disk_gib: int, snapshot: PriceSnapshot = PRICE_SNAPSHOT) -> CostEstimate:
    hours = Decimal(snapshot.hours_per_month)
    compute = (snapshot.t3_micro_hourly * hours).quantize(_CENT, rounding=ROUND_HALF_UP)
    ipv4 = (snapshot.public_ipv4_hourly * hours).quantize(_CENT, rounding=ROUND_HALF_UP)
    disk = (snapshot.gp3_gib_month * disk_gib).quantize(_CENT, rounding=ROUND_HALF_UP)
    return CostEstimate(
        monthly_total_usd=_usd(compute + ipv4 + disk),
        hours_per_month=snapshot.hours_per_month,
        lines=[
            CostLine(
                item="EC2 t3.micro (Linux, on-demand)",
                monthly_usd=_usd(compute),
                basis=f"${snapshot.t3_micro_hourly}/hour x {snapshot.hours_per_month} h",
            ),
            CostLine(
                item="Public IPv4 address",
                monthly_usd=_usd(ipv4),
                basis=f"${snapshot.public_ipv4_hourly}/hour x {snapshot.hours_per_month} h",
            ),
            CostLine(
                item=f"EBS gp3 root volume ({disk_gib} GiB)",
                monthly_usd=_usd(disk),
                basis=f"${snapshot.gp3_gib_month}/GiB-month x {disk_gib} GiB",
            ),
        ],
        price_snapshot={
            "version": snapshot.version,
            "region": snapshot.region,
            "recorded_on": snapshot.recorded_on,
            "sources": list(snapshot.sources),
            "live_quote": False,
        },
        excluded=EXCLUDED,
        disclaimer=DISCLAIMER,
    )
