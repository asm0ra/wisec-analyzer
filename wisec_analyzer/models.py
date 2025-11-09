from dataclasses import dataclass, field
from typing import List, Tuple, Optional


@dataclass
class TimeBin:
    start_ts: float                      # начало интервала (floor по времени)
    count: int                           # сколько deauth/disassoc кадров в бине
    unique_sources: int                  # сколько уникальных MAC-источников
    top_sources: List[Tuple[str, int]]   # [(mac, count), ...]
    alert: bool                          # флаг "подозрительный интервал"


@dataclass
class FileSummary:
    file_path: str
    duration_sec: float
    total_packets: int
    total_deauth: int
    total_disassoc: int
    total_eapol: int
    bins: List[TimeBin]
    bin_size_sec: int
    threshold: int
    attack_detected: bool
    first_attack_ts: Optional[float] = None
    last_attack_ts: Optional[float] = None


@dataclass
class BatchSummary:
    input_dir: str
    files: List[FileSummary] = field(default_factory=list)
