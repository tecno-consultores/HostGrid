"""Embedded offline Linux End-of-Life reference dataset."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date


@dataclass(frozen=True)
class EolEntrySpec:
    """Static EOL lifecycle specification for a Linux distribution version."""

    os_family: str
    os_version: str
    codename: str
    standard_eol_date: date
    extended_eol_date: date | None = None
    notes: str = ""


BUILTIN_EOL_CATALOG: tuple[EolEntrySpec, ...] = (
    EolEntrySpec("debian", "7", "wheezy", date(2016, 4, 25), date(2018, 5, 31), "Debian 7 EOL"),
    EolEntrySpec("debian", "8", "jessie", date(2018, 6, 17), date(2020, 6, 30), "Debian 8 EOL"),
    EolEntrySpec("debian", "9", "stretch", date(2020, 7, 18), date(2022, 6, 30), "Debian 9 EOL"),
    EolEntrySpec("debian", "10", "buster", date(2022, 9, 10), date(2024, 6, 30), "Debian 10 EOL"),
    EolEntrySpec("debian", "11", "bullseye", date(2024, 8, 14), date(2026, 8, 31), "Debian 11 LTS"),
    EolEntrySpec("debian", "12", "bookworm", date(2026, 6, 10), date(2028, 6, 30), "Debian 12"),
    EolEntrySpec("debian", "13", "trixie", date(2028, 8, 9), date(2030, 6, 30), "Debian 13"),
    EolEntrySpec("ubuntu", "14.04", "trusty", date(2019, 4, 30), date(2024, 4, 30), "Ubuntu 14.04"),
    EolEntrySpec("ubuntu", "16.04", "xenial", date(2021, 4, 30), date(2026, 4, 30), "Ubuntu 16.04"),
    EolEntrySpec("ubuntu", "18.04", "bionic", date(2023, 5, 31), date(2028, 4, 30), "Ubuntu 18.04"),
    EolEntrySpec("ubuntu", "20.04", "focal", date(2025, 5, 31), date(2030, 4, 30), "Ubuntu 20.04"),
    EolEntrySpec("ubuntu", "22.04", "jammy", date(2027, 6, 1), date(2032, 4, 30), "Ubuntu 22.04"),
    EolEntrySpec("ubuntu", "24.04", "noble", date(2029, 5, 31), date(2034, 4, 30), "Ubuntu 24.04"),
    EolEntrySpec(
        "ubuntu", "26.04", "resolute", date(2031, 5, 31), date(2036, 4, 30), "Ubuntu 26.04"
    ),
    EolEntrySpec("centos", "6", "centos6", date(2020, 11, 30), None, "CentOS 6 EOL"),
    EolEntrySpec("centos", "7", "centos7", date(2024, 6, 30), None, "CentOS 7 EOL"),
    EolEntrySpec("centos", "8", "centos8", date(2021, 12, 31), None, "CentOS 8 EOL"),
    EolEntrySpec("centos", "9", "stream9", date(2027, 5, 31), None, "CentOS Stream 9"),
    EolEntrySpec("rhel", "6", "santiago", date(2020, 11, 30), date(2024, 6, 30), "RHEL 6 EOL"),
    EolEntrySpec("rhel", "7", "maipo", date(2024, 6, 30), date(2028, 6, 30), "RHEL 7 Maint EOL"),
    EolEntrySpec("rhel", "8", "ootpa", date(2029, 5, 31), date(2032, 5, 31), "RHEL 8"),
    EolEntrySpec("rhel", "9", "plow", date(2032, 5, 31), date(2035, 5, 31), "RHEL 9"),
    EolEntrySpec("alpine", "3.16", "3.16", date(2024, 5, 23), None, "Alpine 3.16 EOL"),
    EolEntrySpec("alpine", "3.17", "3.17", date(2024, 11, 22), None, "Alpine 3.17 EOL"),
    EolEntrySpec("alpine", "3.18", "3.18", date(2025, 5, 9), None, "Alpine 3.18 EOL"),
    EolEntrySpec("alpine", "3.19", "3.19", date(2025, 11, 1), None, "Alpine 3.19"),
    EolEntrySpec("alpine", "3.20", "3.20", date(2026, 4, 1), None, "Alpine 3.20"),
    EolEntrySpec("alpine", "3.21", "3.21", date(2026, 11, 1), None, "Alpine 3.21"),
    EolEntrySpec("alpine", "3.22", "3.22", date(2027, 5, 1), None, "Alpine 3.22"),
    EolEntrySpec("suse", "12", "sles12", date(2024, 10, 31), date(2027, 10, 31), "SLES 12"),
    EolEntrySpec("suse", "15", "sles15", date(2028, 7, 31), date(2031, 7, 31), "SLES 15"),
)

BUILTIN_EOL_INDEX: dict[tuple[str, str], EolEntrySpec] = {
    (item.os_family, item.os_version): item for item in BUILTIN_EOL_CATALOG
}
