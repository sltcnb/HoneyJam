"""Windows services (SYSTEM\\CurrentControlSet\\Services)."""

from __future__ import annotations

from honeyjam.analysis.heuristics import (
    SECURITY_SERVICES,
    START_TYPES,
    analyze_command,
)
from honeyjam.models import Finding, PluginResult, Severity
from honeyjam.parser.hive import Hive
from honeyjam.plugins import Plugin


class ServicesPlugin(Plugin):
    name = "services"
    description = "Enumerate SYSTEM services, flag suspicious ImagePath and disabled security services"
    hives = ["system"]

    def run(self, hive: Hive) -> PluginResult:
        result = self._result()
        result.hive_type = hive.hive_type
        services_path = hive.control_set_path(r"\Services")
        root = hive.get_key(services_path)
        if root is None:
            result.errors.append(f"Services key not found at {services_path}")
            return result

        for svc in root.subkeys():
            image = svc.get_value("ImagePath")
            start = svc.get_value("Start")
            image_path = str(image.data) if image and image.data is not None else ""
            start_val = start.data if start else None
            start_label = START_TYPES.get(
                start_val if isinstance(start_val, int) else -1, "unknown"
            )

            # Suspicious binary path
            suspicion = analyze_command(image_path)
            if suspicion.suspicious:
                result.add(
                    Finding(
                        title=f"Service '{svc.name}' has suspicious ImagePath",
                        description="Suspicious ImagePath: "
                        + ", ".join(h.label for h in suspicion.hits),
                        severity=suspicion.severity,
                        confidence=max(60, suspicion.score),
                        registry_key=svc.path,
                        value_name="ImagePath",
                        value_data=image_path,
                        value_type=image.value_type if image else None,
                        timestamp=svc.last_written,
                        indicators=suspicion.indicators,
                        tags=["service", "suspicious"],
                    )
                )

            # Disabled security service
            lname = svc.name.lower()
            if lname in SECURITY_SERVICES and start_val == 4:
                friendly = SECURITY_SERVICES[lname]
                result.add(
                    Finding(
                        title=f"Security service '{svc.name}' ({friendly}) is DISABLED",
                        description="A security-relevant service has been set to Disabled (Start=4), "
                        "a common defense-evasion technique.",
                        severity=Severity.HIGH,
                        confidence=85,
                        registry_key=svc.path,
                        value_name="Start",
                        value_data=start_val,
                        value_type=start.value_type if start else None,
                        timestamp=svc.last_written,
                        indicators=["defense_evasion.service_disabled"],
                        tags=["service", "defense-evasion"],
                    )
                )

            # Informational inventory entry for anything with a binary path
            if image_path and not suspicion.suspicious and lname not in SECURITY_SERVICES:
                result.add(
                    Finding(
                        title=f"Service '{svc.name}' ({start_label})",
                        description="Service inventory entry",
                        severity=Severity.INFO,
                        confidence=20,
                        registry_key=svc.path,
                        value_name="ImagePath",
                        value_data=image_path,
                        value_type=image.value_type if image else None,
                        timestamp=svc.last_written,
                        tags=["service"],
                    )
                )
        return result
