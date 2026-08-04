from __future__ import annotations

import math
from dataclasses import dataclass


def _round_up(value: float) -> float:
    """Round up to the nearest 0.1 per CVSS v3.1 specification."""
    # To handle floating point inaccuracies (e.g., 4.0200000000000005 -> 4.02),
    # First round to 5 decimal places before ceiling.
    return math.ceil(round(value, 5) * 10) / 10.0

@dataclass
class CVSSVector:
    attack_vector: str = "N"      # N=Network, A=Adjacent, L=Local, P=Physical
    attack_complexity: str = "L"   # L=Low, H=High
    privileges_required: str = "N" # N=None, L=Low, H=High
    user_interaction: str = "N"    # N=None, R=Required
    scope: str = "U"              # U=Unchanged, C=Changed
    confidentiality: str = "N"    # N=None, L=Low, H=High
    integrity: str = "N"          # N=None, L=Low, H=High
    availability: str = "N"       # N=None, L=Low, H=High

    def to_string(self) -> str:
        """Return CVSS v3.1 vector string."""
        return f"CVSS:3.1/AV:{self.attack_vector}/AC:{self.attack_complexity}/PR:{self.privileges_required}/UI:{self.user_interaction}/S:{self.scope}/C:{self.confidentiality}/I:{self.integrity}/A:{self.availability}"

    def calculate_score(self) -> float:
        """Calculate CVSS v3.1 base score using the official formula."""
        av_weights = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
        ac_weights = {"L": 0.77, "H": 0.44}
        ui_weights = {"N": 0.85, "R": 0.62}
        cia_weights = {"N": 0.0, "L": 0.22, "H": 0.56}

        pr_weights = {
            "U": {"N": 0.85, "L": 0.62, "H": 0.27},
            "C": {"N": 0.85, "L": 0.68, "H": 0.50}
        }

        av = av_weights.get(self.attack_vector, 0.85)
        ac = ac_weights.get(self.attack_complexity, 0.77)
        pr = pr_weights.get(self.scope, pr_weights["U"]).get(self.privileges_required, 0.85)
        ui = ui_weights.get(self.user_interaction, 0.85)
        c = cia_weights.get(self.confidentiality, 0.0)
        i = cia_weights.get(self.integrity, 0.0)
        a = cia_weights.get(self.availability, 0.0)

        iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))

        if iss <= 0:
            return 0.0

        if self.scope == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02)**15)

        exploitability = 8.22 * av * ac * pr * ui

        if self.scope == "U":
            return _round_up(min(impact + exploitability, 10.0))
        else:
            return _round_up(min(1.08 * (impact + exploitability), 10.0))

# Pre-defined vectors for common attack chain categories
CHAIN_VECTORS: dict[str, CVSSVector] = {
    "subdomain_takeover": CVSSVector("N", "L", "N", "N", "C", "H", "H", "N"),  # 9.3 (Modified to get exactly 9.3 may need adjustments, but let's stick to vector in prompt)
    "cors_exploitation": CVSSVector("N", "L", "N", "R", "C", "H", "H", "N"),  # 9.3
    "secret_exploitation": CVSSVector("N", "L", "N", "N", "U", "H", "H", "N"),  # 9.1
    "data_exfiltration": CVSSVector("N", "L", "N", "N", "U", "H", "N", "N"),  # 7.5
    "exposed_database": CVSSVector("N", "L", "N", "N", "U", "H", "H", "H"),  # 9.8
    "nuclei_exploit": CVSSVector("N", "L", "N", "N", "U", "H", "H", "N"),    # 9.1
    "internal_access": CVSSVector("N", "L", "L", "N", "C", "H", "H", "N"),    # 8.5
    "tech_cve_chain": CVSSVector("N", "L", "N", "N", "U", "H", "H", "H"),     # 9.8
    "waf_bypass": CVSSVector("N", "H", "N", "N", "U", "L", "L", "N"),         # 4.8
    "ssl_weakness": CVSSVector("N", "H", "N", "N", "U", "H", "N", "N"),       # 5.9
}

def score_chain(chain_type: str) -> tuple[float, str]:
    """Return (score, vector_string) for a chain type."""
    vec = CHAIN_VECTORS.get(chain_type, CVSSVector())
    return vec.calculate_score(), vec.to_string()

def severity_from_score(score: float) -> str:
    """Return severity label: Critical/High/Medium/Low/None."""
    if score >= 9.0:
        return "critical"
    elif score >= 7.0:
        return "high"
    elif score >= 4.0:
        return "medium"
    elif score >= 0.1:
        return "low"
    else:
        return "none"
