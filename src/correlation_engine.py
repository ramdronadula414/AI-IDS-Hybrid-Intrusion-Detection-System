"""
AI-IDS Correlation Engine

Combines:
- ML IDS results
- Behavioral IDS alerts

and produces the final security decision.
"""


# =========================================================
# SEVERITY RANKING
# =========================================================

SEVERITY_RANK = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


# =========================================================
# CORRELATE RESULTS
# =========================================================

def correlate_detection(
    ml_results,
    behavior_alerts,
):
    """
    Produce the overall IDS decision.

    Rules:
    1. If ML detects any attack -> ATTACK
    2. If Behavioral IDS detects any attack -> ATTACK
    3. If both detect attacks -> ATTACK with stronger confidence
    4. If neither detects anything -> BENIGN
    """

    ml_attack_count = int(
        (
            ml_results[
                "Binary Prediction"
            ] == "ATTACK"
        ).sum()
    )

    behavioral_attack_count = len(
        behavior_alerts
    )

    # -----------------------------------------------------
    # Neither engine detected an attack
    # -----------------------------------------------------

    if (
        ml_attack_count == 0
        and behavioral_attack_count == 0
    ):

        return {
            "final_decision": "BENIGN",
            "attack_type": "None",
            "severity": "NORMAL",
            "detection_source": "None",
            "ml_attack_count": 0,
            "behavioral_alert_count": 0,
            "reason": (
                "No malicious activity detected "
                "by ML or behavioral engines."
            ),
        }

    # -----------------------------------------------------
    # Collect attack types
    # -----------------------------------------------------

    ml_attack_types = []

    if ml_attack_count > 0:

        ml_attack_types = (
            ml_results.loc[
                ml_results[
                    "Binary Prediction"
                ] == "ATTACK",
                "Attack Type",
            ]
            .dropna()
            .astype(str)
            .unique()
            .tolist()
        )

    behavioral_attack_types = list(
        dict.fromkeys(
            alert.get(
                "attack_type",
                "Unknown"
            )
            for alert in behavior_alerts
        )
    )

    # -----------------------------------------------------
    # Determine strongest behavioral severity
    # -----------------------------------------------------

    strongest_severity = "MEDIUM"

    if behavior_alerts:

        strongest_severity = max(
            (
                alert.get(
                    "severity",
                    "MEDIUM"
                )
                for alert in behavior_alerts
            ),
            key=lambda x: SEVERITY_RANK.get(
                x,
                0
            ),
        )

    # -----------------------------------------------------
    # BOTH ML + BEHAVIOR
    # -----------------------------------------------------

    if (
        ml_attack_count > 0
        and behavioral_attack_count > 0
    ):

        combined_types = list(
            dict.fromkeys(
                ml_attack_types
                + behavioral_attack_types
            )
        )

        return {
            "final_decision": "ATTACK",
            "attack_type": ", ".join(
                combined_types
            ),
            "severity": strongest_severity,
            "detection_source": (
                "ML + Behavioral IDS"
            ),
            "ml_attack_count": ml_attack_count,
            "behavioral_alert_count": (
                behavioral_attack_count
            ),
            "reason": (
                "Attack indicators were detected "
                "by both ML and behavioral engines."
            ),
        }

    # -----------------------------------------------------
    # ML ONLY
    # -----------------------------------------------------

    if ml_attack_count > 0:

        return {
            "final_decision": "ATTACK",
            "attack_type": ", ".join(
                ml_attack_types
            ),
            "severity": "HIGH",
            "detection_source": (
                "XGBoost ML IDS"
            ),
            "ml_attack_count": ml_attack_count,
            "behavioral_alert_count": 0,
            "reason": (
                "The ML intrusion detection model "
                "classified one or more flows "
                "as malicious."
            ),
        }

    # -----------------------------------------------------
    # BEHAVIORAL ONLY
    # -----------------------------------------------------

    return {
        "final_decision": "ATTACK",
        "attack_type": ", ".join(
            behavioral_attack_types
        ),
        "severity": strongest_severity,
        "detection_source": (
            "Behavioral IDS"
        ),
        "ml_attack_count": 0,
        "behavioral_alert_count": (
            behavioral_attack_count
        ),
        "reason": (
            "Suspicious cross-flow behavior was "
            "detected even though individual "
            "flows were not classified as attacks "
            "by the ML model."
        ),
    }