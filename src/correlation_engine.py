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
    behavioral_alerts,
    web_alerts=None,
):
    """
    Produce the overall IDS decision.

    Rules:
    1. If ML detects any attack -> ATTACK
    2. If Behavioral IDS detects any attack -> ATTACK
    3. If both detect attacks -> ATTACK with stronger confidence
    4. If neither detects anything -> BENIGN
    """

    if web_alerts is None:
        web_alerts = []

    ml_attack_count = int(
        (
            ml_results[
                "Binary Prediction"
            ] == "ATTACK"
        ).sum()
    )

    behavioral_attack_count = len(
        behavioral_alerts
    )

    web_alert_count = len(
        web_alerts
    )

    # -----------------------------------------------------
    # No engine detected an attack
    # -----------------------------------------------------

    if (
        ml_attack_count == 0
        and behavioral_attack_count == 0
        and web_alert_count == 0
    ):

        return {
            "final_decision": "BENIGN",
            "attack_type": "None",
            "severity": "NORMAL",
            "detection_source": "None",
            "ml_attack_count": 0,
            "behavioral_alert_count": 0,
            "web_alert_count": 0,
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
            for alert in behavioral_alerts
        )
    )

    web_attack_types = [
        alert.get(
            "attack_type",
            "Unknown"
        )
        for alert in web_alerts
    ]

    # -----------------------------------------------------
    # Determine strongest severity across behavioral
    # and web alerts
    # -----------------------------------------------------

    security_alerts = (
        list(behavioral_alerts)
        + list(web_alerts)
    )

    strongest_severity = "MEDIUM"

    if security_alerts:

        strongest_severity = max(
            (
                alert.get(
                    "severity",
                    "MEDIUM"
                )
                for alert in security_alerts
            ),
            key=lambda x: SEVERITY_RANK.get(
                x,
                0
            ),
        )

    # -----------------------------------------------------
    # ML + (BEHAVIORAL AND/OR WEB)
    # -----------------------------------------------------

    if (
        ml_attack_count > 0
        and (
            behavioral_attack_count > 0
            or web_alert_count > 0
        )
    ):

        combined_types = list(
            dict.fromkeys(
                ml_attack_types
                + behavioral_attack_types
                + web_attack_types
            )
        )

        return {
            "final_decision": "ATTACK",
            "attack_type": ", ".join(
                combined_types
            ),
            "severity": strongest_severity,
            "detection_source": (
                "Hybrid IDS"
            ),
            "ml_attack_count": ml_attack_count,
            "behavioral_alert_count": (
                behavioral_attack_count
            ),
            "web_alert_count": web_alert_count,
            "reason": (
                "Attack indicators were detected "
                "by multiple AI-IDS detection engines."
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
            "web_alert_count": 0,
            "reason": (
                "The ML intrusion detection model "
                "classified one or more flows "
                "as malicious."
            ),
        }

    # -----------------------------------------------------
    # BEHAVIORAL AND/OR WEB (no ML detection)
    # -----------------------------------------------------

    combined_types = list(
        dict.fromkeys(
            behavioral_attack_types
            + web_attack_types
        )
    )

    if behavioral_attack_count > 0 and web_alert_count > 0:
        detection_source = "Behavioral IDS + Payload Inspection"
        reason = (
            "Suspicious cross-flow behavior and "
            "malicious payloads were detected even "
            "though individual flows were not "
            "classified as attacks by the ML model."
        )
    elif web_alert_count > 0:
        detection_source = "Payload Inspection"
        reason = (
            "Malicious web payload indicators were "
            "detected even though individual flows "
            "were not classified as attacks by the "
            "ML model."
        )
    else:
        detection_source = "Behavioral IDS"
        reason = (
            "Suspicious cross-flow behavior was "
            "detected even though individual "
            "flows were not classified as attacks "
            "by the ML model."
        )

    return {
        "final_decision": "ATTACK",
        "attack_type": ", ".join(
            combined_types
        ),
        "severity": strongest_severity,
        "detection_source": detection_source,
        "ml_attack_count": 0,
        "behavioral_alert_count": (
            behavioral_attack_count
        ),
        "web_alert_count": web_alert_count,
        "reason": reason,
    }
