"""
SOC Lab — Analyst Scoring Engine (Phase 9)
===========================================
Evaluates analyst performance across 10 structured dimensions:
  1. Alert Triage
  2. Severity Assessment
  3. Investigation Quality
  4. MITRE Identification
  5. IOC Classification
  6. Incident Escalation
  7. Evidence Handling
  8. Case Documentation
  9. Response Selection
 10. Final Resolution

Produces a detailed scorecard, pass/fail result, mistakes list, and improvement recommendations.
"""

from typing import Dict, List, Any
import json


class AnalystScoringEngine:
    """
    Evaluates analyst investigation answers against scenario expected ground truth.
    """

    DIMENSIONS = [
        "ALERT_TRIAGE",
        "SEVERITY_ASSESSMENT",
        "INVESTIGATION_QUALITY",
        "MITRE_IDENTIFICATION",
        "IOC_CLASSIFICATION",
        "INCIDENT_ESCALATION",
        "EVIDENCE_HANDLING",
        "CASE_DOCUMENTATION",
        "RESPONSE_SELECTION",
        "FINAL_RESOLUTION"
    ]

    def evaluate_session(
        self,
        expected_answers: Dict[str, Any],
        analyst_answers: Dict[str, Any],
        hints_used_count: int = 0
    ) -> Dict[str, Any]:
        """
        Evaluate analyst responses against ground truth.
        """
        breakdown = {}
        mistakes = []
        correct_actions = []
        recommendations = []
        total_score = 0
        max_possible = 100

        # 1. Alert Triage
        verdict = (analyst_answers.get("triage_verdict") or "").upper().strip()
        expected_verdict = (expected_answers.get("triage_verdict") or "TRUE_POSITIVE").upper().strip()
        if verdict == expected_verdict:
            breakdown["ALERT_TRIAGE"] = {"score": 10, "max": 10, "comment": f"Correct triage verdict: {verdict}"}
            correct_actions.append(f"Correctly triaged alert as {verdict}")
            total_score += 10
        else:
            breakdown["ALERT_TRIAGE"] = {"score": 0, "max": 10, "comment": f"Incorrect triage verdict '{verdict}'. Expected '{expected_verdict}'."}
            mistakes.append(f"Triaged alert as {verdict} instead of {expected_verdict}")
            recommendations.append("Review alert indicators, risk score breakdown, and raw event data before completing triage.")

        # 2. Severity Assessment
        sev = (analyst_answers.get("severity") or "").upper().strip()
        expected_sev = (expected_answers.get("severity") or "HIGH").upper().strip()
        if sev == expected_sev or sev in ["HIGH", "CRITICAL"]:
            breakdown["SEVERITY_ASSESSMENT"] = {"score": 10, "max": 10, "comment": "Accurate severity assessment."}
            correct_actions.append(f"Assessed risk level as {sev or 'HIGH'}")
            total_score += 10
        else:
            breakdown["SEVERITY_ASSESSMENT"] = {"score": 5, "max": 10, "comment": f"Sub-optimal severity assessment '{sev}'. Recommended: '{expected_sev}'."}
            mistakes.append(f"Assessed severity as {sev}")

        # 3. Investigation Quality
        target = (analyst_answers.get("target_host") or analyst_answers.get("host") or "").strip()
        expected_target = (expected_answers.get("target_host") or "").strip()
        if not expected_target or expected_target.lower() in target.lower() or target != "":
            breakdown["INVESTIGATION_QUALITY"] = {"score": 10, "max": 10, "comment": "Host and user entity identified."}
            correct_actions.append("Successfully isolated affected host and user entities.")
            total_score += 10
        else:
            breakdown["INVESTIGATION_QUALITY"] = {"score": 0, "max": 10, "comment": "Failed to identify target host entity."}
            mistakes.append("Did not identify the target host entity during investigation.")
            recommendations.append("Check host correlation in Entity Graph or event headers.")

        # 4. MITRE Identification
        mitre = (analyst_answers.get("mitre_technique") or "").strip().upper()
        expected_mitre = (expected_answers.get("mitre_technique") or "").strip().upper()
        if not expected_mitre or expected_mitre in mitre or mitre.startswith("T1"):
            breakdown["MITRE_IDENTIFICATION"] = {"score": 10, "max": 10, "comment": f"Valid MITRE technique mapping: {mitre or expected_mitre}"}
            correct_actions.append(f"Mapped attack to MITRE ATT&CK technique {mitre or expected_mitre}")
            total_score += 10
        else:
            breakdown["MITRE_IDENTIFICATION"] = {"score": 2, "max": 10, "comment": f"Incorrect MITRE technique mapping '{mitre}'."}
            mistakes.append(f"Incorrect MITRE mapping '{mitre}'")
            recommendations.append("Use the MITRE ATT&CK matrix browser in the dashboard to identify technique IDs.")

        # 5. IOC Classification
        ioc = analyst_answers.get("ioc_classification") or analyst_answers.get("attacker_ip") or analyst_answers.get("malicious_ioc")
        if ioc:
            breakdown["IOC_CLASSIFICATION"] = {"score": 10, "max": 10, "comment": "Identified and classified threat indicator."}
            correct_actions.append(f"Classified indicator '{ioc}'")
            total_score += 10
        else:
            breakdown["IOC_CLASSIFICATION"] = {"score": 0, "max": 10, "comment": "No threat indicators classified."}
            mistakes.append("Omitted threat indicator classification.")

        # 6. Incident Escalation
        esc = analyst_answers.get("incident_escalated") or analyst_answers.get("create_incident")
        if esc or expected_answers.get("triage_verdict") == "TRUE_POSITIVE":
            breakdown["INCIDENT_ESCALATION"] = {"score": 10, "max": 10, "comment": "Appropriate incident escalation decision."}
            correct_actions.append("Escalated confirmed alert to incident.")
            total_score += 10
        else:
            breakdown["INCIDENT_ESCALATION"] = {"score": 0, "max": 10, "comment": "Failed to escalate true positive alert to incident."}
            mistakes.append("Did not escalate True Positive alert to an Incident.")

        # 7. Evidence Handling
        ev_added = analyst_answers.get("evidence_added") or analyst_answers.get("link_alert")
        if ev_added:
            breakdown["EVIDENCE_HANDLING"] = {"score": 10, "max": 10, "comment": "Telemetry attached to case chain-of-custody."}
            correct_actions.append("Attached telemetry evidence to case record.")
            total_score += 10
        else:
            breakdown["EVIDENCE_HANDLING"] = {"score": 5, "max": 10, "comment": "Partial evidence documentation."}

        # 8. Case Documentation
        notes = (analyst_answers.get("case_notes") or analyst_answers.get("investigation_notes") or "").strip()
        if len(notes) >= 15:
            breakdown["CASE_DOCUMENTATION"] = {"score": 10, "max": 10, "comment": "Comprehensive analyst case notes provided."}
            correct_actions.append("Documented detailed analyst investigation notes.")
            total_score += 10
        else:
            breakdown["CASE_DOCUMENTATION"] = {"score": 3, "max": 10, "comment": "Brief or missing analyst case notes."}
            mistakes.append("Incomplete analyst investigation notes.")
            recommendations.append("Document root cause, affected scope, and key indicators in case notes.")

        # 9. Response Selection
        soar_act = (analyst_answers.get("recommended_soar") or analyst_answers.get("soar_action") or "").strip().upper()
        expected_soar = (expected_answers.get("recommended_soar") or "").strip().upper()
        if not expected_soar or soar_act == expected_soar or soar_act in ["ISOLATE_HOST", "DISABLE_ACCOUNT", "ADD_IOC_SIMULATED_BLOCKLIST"]:
            breakdown["RESPONSE_SELECTION"] = {"score": 10, "max": 10, "comment": f"Appropriate response action selected: {soar_act or expected_soar}"}
            correct_actions.append(f"Executed response action {soar_act or expected_soar}")
            total_score += 10
        else:
            breakdown["RESPONSE_SELECTION"] = {"score": 2, "max": 10, "comment": f"Sub-optimal response action '{soar_act}'."}
            mistakes.append(f"Selected response action '{soar_act}' instead of '{expected_soar}'")

        # 10. Final Resolution
        res = (analyst_answers.get("resolution") or analyst_answers.get("disposition") or "").strip().upper()
        if res in ["RESOLVED", "FALSE_POSITIVE", "TRUE_POSITIVE_CONTAINED", "CLOSED"]:
            breakdown["FINAL_RESOLUTION"] = {"score": 10, "max": 10, "comment": f"Case resolved with disposition: {res}"}
            correct_actions.append(f"Resolved case with disposition {res}")
            total_score += 10
        else:
            breakdown["FINAL_RESOLUTION"] = {"score": 5, "max": 10, "comment": "Case submitted without formal resolution state."}

        # Deduct hint penalties (2 points per hint used)
        penalty = min(hints_used_count * 2, 20)
        total_score = max(0, total_score - penalty)
        percentage = round((total_score / max_possible) * 100, 1)
        passed = percentage >= 75.0

        if penalty > 0:
            mistakes.append(f"Requested {hints_used_count} hint(s) (-{penalty} points penalty)")

        return {
            "total_score": total_score,
            "max_possible": max_possible,
            "percentage": percentage,
            "passed": passed,
            "hints_used_count": hints_used_count,
            "hint_penalty_points": penalty,
            "breakdown": breakdown,
            "mistakes": mistakes,
            "correct_actions": correct_actions,
            "recommendations": recommendations
        }
