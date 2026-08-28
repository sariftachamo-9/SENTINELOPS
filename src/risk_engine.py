from typing import Dict, Any

class RiskEngine:
    """
    Explainable, Transparent Risk Scoring Model for Enterprise SOC.
    
    Formula & Point Factors:
    1. Base Severity: Critical (+40), High (+30), Medium (+20), Low (+10)
    2. Event Frequency / Recurrence: 1 (+0), 2-4 (+10), >=5 (+20)
    3. Confidence Score: Confidence % * 0.20 (Up to +20)
    4. Asset Criticality: Critical/Domain-Controller (+20), High (+15), Medium (+10), Low (+5)
    5. Account Sensitivity: Admin/Root/Domain Admin (+15), Sensitive (+10), Standard (+5)
    6. Correlation Strength: Multi-event sequence (+15), Single rule (+5)
    7. IOC Threat Intel Match: Confirmed Malicious (+15), Suspicious (+10), Clean/Unknown (+0)
    
    Final Risk Score: Sum of factors capped strictly between 0 and 100.
    """
    def __init__(self):
        pass

    def calculate_risk(self, alert_or_event: Dict[str, Any]) -> Dict[str, Any]:
        breakdown = {}

        # 1. Base Severity Factor (Max 40)
        sev_str = str(alert_or_event.get("severity", "medium")).lower()
        if sev_str == "critical":
            sev_pts = 40
        elif sev_str == "high":
            sev_pts = 30
        elif sev_str == "medium":
            sev_pts = 20
        else:
            sev_pts = 10
        breakdown["base_severity"] = sev_pts

        # 2. Event Frequency / Recurrence Factor (Max 20)
        count = int(alert_or_event.get("occurrence_count") or len(alert_or_event.get("triggering_event_ids") or [1]))
        if count >= 5:
            freq_pts = 20
        elif count >= 2:
            freq_pts = 10
        else:
            freq_pts = 0
        breakdown["event_frequency"] = freq_pts

        # 3. Confidence Factor (Max 20)
        conf = float(alert_or_event.get("confidence", 80))
        conf_pts = int(round((conf / 100.0) * 20))
        breakdown["confidence"] = conf_pts

        # 4. Asset Criticality Factor (Max 20)
        asset_crit = str(alert_or_event.get("asset_criticality") or alert_or_event.get("affected_asset") or "Medium").lower()
        if any(kw in asset_crit for kw in ["dc", "domain-controller", "database", "prod-db", "critical"]):
            asset_pts = 20
        elif "high" in asset_crit or "server" in asset_crit:
            asset_pts = 15
        elif "medium" in asset_crit:
            asset_pts = 10
        else:
            asset_pts = 5
        breakdown["asset_criticality"] = asset_pts

        # 5. Account Sensitivity Factor (Max 15)
        user = str(alert_or_event.get("affected_user") or alert_or_event.get("username") or "").lower()
        if user in ["admin", "administrator", "root", "domain admin", "system"]:
            account_pts = 15
        elif user != "" and user != "n/a":
            account_pts = 10
        else:
            account_pts = 5
        breakdown["account_sensitivity"] = account_pts

        # 6. Correlation Strength Factor (Max 15)
        rule_id = str(alert_or_event.get("rule_id", ""))
        is_corr = rule_id.startswith("CORR-") or len(alert_or_event.get("triggering_event_ids", [])) > 1
        corr_pts = 15 if is_corr else 5
        breakdown["correlation_strength"] = corr_pts

        # 7. IOC Reputation Factor (Max 15)
        ti_obj = alert_or_event.get("threat_intel")
        highest_rep = ""
        if isinstance(ti_obj, dict):
            highest_rep = str(ti_obj.get("highest_reputation", "")).upper()

        ioc_rep = alert_or_event.get("threat_intel_matched") or alert_or_event.get("ioc_reputation") or highest_rep
        if ioc_rep is True or str(ioc_rep).upper() in ["MALICIOUS", "HIGH_RISK"]:
            ioc_pts = 15
        elif ioc_rep == "SUSPICIOUS" or str(ioc_rep).lower() == "suspicious":
            ioc_pts = 10
        else:
            ioc_pts = 0
        breakdown["ioc_reputation"] = ioc_pts

        total_risk = sum(breakdown.values())
        final_risk = max(0, min(100, total_risk))

        if final_risk >= 80:
            level = "CRITICAL"
        elif final_risk >= 60:
            level = "HIGH"
        elif final_risk >= 40:
            level = "MEDIUM"
        else:
            level = "LOW"

        explanation_parts = [f"Base severity '{sev_str.upper()}': +{sev_pts}"]
        if freq_pts > 0:
            explanation_parts.append(f"Event frequency ({count} occurrences): +{freq_pts}")
        explanation_parts.append(f"Confidence ({conf}%): +{conf_pts}")
        explanation_parts.append(f"Asset criticality factor: +{asset_pts}")
        if account_pts > 5:
            explanation_parts.append(f"Sensitive account '{user}': +{account_pts}")
        if corr_pts > 5:
            explanation_parts.append(f"Multi-event correlation: +{corr_pts}")
        if ioc_pts > 0:
            explanation_parts.append(f"Threat intel IOC match: +{ioc_pts}")

        return {
            "risk_score": final_risk,
            "risk_level": level,
            "breakdown": breakdown,
            "formula": "Risk = BaseSeverity + EventFrequency + Confidence + AssetCriticality + AccountSensitivity + CorrelationStrength + IOCReputation",
            "explanation": f"Risk Score {final_risk} ({level}) calculated from: " + "; ".join(explanation_parts) + "."
        }
