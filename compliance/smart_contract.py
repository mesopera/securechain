"""
compliance/smart_contract.py
Orchestrates the full compliance pipeline for a transaction.

Pipeline order (UPDATED for Phase 2 ZKP):
  0. ZKP identity verification — hard block (no proof = instant reject)
  1. Sanctions screening (OFAC + UN) — hard block
  2. Transfer limits (corridor rules + velocity limits) — hard block
  3. Fraud scoring (velocity + pattern analysis) — block if score >= threshold

A transaction must pass ALL four checks to be approved.
"""

import time
from compliance import sanctions, limits, fraud_score
from identity import zkp_verifier


def run(transaction) -> dict:
    if hasattr(transaction, "to_dict"):
        tx = transaction.to_dict()
    else:
        tx = transaction

    # Step 0 — ZKP identity gate
    zkp_result = zkp_verifier.verify(transaction)
    if not zkp_result["passed"]:
        result = _build_result(
            approved=False,
            rejection_reason=zkp_result["reason"],
            checks={"zkp": zkp_result, "sanctions": None, "limits": None, "fraud_score": None},
            risk_level="HIGH",
        )
        _attach(transaction, result)
        return result

    # Step 1 — Sanctions
    sanctions_result = sanctions.check(transaction)
    if not sanctions_result["passed"]:
        result = _build_result(
            approved=False,
            rejection_reason=sanctions_result["reason"],
            checks={"zkp": zkp_result, "sanctions": sanctions_result, "limits": None, "fraud_score": None},
            risk_level="HIGH",
        )
        _attach(transaction, result)
        return result

    # Step 2 — Limits
    limits_result = limits.check(transaction)
    if not limits_result["passed"]:
        result = _build_result(
            approved=False,
            rejection_reason=limits_result["reason"],
            checks={"zkp": zkp_result, "sanctions": sanctions_result, "limits": limits_result, "fraud_score": None},
            risk_level="HIGH",
        )
        _attach(transaction, result)
        return result

    # Step 3 — Fraud score
    fraud_result = fraud_score.compute_score(transaction)
    if not fraud_result["passed"]:
        result = _build_result(
            approved=False,
            rejection_reason=fraud_result["reason"],
            checks={"zkp": zkp_result, "sanctions": sanctions_result, "limits": limits_result, "fraud_score": fraud_result},
            risk_level="HIGH",
        )
        _attach(transaction, result)
        return result

    # All checks passed
    limits.record_approved(transaction)
    fraud_score.record_approved(transaction)

    result = _build_result(
        approved=True,
        rejection_reason=None,
        checks={"zkp": zkp_result, "sanctions": sanctions_result, "limits": limits_result, "fraud_score": fraud_result},
        risk_level=fraud_result["risk_level"],
    )
    _attach(transaction, result)
    return result


def _build_result(approved, rejection_reason, checks, risk_level) -> dict:
    return {
        "approved": approved,
        "timestamp": time.time(),
        "checks": checks,
        "rejection_reason": rejection_reason,
        "risk_level": risk_level,
    }


def _attach(transaction, result: dict):
    if hasattr(transaction, "compliance_result"):
        transaction.compliance_result = result


def explain(compliance_result: dict) -> str:
    if compliance_result["approved"]:
        risk = compliance_result["risk_level"]
        fraud = compliance_result["checks"].get("fraud_score") or {}
        score = fraud.get("score", "N/A")
        zkp = compliance_result["checks"].get("zkp") or {}
        commitment = zkp.get("commitment", "N/A")
        lines = [
            "✅ APPROVED",
            f"   Risk level  : {risk}",
            f"   Fraud score : {score}/100",
            f"   ZKP proof   : valid (commitment {str(commitment)[:16]}...)",
        ]
        fraud_rules = fraud.get("rules_triggered", [])
        if fraud_rules:
            lines.append("   Fraud flags (non-blocking):")
            for r in fraud_rules:
                lines.append(f"     • {r['rule']}: {r['detail']}")
        edd = compliance_result["checks"].get("limits") or {}
        if edd.get("enhanced_due_diligence_required"):
            lines.append("   ⚠ Enhanced due diligence required for this corridor")
    else:
        reason = compliance_result["rejection_reason"]
        lines = ["❌ REJECTED", f"   Reason: {reason}"]
        for check_name, check_result in compliance_result["checks"].items():
            if check_result and not check_result.get("passed", True):
                lines.append(f"   Failed check: {check_name.upper()}")
                flags = check_result.get("flags", [])
                if flags:
                    if isinstance(flags[0], dict):
                        for f in flags:
                            lines.append(f"     • {f.get('field', '')}: {f.get('detail', {}).get('reason', '')}")
                    else:
                        for f in flags:
                            lines.append(f"     • {f}")
                break

    return "\n".join(lines)