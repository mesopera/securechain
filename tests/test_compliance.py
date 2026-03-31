"""
tests/test_compliance.py
Tests for sanctions, limits, fraud_score, and smart_contract.
"""

import pytest
import time
from core.transaction import Transaction
from compliance import sanctions, limits, fraud_score, smart_contract


# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────

def make_tx(
    sender="clean_sender_address_" + "0" * 44,
    receiver="clean_receiver_address_" + "0" * 42,
    amount=500,
    currency="USD",
    sender_country="US",
    receiver_country="IN",
):
    return Transaction(
        sender=sender,
        receiver=receiver,
        amount=amount,
        currency=currency,
        sender_country=sender_country,
        receiver_country=receiver_country,
    )


OFAC_BLOCKED = "deadbeef00000000000000000000000000000000000000000000000000000001"
UN_BLOCKED   = "1111111100000000000000000000000000000000000000000000000000000001"
CLEAN_ADDR_A = "aaaa000000000000000000000000000000000000000000000000000000000001"
CLEAN_ADDR_B = "bbbb000000000000000000000000000000000000000000000000000000000002"


# ─────────────────────────────────────────────────────────────
# Sanctions tests
# ─────────────────────────────────────────────────────────────

class TestSanctions:
    def test_clean_transaction_passes(self):
        tx = make_tx(sender=CLEAN_ADDR_A, receiver=CLEAN_ADDR_B)
        result = sanctions.check(tx)
        assert result["passed"] is True

    def test_ofac_sender_blocked(self):
        tx = make_tx(sender=OFAC_BLOCKED, receiver=CLEAN_ADDR_B)
        result = sanctions.check(tx)
        assert result["passed"] is False
        assert any(f["detail"].get("list") == "OFAC" for f in result["flags"])

    def test_un_sender_blocked(self):
        tx = make_tx(sender=UN_BLOCKED, receiver=CLEAN_ADDR_B)
        result = sanctions.check(tx)
        assert result["passed"] is False

    def test_ofac_receiver_blocked(self):
        tx = make_tx(sender=CLEAN_ADDR_A, receiver=OFAC_BLOCKED)
        result = sanctions.check(tx)
        assert result["passed"] is False

    def test_blocked_country_KP(self):
        tx = make_tx(sender=CLEAN_ADDR_A, receiver=CLEAN_ADDR_B,
                     sender_country="US", receiver_country="KP")
        result = sanctions.check(tx)
        assert result["passed"] is False

    def test_clean_countries_pass(self):
        tx = make_tx(sender_country="US", receiver_country="GB")
        result = sanctions.check(tx)
        assert result["passed"] is True

    def test_both_sender_and_receiver_blocked(self):
        tx = make_tx(sender=OFAC_BLOCKED, receiver=UN_BLOCKED)
        result = sanctions.check(tx)
        assert result["passed"] is False
        assert len(result["flags"]) == 2


# ─────────────────────────────────────────────────────────────
# Limits tests
# ─────────────────────────────────────────────────────────────

class TestLimits:
    def test_normal_transaction_passes(self):
        tx = make_tx(sender=CLEAN_ADDR_A, amount=500,
                     sender_country="US", receiver_country="IN")
        result = limits.check(tx)
        assert result["passed"] is True

    def test_exceeds_single_tx_limit(self):
        tx = make_tx(sender=CLEAN_ADDR_A, amount=30000,
                     sender_country="US", receiver_country="IN")
        result = limits.check(tx)
        assert result["passed"] is False
        assert any("single_tx_limit_exceeded" in f for f in result["flags"])

    def test_blocked_corridor_US_IR(self):
        tx = make_tx(sender=CLEAN_ADDR_A, amount=1,
                     sender_country="US", receiver_country="IR")
        result = limits.check(tx)
        assert result["passed"] is False
        assert "corridor_blocked" in result["flags"]

    def test_blocked_corridor_US_KP(self):
        tx = make_tx(sender=CLEAN_ADDR_A, amount=1,
                     sender_country="US", receiver_country="KP")
        result = limits.check(tx)
        assert result["passed"] is False

    def test_edd_required_for_high_risk(self):
        tx = make_tx(sender=CLEAN_ADDR_A, amount=100,
                     sender_country="US", receiver_country="NG")
        result = limits.check(tx)
        assert result["enhanced_due_diligence_required"] is True

    def test_default_corridor_applied(self):
        tx = make_tx(sender=CLEAN_ADDR_A, amount=500,
                     sender_country="ZZ", receiver_country="ZZ")
        result = limits.check(tx)
        assert result["corridor"] == "ZZ-ZZ"
        assert result["corridor_limits"]["single_tx_limit"] == 10000


# ─────────────────────────────────────────────────────────────
# Fraud score tests
# ─────────────────────────────────────────────────────────────

class TestFraudScore:
    def test_clean_low_amount_scores_low(self):
        tx = make_tx(sender=CLEAN_ADDR_A, amount=200,
                     sender_country="US", receiver_country="IN")
        result = fraud_score.compute_score(tx)
        assert result["score"] < fraud_score.FRAUD_REVIEW_THRESHOLD
        assert result["risk_level"] == "LOW"
        assert result["passed"] is True

    def test_high_amount_raises_score(self):
        tx = make_tx(sender=CLEAN_ADDR_A, amount=22000,
                     sender_country="US", receiver_country="IN")
        result = fraud_score.compute_score(tx)
        assert result["score"] > 0
        assert any(r["rule"] == "R1_HIGH_AMOUNT" for r in result["rules_triggered"])

    def test_round_number_triggers_r2(self):
        tx = make_tx(sender=CLEAN_ADDR_A, amount=5000,
                     sender_country="US", receiver_country="IN")
        result = fraud_score.compute_score(tx)
        assert any(r["rule"] == "R2_ROUND_AMOUNT" for r in result["rules_triggered"])

    def test_structuring_below_10k_triggers_r7(self):
        tx = make_tx(sender=CLEAN_ADDR_A, amount=9500,
                     sender_country="US", receiver_country="IN")
        result = fraud_score.compute_score(tx)
        assert any(r["rule"] == "R7_STRUCTURING" for r in result["rules_triggered"])

    def test_high_risk_country_triggers_r6(self):
        tx = make_tx(sender=CLEAN_ADDR_A, amount=200,
                     sender_country="US", receiver_country="IR")
        result = fraud_score.compute_score(tx)
        assert any(r["rule"] == "R6_HIGH_RISK_COUNTRY" for r in result["rules_triggered"])

    def test_score_capped_at_100(self):
        # All bad flags at once
        tx = make_tx(
            sender=CLEAN_ADDR_A,
            amount=25000,   # R1 + R2 + R7 candidate
            sender_country="US",
            receiver_country="IR",  # R6
        )
        # Override to 9999 for R7
        tx2 = make_tx(sender=CLEAN_ADDR_A, amount=9999,
                      sender_country="US", receiver_country="IR")
        result = fraud_score.compute_score(tx2)
        assert result["score"] <= 100

    def test_new_sender_large_amount_triggers_r8(self):
        unique_addr = "f1f1" + "0" * 60
        tx = make_tx(sender=unique_addr, amount=8000,
                     sender_country="US", receiver_country="IN")
        result = fraud_score.compute_score(tx)
        assert any(r["rule"] == "R8_NEW_SENDER_LARGE" for r in result["rules_triggered"])


# ─────────────────────────────────────────────────────────────
# Smart contract (full pipeline) tests
# ─────────────────────────────────────────────────────────────

class TestSmartContract:
    def test_clean_transaction_approved(self):
        tx = make_tx(sender=CLEAN_ADDR_A, receiver=CLEAN_ADDR_B,
                     amount=200, sender_country="US", receiver_country="IN")
        result = smart_contract.run(tx)
        assert result["approved"] is True
        assert result["rejection_reason"] is None

    def test_sanctioned_sender_rejected(self):
        tx = make_tx(sender=OFAC_BLOCKED, receiver=CLEAN_ADDR_B)
        result = smart_contract.run(tx)
        assert result["approved"] is False
        assert result["checks"]["limits"] is None  # stops at sanctions

    def test_blocked_corridor_rejected(self):
        tx = make_tx(sender=CLEAN_ADDR_A, receiver=CLEAN_ADDR_B,
                     amount=1, sender_country="US", receiver_country="IR")
        result = smart_contract.run(tx)
        assert result["approved"] is False
        assert result["checks"]["sanctions"]["passed"] is True  # got past sanctions
        assert result["checks"]["limits"]["passed"] is False

    def test_compliance_result_attached_to_tx(self):
        tx = make_tx(sender=CLEAN_ADDR_A, receiver=CLEAN_ADDR_B,
                     amount=100, sender_country="US", receiver_country="IN")
        smart_contract.run(tx)
        assert tx.compliance_result is not None
        assert "approved" in tx.compliance_result

    def test_explain_approved(self):
        tx = make_tx(sender=CLEAN_ADDR_A, receiver=CLEAN_ADDR_B,
                     amount=100, sender_country="US", receiver_country="IN")
        result = smart_contract.run(tx)
        explanation = smart_contract.explain(result)
        assert "APPROVED" in explanation

    def test_explain_rejected(self):
        tx = make_tx(sender=OFAC_BLOCKED, receiver=CLEAN_ADDR_B)
        result = smart_contract.run(tx)
        explanation = smart_contract.explain(result)
        assert "REJECTED" in explanation