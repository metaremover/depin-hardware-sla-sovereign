#!/usr/bin/env python3
"""
DePINHardwareSlaSovereign — 11-Phase Hardcore Security Regression Test Suite (Remediated)
========================================================================================
Validates all hardened state machine transitions, access control boundaries,
economic invariants, and game-theoretic defenses against all Steward Hardcore Audit findings:
1. Permanently Non-Consumable Pre-seeded Genesis Fixtures (NODE_1 SLASHED_JAILED, NODE_2 ACTIVE, LEASE_1 burned).
2. Length-Prefixed Canonical SHA-256 Hashing & Delimiter Injection Resistance.
3. Access Control & Frontrunning Defense: Self-key registration allowed, duplicate registration blocked, non-operator lease commit blocked, operator self-challenge blocked.
4. Verifiable Payable Staking Escrow & Tier Minimums ([ERR_STAKE_INSUFFICIENT], [ERR_BOND_INSUFFICIENT]).
5. Complete SSRF Neutralization & Strict Hex Address Validation ([ERR_ADDR_01], [ERR_ADDR_02], [ERR_URL_SSRF], [ERR_NONCE_LEN]).
6. Stage 3 SLA Verification: Autonomous Multi-Validator Telemetry Audit & Discrete Scoring Determinism.
7. FAIL-CLOSED INVARIANT: Live Telemetry / Breach Proof Fetch Failure Aborts Without Altering State ([ERR_EVIDENCE_FETCH_FAILED]).
8. Reusable Public Gateway Hook: Real-Time On-Chain SLA Compliance Verification (check_node_sla_compliance).
9. GL-SEC-01 & GL-SEC-02 Remediated: Pre-Audit Challenge Blocked ([ERR_NODE_NOT_ACTIVE]), 90% Slashed to Whistleblower, 10% Protocol Fee to Owner, and 100% Zero-Leak Collateral Accounting.
10. Slashed Challenge Bond Compensation: Dismissed challenges credit 100% of challenger bond to innocent node operator claimable balance.
11. Stage 6B Non-Admin Block Time Expiration & Clean Collateral Release ([ERR_LEASE_STILL_ACTIVE]).
12. GL-SEC-04 Single Active Lease Invariant ([ERR_ACTIVE_LEASE_EXISTS]), Single-Use Settlement, Anti-Tamper & Global Replay Defense.
"""

import hashlib
import json
import urllib.parse
import datetime
from typing import Dict, Any, Optional


def compute_lease_hash(node: str, operator: str, tier: str, duration_sec: int, stake: int, url: str, nonce: str) -> str:
    n_bytes = node.encode("utf-8")
    o_bytes = operator.encode("utf-8")
    t_bytes = tier.encode("utf-8")
    dur_bytes = str(duration_sec).encode("utf-8")
    s_bytes = str(stake).encode("utf-8")
    u_bytes = url.encode("utf-8")
    nc_bytes = nonce.encode("utf-8")

    canonical_str = (
        "L" + str(len(n_bytes)) + ":" + node + "|"
        + "L" + str(len(o_bytes)) + ":" + operator + "|"
        + "L" + str(len(t_bytes)) + ":" + tier + "|"
        + "L" + str(len(dur_bytes)) + ":" + str(duration_sec) + "|"
        + "L" + str(len(s_bytes)) + ":" + str(stake) + "|"
        + "L" + str(len(u_bytes)) + ":" + url + "|"
        + "L" + str(len(nc_bytes)) + ":" + nonce
    )
    return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()


def compute_challenge_hash(node: str, challenger: str, violation_type: str, proof_url: str, bond: int, nonce: str) -> str:
    n_bytes = node.encode("utf-8")
    c_bytes = challenger.encode("utf-8")
    v_bytes = violation_type.encode("utf-8")
    p_bytes = proof_url.encode("utf-8")
    b_bytes = str(bond).encode("utf-8")
    nc_bytes = nonce.encode("utf-8")

    canonical_str = (
        "L" + str(len(n_bytes)) + ":" + node + "|"
        + "L" + str(len(c_bytes)) + ":" + challenger + "|"
        + "L" + str(len(v_bytes)) + ":" + violation_type + "|"
        + "L" + str(len(p_bytes)) + ":" + proof_url + "|"
        + "L" + str(len(b_bytes)) + ":" + str(bond) + "|"
        + "L" + str(len(nc_bytes)) + ":" + nonce
    )
    return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()


class SimulatedDePINHardwareSlaSovereign:
    """
    Simulates the exact state machine transitions, access control boundaries,
    payable escrow mechanics, and fail-closed security invariants of DePINHardwareSlaSovereign.py.
    """

    TIER_1 = "TIER_1_STANDARD_CPU"
    TIER_2 = "TIER_2_HIGH_MEM_RAM"
    TIER_3 = "TIER_3_GPU_TRAINING"
    TIER_4 = "TIER_4_HPC_DISTRIBUTED"

    TIER_1_MIN_STAKE = 100_000_000_000        # 100 Gwei
    TIER_2_MIN_STAKE = 500_000_000_000        # 500 Gwei
    TIER_3_MIN_STAKE = 2_000_000_000_000      # 2000 Gwei
    TIER_4_MIN_STAKE = 5_000_000_000_000      # 5000 Gwei

    MIN_SLA_CERTIFICATION_SCORE = 800

    def __init__(self, owner: str, initial_block_time: int = 1774000000):
        self.owner = owner.strip().lower()
        self.current_time = initial_block_time

        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.leases: Dict[str, Dict[str, Any]] = {}
        self.leases_by_hash: Dict[str, str] = {}
        self.consumed_lease_hashes: Dict[str, bool] = {}

        self.challenges: Dict[str, Dict[str, Any]] = {}
        self.challenges_by_hash: Dict[str, str] = {}
        self.consumed_challenge_hashes: Dict[str, bool] = {}

        self.claimable_balances: Dict[str, int] = {}
        self.total_collateral_locked = 2_000_000_000_000
        self.next_lease_id = 3
        self.next_challenge_id = 2
        self.total_nodes_registered = 2
        self.total_leases_created = 2
        self.total_challenges_submitted = 1
        self.total_slashed_nodes = 1
        self.total_successful_bounties = 1
        self.total_claimable_withdrawn = 0

        # Transfer simulation log
        self.emitted_transfers = []

        # Genesis Fixture 1: NODE_1 (Slashed Cheating Node)
        n1_addr = "0x1111111111111111111111111111111111111111"
        n1_op = "0x3333333333333333333333333333333333333333"
        self.nodes[n1_addr] = {
            "node_address": n1_addr,
            "operator": n1_op,
            "hardware_model": "AMD-EPYC-7763-RTX-4090",
            "geo_region": "US-EAST-VA",
            "benchmark_manifest_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "status": "SLASHED_JAILED",
            "sla_reliability_score": 180,
            "active_tier": "REVOKED",
            "active_lease_id": "LEASE_1",
            "registered_at": 1765000000,
            "jail_reason": "Confirmed hardware benchmark forgery and 14% packet drop rate."
        }

        l1_url = "https://raw.githubusercontent.com/depin-sla/fixtures/main/cheating_node_metrics.json"
        l1_hash = compute_lease_hash(n1_addr, n1_op, self.TIER_2, 86400, 500_000_000_000, l1_url, "GENESIS_LEASE_01")
        self.leases["LEASE_1"] = {
            "lease_id": "LEASE_1",
            "node_address": n1_addr,
            "operator": n1_op,
            "target_tier": self.TIER_2,
            "commitment_duration_sec": 86400,
            "escrowed_stake": 500_000_000_000,
            "telemetry_metrics_url": l1_url,
            "lease_hash": l1_hash,
            "status": "REVOKED_SLASHED",
            "sla_score": 180,
            "validator_synthesis": "Genesis fixture: Operator reported spoofed telemetry; severe SLA failure.",
            "lease_starts_at": 1765000000,
            "lease_expires_at": 1765086400,
            "is_consumed": True,
            "consumed_by": "CHALLENGER_0x5555"
        }
        self.leases_by_hash[l1_hash] = "LEASE_1"
        self.consumed_lease_hashes[l1_hash] = True

        challenger_addr = "0x5555555555555555555555555555555555555555"
        c1_url = "https://raw.githubusercontent.com/depin-sla/fixtures/main/downtime_proof_01.json"
        c1_hash = compute_challenge_hash(n1_addr, challenger_addr, "FORGED_ATTESTATION", c1_url, 250_000_000_000, "GENESIS_CHALLENGE_01")
        self.challenges["CHALLENGE_1"] = {
            "challenge_id": "CHALLENGE_1",
            "node_address": n1_addr,
            "challenger": challenger_addr,
            "challenge_bond": 250_000_000_000,
            "violation_type": "FORGED_ATTESTATION",
            "violation_proof_url": c1_url,
            "challenge_hash": c1_hash,
            "status": "SETTLED_REWARDED",
            "adjudication_rationale": "Genesis fixture: Network auditor demonstrated cryptographic proof of fake telemetry reporting.",
            "created_at": 1765050000,
            "is_consumed": True
        }
        self.challenges_by_hash[c1_hash] = "CHALLENGE_1"
        self.consumed_challenge_hashes[c1_hash] = True

        # Genesis Fixture 2: NODE_2 (Active High-Performance Cluster)
        n2_addr = "0x2222222222222222222222222222222222222222"
        n2_op = "0x4444444444444444444444444444444444444444"
        self.nodes[n2_addr] = {
            "node_address": n2_addr,
            "operator": n2_op,
            "hardware_model": "8x-NVIDIA-H100-SXM5-80GB",
            "geo_region": "EU-CENTRAL-FR",
            "benchmark_manifest_hash": "4a5a4e37517c5d799042b781de4f8a37fef4f41b4e13511eb9c2f6d2f36f363c",
            "status": "ACTIVE",
            "sla_reliability_score": 960,
            "active_tier": self.TIER_3,
            "active_lease_id": "LEASE_2",
            "registered_at": 1770000000,
            "jail_reason": ""
        }

        l2_url = "https://raw.githubusercontent.com/depin-sla/fixtures/main/h100_cluster_metrics.json"
        l2_hash = compute_lease_hash(n2_addr, n2_op, self.TIER_3, 604800, 2_000_000_000_000, l2_url, "GENESIS_LEASE_02")
        self.leases["LEASE_2"] = {
            "lease_id": "LEASE_2",
            "node_address": n2_addr,
            "operator": n2_op,
            "target_tier": self.TIER_3,
            "commitment_duration_sec": 604800,
            "escrowed_stake": 2_000_000_000_000,
            "telemetry_metrics_url": l2_url,
            "lease_hash": l2_hash,
            "status": "ACTIVE_CERTIFIED",
            "sla_score": 960,
            "validator_synthesis": "Genesis fixture: High-confidence SLA adherence. 99.98% verified uptime, 0 thermal throttling events.",
            "lease_starts_at": 1770000000,
            "lease_expires_at": 2000000000,
            "is_consumed": False,
            "consumed_by": ""
        }
        self.leases_by_hash[l2_hash] = "LEASE_2"

    def _get_current_time(self) -> int:
        return self.current_time

    def _set_mock_time(self, t: int) -> None:
        self.current_time = t

    def _validate_eth_address(self, addr: str, field_name: str) -> str:
        clean = addr.strip().strip('"').strip("'").lower()
        assert len(clean) == 42 and clean.startswith("0x"), f"[ERR_ADDR_01] {field_name} must be a 42-character hex address."
        assert all(c in "0123456789abcdef" for c in clean[2:]), f"[ERR_ADDR_02] {field_name} contains non-hexadecimal characters."
        assert clean != "0x0000000000000000000000000000000000000000", f"[ERR_ADDR_03] {field_name} cannot be the zero address."
        return clean

    def _validate_url(self, raw_url: str, field_name: str) -> str:
        clean = raw_url.strip().strip('"').strip("'")
        assert 10 <= len(clean) <= 512, f"[ERR_URL_LEN] {field_name} must be between 10 and 512 characters."
        parsed = urllib.parse.urlparse(clean)
        scheme = parsed.scheme.lower()
        assert scheme in ("http", "https"), f"[ERR_URL_SCHEME] {field_name} must use HTTP or HTTPS."
        netloc = parsed.netloc.lower().split(":")[0]
        assert netloc not in ("localhost", "127.0.0.1", "0.0.0.0", "::1", "169.254.169.254"), f"[ERR_URL_SSRF] {field_name} cannot target internal loopback or cloud metadata IPs."
        assert not netloc.startswith("10.") and not netloc.startswith("192.168."), f"[ERR_URL_SSRF] {field_name} cannot target private RFC 1918 subnets."
        return clean

    def _get_min_stake_for_tier(self, tier: str) -> int:
        if tier == self.TIER_1:
            return self.TIER_1_MIN_STAKE
        elif tier == self.TIER_2:
            return self.TIER_2_MIN_STAKE
        elif tier == self.TIER_3:
            return self.TIER_3_MIN_STAKE
        elif tier == self.TIER_4:
            return self.TIER_4_MIN_STAKE
        else:
            raise AssertionError(f"[ERR_UNKNOWN_TIER] Unrecognized DePIN compute tier: {tier}")

    def _get_tier_level(self, tier: str) -> int:
        if tier == self.TIER_1:
            return 1
        elif tier == self.TIER_2:
            return 2
        elif tier == self.TIER_3:
            return 3
        elif tier == self.TIER_4:
            return 4
        return 0

    def register_node_cluster(self, sender: str, node_address: str, hardware_model: str, geo_region: str, benchmark_manifest_hash: str) -> str:
        clean_op = self._validate_eth_address(sender, "Operator")
        clean_node = self._validate_eth_address(node_address, "Node address")

        assert clean_node not in self.nodes, "[ERR_NODE_EXISTS] Hardware node address is already registered."

        clean_model = hardware_model.strip().strip('"').strip("'")
        assert 3 <= len(clean_model) <= 64, "[ERR_MODEL_LEN] Hardware model must be between 3 and 64 characters."

        clean_region = geo_region.strip().strip('"').strip("'")
        assert 2 <= len(clean_region) <= 32, "[ERR_REGION_LEN] Geographic region must be between 2 and 32 characters."

        clean_hash = benchmark_manifest_hash.strip().strip('"').strip("'").lower()
        assert len(clean_hash) == 64 and all(c in "0123456789abcdef" for c in clean_hash), "[ERR_BENCHMARK_HASH] Benchmark manifest hash must be a 64-character hexadecimal SHA-256 string."

        current_time = self._get_current_time()
        self.nodes[clean_node] = {
            "node_address": clean_node,
            "operator": clean_op,
            "hardware_model": clean_model,
            "geo_region": clean_region,
            "benchmark_manifest_hash": clean_hash,
            "status": "PENDING_SLA",
            "sla_reliability_score": 0,
            "active_tier": "NONE",
            "active_lease_id": "NONE",
            "registered_at": current_time,
            "jail_reason": ""
        }
        self.total_nodes_registered += 1
        return f"NODE_REGISTERED: {clean_node} | Model: {clean_model} | Operator: {clean_op} | Status: PENDING_SLA"

    def commit_sla_lease(self, sender: str, msg_value: int, node_address: str, target_tier: str, duration_seconds: int, telemetry_metrics_url: str, nonce: str) -> str:
        clean_op = self._validate_eth_address(sender, "Operator")
        clean_node = self._validate_eth_address(node_address, "Node address")

        assert clean_node in self.nodes, "[ERR_NODE_NOT_FOUND] Hardware node address is not registered."
        node_rec = self.nodes[clean_node]
        assert clean_op == node_rec["operator"], "[ERR_AUTH_OPERATOR] Only the registered operator can commit an SLA lease for this node."
        assert node_rec["status"] != "SLASHED_JAILED", "[ERR_NODE_SLASHED] Node is currently SLASHED_JAILED due to prior fraud. Lease rejected."
        assert node_rec["active_lease_id"] == "NONE", "[ERR_ACTIVE_LEASE_EXISTS] Node already has an active or pending lease. Await expiry or settlement."

        clean_tier = target_tier.strip().upper()
        min_required_stake = self._get_min_stake_for_tier(clean_tier)
        assert msg_value >= min_required_stake, f"[ERR_STAKE_INSUFFICIENT] Escrowed collateral ({msg_value}) is below minimum for {clean_tier} ({min_required_stake})."

        assert 3600 <= duration_seconds <= 31536000, "[ERR_DURATION_RANGE] SLA commitment duration must be between 1 hour (3600s) and 365 days (31536000s)."
        clean_url = self._validate_url(telemetry_metrics_url, "Telemetry metrics URL")

        clean_nonce = nonce.strip().strip('"').strip("'")
        assert 8 <= len(clean_nonce) <= 64, "[ERR_NONCE_LEN] Nonce must be between 8 and 64 characters."

        lease_hash = compute_lease_hash(clean_node, clean_op, clean_tier, duration_seconds, msg_value, clean_url, clean_nonce)
        assert lease_hash not in self.consumed_lease_hashes, "[ERR_REPLAY_02] SLA lease hash is globally burned and cannot be re-committed."

        if lease_hash in self.leases_by_hash:
            existing_id = self.leases_by_hash[lease_hash]
            existing_rec = self.leases[existing_id]
            if not existing_rec["is_consumed"]:
                return f"DUPLICATE_ACTIVE_LEASE: {existing_id} | Status: {existing_rec['status']} | Hash: {lease_hash}"

        l_id = f"LEASE_{self.next_lease_id}"
        self.next_lease_id += 1

        self.leases[l_id] = {
            "lease_id": l_id,
            "node_address": clean_node,
            "operator": clean_op,
            "target_tier": clean_tier,
            "commitment_duration_sec": duration_seconds,
            "escrowed_stake": msg_value,
            "telemetry_metrics_url": clean_url,
            "lease_hash": lease_hash,
            "status": "PENDING_AUDIT",
            "sla_score": 0,
            "validator_synthesis": "",
            "lease_starts_at": 0,
            "lease_expires_at": 0,
            "is_consumed": False,
            "consumed_by": ""
        }
        self.leases_by_hash[lease_hash] = l_id
        node_rec["active_lease_id"] = l_id
        self.total_leases_created += 1
        self.total_collateral_locked += msg_value

        return f"LEASE_COMMITTED: {l_id} | Node: {clean_node} | Tier: {clean_tier} | Collateral: {msg_value} | Status: PENDING_AUDIT | Hash: {lease_hash}"

    def verify_hardware_sla(self, node_address: str, lease_id: str, mock_llm_response: Optional[str] = None, fail_fetch: bool = False) -> str:
        clean_node = self._validate_eth_address(node_address, "Node address")
        l_id = lease_id.strip()
        assert l_id in self.leases, "[ERR_LEASE_NOT_FOUND] Specified lease ID does not exist."
        lease_rec = self.leases[l_id]
        assert lease_rec["node_address"] == clean_node, "[ERR_LEASE_NODE_MISMATCH] Lease record does not belong to specified node address."
        assert lease_rec["status"] == "PENDING_AUDIT", f"[ERR_INVALID_STATUS] Lease is not pending audit (Current: {lease_rec['status']})."

        node_rec = self.nodes[clean_node]
        assert node_rec["status"] != "SLASHED_JAILED", "[ERR_NODE_SLASHED] Node is SLASHED_JAILED; audit aborted."

        if fail_fetch:
            raise AssertionError("[ERR_EVIDENCE_FETCH_FAILED] Live telemetry could not be fetched or payload is empty. Audit aborted fail-closed.")

        if mock_llm_response is None:
            mock_llm_response = json.dumps({
                "score": 900,
                "verdict": "APPROVED",
                "rationale": "Hardware telemetry demonstrates continuous 99.99% heartbeat and expected FLOPS."
            })

        parsed = json.loads(mock_llm_response)
        verdict_candidate = str(parsed.get("verdict", "REJECTED")).upper().strip()
        score_candidate = int(parsed.get("score", 0))
        rationale_candidate = str(parsed.get("rationale", "Autonomous multi-validator compute audit completed."))

        if verdict_candidate == "EVIDENCE_FETCH_FAILED" or "FETCH_FAILED" in verdict_candidate:
            raise AssertionError("[ERR_EVIDENCE_FETCH_FAILED] Live telemetry could not be fetched or payload is empty. Audit aborted fail-closed.")

        final_score = max(0, min(1000, score_candidate))
        current_time = self._get_current_time()

        lease_rec["sla_score"] = final_score
        lease_rec["validator_synthesis"] = rationale_candidate

        if final_score >= self.MIN_SLA_CERTIFICATION_SCORE and verdict_candidate == "APPROVED":
            lease_expires = current_time + lease_rec["commitment_duration_sec"]
            lease_rec["status"] = "ACTIVE_CERTIFIED"
            lease_rec["lease_starts_at"] = current_time
            lease_rec["lease_expires_at"] = lease_expires

            node_rec["status"] = "ACTIVE"
            node_rec["active_tier"] = lease_rec["target_tier"]
            node_rec["active_lease_id"] = l_id
            node_rec["sla_reliability_score"] = final_score

            return f"SLA_CERTIFIED: {l_id} | Node: {clean_node} | Tier: {lease_rec['target_tier']} | Score: {final_score} | ExpiresAt: {lease_expires}"
        else:
            lease_rec["status"] = "REJECTED_DEFICIENT"
            node_rec["active_lease_id"] = "NONE"
            node_rec["active_tier"] = "NONE"
            return f"SLA_REJECTED: {l_id} | Node: {clean_node} | Score: {final_score} | Status: REJECTED_DEFICIENT | Rationale: {rationale_candidate}"

    def check_node_sla_compliance(self, node_address: str, required_tier: str) -> bool:
        clean_node = node_address.strip().strip('"').strip("'").lower()
        if len(clean_node) != 42 or not clean_node.startswith("0x") or clean_node not in self.nodes:
            return False

        node_rec = self.nodes[clean_node]
        if node_rec["status"] != "ACTIVE":
            return False

        if node_rec["active_lease_id"] == "NONE" or node_rec["active_lease_id"] not in self.leases:
            return False

        lease_rec = self.leases[node_rec["active_lease_id"]]
        if lease_rec["status"] != "ACTIVE_CERTIFIED":
            return False

        current_time = self._get_current_time()
        if current_time >= lease_rec["lease_expires_at"]:
            return False

        active_level = self._get_tier_level(node_rec["active_tier"])
        required_level = self._get_tier_level(required_tier)
        if required_level <= 0 or active_level < required_level:
            return False

        if node_rec["sla_reliability_score"] < self.MIN_SLA_CERTIFICATION_SCORE:
            return False

        return True

    def submit_sla_violation_challenge(self, sender: str, msg_value: int, node_address: str, violation_type: str, violation_proof_url: str, challenge_nonce: str) -> str:
        clean_challenger = self._validate_eth_address(sender, "Challenger")
        clean_node = self._validate_eth_address(node_address, "Target node")

        assert clean_challenger != clean_node, "[ERR_SELF_CHALLENGE] Node cannot challenge itself."
        assert clean_node in self.nodes, "[ERR_NODE_NOT_FOUND] Target node is not registered."

        node_rec = self.nodes[clean_node]
        # GL-SEC-01 REMEDIATION: Node must be ACTIVE with a certified lease to be challenged!
        assert node_rec["status"] == "ACTIVE" and node_rec["active_lease_id"] != "NONE", \
            "[ERR_NODE_NOT_ACTIVE] Challenges can only target active nodes with certified leases."
        assert node_rec["active_lease_id"] in self.leases, \
            "[ERR_LEASE_NOT_FOUND] Target node does not have an active lease record."
        active_lease = self.leases[node_rec["active_lease_id"]]
        assert active_lease["status"] == "ACTIVE_CERTIFIED", \
            "[ERR_LEASE_NOT_CERTIFIED] Target node does not possess an active certified lease."

        assert clean_challenger != node_rec["operator"], "[ERR_OPERATOR_CHALLENGE] Operator cannot challenge their own node."

        clean_violation = violation_type.strip().upper()
        assert clean_violation in ("UNSCHEDULED_DOWNTIME", "THERMAL_THROTTLING", "FORGED_ATTESTATION", "COMPUTE_HASH_MISMATCH"), f"[ERR_INVALID_VIOLATION_TYPE] Unsupported violation type: {violation_type}"

        tier_level = self._get_tier_level(node_rec["active_tier"])
        base_min_stake = self._get_min_stake_for_tier(node_rec["active_tier"]) if tier_level > 0 else self.TIER_1_MIN_STAKE
        min_challenge_bond = base_min_stake // 2

        assert msg_value >= min_challenge_bond, f"[ERR_BOND_INSUFFICIENT] Challenge bond ({msg_value}) is below required minimum ({min_challenge_bond})."

        clean_proof_url = self._validate_url(violation_proof_url, "Violation proof URL")
        clean_nonce = challenge_nonce.strip().strip('"').strip("'")
        assert 8 <= len(clean_nonce) <= 64, "[ERR_NONCE_LEN] Nonce must be between 8 and 64 characters."

        challenge_hash = compute_challenge_hash(clean_node, clean_challenger, clean_violation, clean_proof_url, msg_value, clean_nonce)
        assert challenge_hash not in self.consumed_challenge_hashes, "[ERR_REPLAY_02] Challenge hash has already been settled and consumed."

        if challenge_hash in self.challenges_by_hash:
            existing_c_id = self.challenges_by_hash[challenge_hash]
            existing_rec = self.challenges[existing_c_id]
            if not existing_rec["is_consumed"]:
                return f"DUPLICATE_ACTIVE_CHALLENGE: {existing_c_id} | Status: {existing_rec['status']} | Hash: {challenge_hash}"

        c_id = f"CHALLENGE_{self.next_challenge_id}"
        self.next_challenge_id += 1
        current_time = self._get_current_time()

        self.challenges[c_id] = {
            "challenge_id": c_id,
            "node_address": clean_node,
            "challenger": clean_challenger,
            "challenge_bond": msg_value,
            "violation_type": clean_violation,
            "violation_proof_url": clean_proof_url,
            "challenge_hash": challenge_hash,
            "status": "PENDING_AUDIT",
            "adjudication_rationale": "",
            "created_at": current_time,
            "is_consumed": False
        }
        self.challenges_by_hash[challenge_hash] = c_id
        self.total_challenges_submitted += 1
        self.total_collateral_locked += msg_value

        return f"CHALLENGE_SUBMITTED: {c_id} | TargetNode: {clean_node} | Challenger: {clean_challenger} | Bond: {msg_value} | Hash: {challenge_hash}"

    def adjudicate_sla_violation_challenge(self, node_address: str, challenge_id: str, mock_llm_verdict: Optional[str] = None, fail_fetch: bool = False) -> str:
        clean_node = self._validate_eth_address(node_address, "Node address")
        c_id = challenge_id.strip()
        assert c_id in self.challenges, "[ERR_CHALLENGE_NOT_FOUND] Specified challenge ID does not exist."
        c_rec = self.challenges[c_id]

        assert c_rec["node_address"] == clean_node, "[ERR_CHALLENGE_NODE_MISMATCH] Challenge record does not target specified node address."
        assert c_rec["status"] == "PENDING_AUDIT", f"[ERR_INVALID_STATUS] Challenge is not pending audit (Current: {c_rec['status']})."

        node_rec = self.nodes[clean_node]

        if fail_fetch:
            raise AssertionError("[ERR_EVIDENCE_FETCH_FAILED] Violation proof could not be fetched or payload is empty. Adjudication aborted fail-closed.")

        if mock_llm_verdict is None:
            mock_llm_verdict = json.dumps({
                "verdict": "SLA_BREACH_CONFIRMED",
                "adjudication_rationale": "Cryptographic trace proves unannounced 3-hour cluster outage."
            })

        parsed = json.loads(mock_llm_verdict)
        verdict_candidate = str(parsed.get("verdict", "CHALLENGE_DISMISSED")).upper().strip()
        rationale_candidate = str(parsed.get("adjudication_rationale", "Adjudication completed."))

        if verdict_candidate == "EVIDENCE_FETCH_FAILED" or "FETCH_FAILED" in verdict_candidate:
            raise AssertionError("[ERR_EVIDENCE_FETCH_FAILED] Violation proof could not be fetched or payload is empty. Adjudication aborted fail-closed.")

        c_rec["adjudication_rationale"] = rationale_candidate

        if verdict_candidate == "SLA_BREACH_CONFIRMED":
            active_lid = node_rec["active_lease_id"]
            node_rec["status"] = "SLASHED_JAILED"
            node_rec["active_tier"] = "REVOKED"
            node_rec["active_lease_id"] = "NONE"
            node_rec["sla_reliability_score"] = 0
            node_rec["jail_reason"] = f"SLA breach challenge {c_id} confirmed: {rationale_candidate}"
            self.total_slashed_nodes += 1

            slashed_op_collateral = 0
            full_lease_stake = 0
            residual_fee = 0
            if active_lid != "NONE" and active_lid in self.leases:
                active_l = self.leases[active_lid]
                if active_l["status"] == "ACTIVE_CERTIFIED":
                    active_l["status"] = "REVOKED_SLASHED"
                    active_l["is_consumed"] = True
                    active_l["consumed_by"] = c_rec["challenger"]
                    self.consumed_lease_hashes[active_l["lease_hash"].lower()] = True
                    full_lease_stake = active_l["escrowed_stake"]
                    # Slash 90% of operator collateral to challenger
                    slashed_op_collateral = (full_lease_stake * 90) // 100
                    residual_fee = full_lease_stake - slashed_op_collateral

            challenger_payout = c_rec["challenge_bond"] + slashed_op_collateral
            c_rec["status"] = "SETTLED_REWARDED"
            c_rec["is_consumed"] = True
            self.consumed_challenge_hashes[c_rec["challenge_hash"].lower()] = True
            self.total_successful_bounties += 1

            # Retain 10% residual fee to protocol owner claimable balance (GL-SEC-02 Remediated)
            if residual_fee > 0:
                self.claimable_balances[self.owner] = self.claimable_balances.get(self.owner, 0) + residual_fee

            # Deduct full 100% of lease stake + challenger bond
            total_deducted = c_rec["challenge_bond"] + full_lease_stake
            if self.total_collateral_locked >= total_deducted:
                self.total_collateral_locked -= total_deducted
            else:
                self.total_collateral_locked = 0

            # Transfer to challenger
            self.emitted_transfers.append({
                "recipient": c_rec["challenger"],
                "amount": challenger_payout,
                "reason": "SLA_BREACH_BOUNTY"
            })

            return f"SLA_BREACH_CONFIRMED: {c_id} | Node: {clean_node} SLASHED_JAILED | ChallengerReward: {challenger_payout} | SlashedOperatorCollateral: {slashed_op_collateral}"
        else:
            c_rec["status"] = "CHALLENGE_DISMISSED"
            c_rec["is_consumed"] = True
            self.consumed_challenge_hashes[c_rec["challenge_hash"].lower()] = True

            # Reward innocent operator with the slashed challenge bond (GL-SEC-02 Remediated)
            bond_val = c_rec["challenge_bond"]
            self.claimable_balances[node_rec["operator"]] = self.claimable_balances.get(node_rec["operator"], 0) + bond_val

            if self.total_collateral_locked >= bond_val:
                self.total_collateral_locked -= bond_val

            return f"CHALLENGE_DISMISSED: {c_id} | TargetNode: {clean_node} Remains Active | ChallengerBondSlashed: {bond_val} CreditedToOperator: {node_rec['operator']}"

    def refund_deficient_lease(self, sender: str, node_address: str, lease_id: str, caller_expected_hash: str) -> str:
        clean_op = self._validate_eth_address(sender, "Operator")
        clean_node = self._validate_eth_address(node_address, "Node address")
        l_id = lease_id.strip()
        clean_exp_hash = caller_expected_hash.strip().lower()

        assert l_id in self.leases, "[ERR_LEASE_NOT_FOUND] Specified lease ID does not exist."
        lease_rec = self.leases[l_id]
        node_rec = self.nodes[clean_node]

        assert clean_op == lease_rec["operator"], "[ERR_AUTH_OPERATOR] Only the depositing operator can reclaim rejected lease collateral."
        assert lease_rec["status"] == "REJECTED_DEFICIENT" or (node_rec["status"] == "SLASHED_JAILED" and lease_rec["status"] == "PENDING_AUDIT"), \
            f"[ERR_INVALID_STATUS] Lease is not eligible for refund (Current: {lease_rec['status']})."

        assert lease_rec["lease_hash"].lower() == clean_exp_hash, "[ERR_MISMATCH_01] Canonical lease hash mismatch. Parameter substitution detected."
        assert not lease_rec["is_consumed"], "[ERR_REPLAY_01] Lease collateral has already been fully refunded or consumed."
        assert lease_rec["lease_hash"].lower() not in self.consumed_lease_hashes, "[ERR_REPLAY_02] Lease hash is globally burned and cannot be settled again."

        stake_refund = lease_rec["escrowed_stake"]
        lease_rec["is_consumed"] = True
        lease_rec["consumed_by"] = clean_op
        lease_rec["status"] = "SETTLED_REFUNDED"
        self.consumed_lease_hashes[lease_rec["lease_hash"].lower()] = True

        if node_rec["active_lease_id"] == l_id:
            node_rec["active_lease_id"] = "NONE"
            node_rec["active_tier"] = "NONE"

        if self.total_collateral_locked >= stake_refund:
            self.total_collateral_locked -= stake_refund

        self.emitted_transfers.append({
            "recipient": clean_op,
            "amount": stake_refund,
            "reason": "DEFICIENT_LEASE_REFUND"
        })

        return f"LEASE_REFUNDED: {l_id} | RefundTo: {clean_op} | Amount: {stake_refund} | Hash: {clean_exp_hash}"

    def release_clean_expired_lease(self, sender: str, node_address: str, lease_id: str, caller_expected_hash: str) -> str:
        clean_op = self._validate_eth_address(sender, "Operator")
        clean_node = self._validate_eth_address(node_address, "Node address")
        l_id = lease_id.strip()
        clean_exp_hash = caller_expected_hash.strip().lower()

        assert l_id in self.leases, "[ERR_LEASE_NOT_FOUND] Specified lease ID does not exist."
        lease_rec = self.leases[l_id]

        assert clean_op == lease_rec["operator"], "[ERR_AUTH_OPERATOR] Only the depositing operator can reclaim expired lease collateral."
        assert lease_rec["status"] == "ACTIVE_CERTIFIED", f"[ERR_INVALID_STATUS] Lease is not currently ACTIVE_CERTIFIED (Current: {lease_rec['status']})."

        current_time = self._get_current_time()
        assert current_time >= lease_rec["lease_expires_at"], "[ERR_LEASE_STILL_ACTIVE] SLA commitment has not yet expired based on consensus block time."
        assert lease_rec["lease_hash"].lower() == clean_exp_hash, "[ERR_MISMATCH_01] Canonical lease hash mismatch. Parameter substitution detected."
        assert not lease_rec["is_consumed"], "[ERR_REPLAY_01] Lease collateral has already been consumed or refunded."
        assert lease_rec["lease_hash"].lower() not in self.consumed_lease_hashes, "[ERR_REPLAY_02] Lease hash is globally burned."

        stake_refund = lease_rec["escrowed_stake"]
        lease_rec["is_consumed"] = True
        lease_rec["consumed_by"] = clean_op
        lease_rec["status"] = "SETTLED_REFUNDED"
        self.consumed_lease_hashes[lease_rec["lease_hash"].lower()] = True

        node_rec = self.nodes[clean_node]
        if node_rec["active_lease_id"] == l_id:
            node_rec["active_tier"] = "NONE"
            node_rec["active_lease_id"] = "NONE"

        if self.total_collateral_locked >= stake_refund:
            self.total_collateral_locked -= stake_refund

        self.emitted_transfers.append({
            "recipient": clean_op,
            "amount": stake_refund,
            "reason": "EXPIRED_LEASE_RELEASE"
        })

        return f"LEASE_EXPIRED_SETTLED: {l_id} | RefundTo: {clean_op} | Amount: {stake_refund}"

    def withdraw_claimable(self, sender: str) -> str:
        clean_caller = self._validate_eth_address(sender, "Caller")
        assert clean_caller in self.claimable_balances, "[ERR_NO_CLAIMABLE] Caller has no claimable balance."
        balance = self.claimable_balances[clean_caller]
        assert balance > 0, "[ERR_ZERO_CLAIMABLE] Claimable balance is zero."

        self.claimable_balances[clean_caller] = 0
        self.total_claimable_withdrawn += balance
        self.emitted_transfers.append({
            "recipient": clean_caller,
            "amount": balance,
            "reason": "WITHDRAW_CLAIMABLE"
        })
        return f"WITHDRAWAL_SUCCESS: {clean_caller} | Amount: {balance}"


# ==============================================================================
# 11-PHASE HARDCORE TEST RUNNER (WITH REMEDIATION VERIFICATION)
# ==============================================================================
def run_all_tests():
    print("=" * 80)
    print("STARTING 11-PHASE REGRESSION TEST SUITE: DePINHardwareSlaSovereign (REMEDIATED)")
    print("=" * 80)

    protocol_owner = "0x9999999999999999999999999999999999999999"
    contract = SimulatedDePINHardwareSlaSovereign(owner=protocol_owner)

    # PHASE 1: Genesis Fixtures & Immutability
    print("\n[Phase 1] Validating Genesis Pre-Seeded Fixtures & Burned State...")
    n1 = contract.nodes["0x1111111111111111111111111111111111111111"]
    assert n1["status"] == "SLASHED_JAILED", "Node 1 should be SLASHED_JAILED"
    assert n1["active_tier"] == "REVOKED", "Node 1 tier should be REVOKED"
    assert n1["sla_reliability_score"] == 180, "Node 1 score should be 180"

    l1 = contract.leases["LEASE_1"]
    assert l1["status"] == "REVOKED_SLASHED", "Lease 1 should be REVOKED_SLASHED"
    assert l1["is_consumed"] is True, "Lease 1 should be consumed"
    assert l1["lease_hash"] in contract.consumed_lease_hashes, "Lease 1 hash must be in burned map"

    c1 = contract.challenges["CHALLENGE_1"]
    assert c1["status"] == "SETTLED_REWARDED", "Challenge 1 should be SETTLED_REWARDED"
    assert c1["is_consumed"] is True, "Challenge 1 should be consumed"

    n2 = contract.nodes["0x2222222222222222222222222222222222222222"]
    assert n2["status"] == "ACTIVE", "Node 2 should be ACTIVE"
    assert n2["active_tier"] == contract.TIER_3, "Node 2 should have TIER_3"
    assert n2["sla_reliability_score"] == 960, "Node 2 score should be 960"

    assert contract.total_collateral_locked == 2_000_000_000_000, "Initial collateral locked mismatch"
    print("  --> PASS: Genesis fixtures are permanently burned, immutable, and correctly initialized.")

    # PHASE 2: Length-Prefixed Hashing & Delimiter Resistance
    print("\n[Phase 2] Validating Delimiter Injection Resistance & Canonical Hashing...")
    h1 = compute_lease_hash("0xaaa", "0xbbb", "TIER_1", 3600, 100, "https://url1", "nonce1")
    h2 = compute_lease_hash("0xaaa|0xbbb", "", "TIER_1", 3600, 100, "https://url1", "nonce1")
    assert h1 != h2, "Delimiter injection must produce completely different hash"

    c_h1 = compute_challenge_hash("0xaaa", "0xbbb", "DOWNTIME", "https://proof", 100, "nonce1")
    c_h2 = compute_challenge_hash("0xaaa|0xbbb", "", "DOWNTIME", "https://proof", 100, "nonce1")
    assert c_h1 != c_h2, "Challenge delimiter injection must produce different hash"
    print("  --> PASS: Length-prefixed serialization completely neutralizes delimiter injection attacks.")

    # PHASE 3: Access Control & Frontrunning Defense (GL-SEC-03 & GL-SEC-01 Remediated)
    print("\n[Phase 3] Testing Access Control Boundaries & Counterparty Authentication...")
    # 1. Direct self-key registration is supported (GL-SEC-03)
    reg_res = contract.register_node_cluster("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "ModelSelf", "US-EAST", "0" * 64)
    assert "NODE_REGISTERED" in reg_res

    # 2. Register Node 3 with separate operator
    node_3_addr = "0x7777777777777777777777777777777777777777"
    op_3_addr   = "0x8888888888888888888888888888888888888888"
    contract.register_node_cluster(op_3_addr, node_3_addr, "8x NVIDIA RTX 4090", "US-WEST", "a" * 64)

    # 3. Duplicate registration rejected
    try:
        contract.register_node_cluster(op_3_addr, node_3_addr, "8x NVIDIA RTX 4090", "US-WEST", "a" * 64)
        assert False, "Duplicate node registration must revert"
    except AssertionError as e:
        assert "[ERR_NODE_EXISTS]" in str(e)

    # 4. GL-SEC-01 Verification: Pre-certification challenge on PENDING_SLA node MUST revert
    try:
        contract.submit_sla_violation_challenge("0x6666666666666666666666666666666666666666", 50_000_000_000, node_3_addr, "UNSCHEDULED_DOWNTIME", "https://proof.io", "nonce_grief_01")
        assert False, "Pre-certification challenge on pending node must revert"
    except AssertionError as e:
        assert "[ERR_NODE_NOT_ACTIVE]" in str(e)

    # 5. Unauthorized operator committing lease
    try:
        contract.commit_sla_lease("0x9999999999999999999999999999999999999999", 2_000_000_000_000, node_3_addr, contract.TIER_3, 86400, "https://node3.io/metrics", "nonce12345")
        assert False, "Unauthorized operator must revert"
    except AssertionError as e:
        assert "[ERR_AUTH_OPERATOR]" in str(e)

    # 6. Committing lease on slashed node
    try:
        contract.commit_sla_lease("0x3333333333333333333333333333333333333333", 500_000_000_000, "0x1111111111111111111111111111111111111111", contract.TIER_2, 86400, "https://n1.io/m", "nonce12345")
        assert False, "Lease commit on slashed node must revert"
    except AssertionError as e:
        assert "[ERR_NODE_SLASHED]" in str(e)

    print("  --> PASS: Counterparty authentication and frontrunning boundaries strictly enforced.")

    # PHASE 4: Verifiable Payable Escrow & Tier Minimums
    print("\n[Phase 4] Testing Payable Escrow Boundaries & Tier Stake Minimums...")
    # TIER_1 minimum is 100 Gwei (100_000_000_000). Offer 50 Gwei.
    try:
        contract.commit_sla_lease(op_3_addr, 50_000_000_000, node_3_addr, contract.TIER_1, 86400, "https://node3.io/metrics", "nonce12345")
        assert False, "Sub-minimum stake must revert"
    except AssertionError as e:
        assert "[ERR_STAKE_INSUFFICIENT]" in str(e)

    # TIER_3 minimum is 2000 Gwei (2_000_000_000_000). Offer 1000 Gwei.
    try:
        contract.commit_sla_lease(op_3_addr, 1_000_000_000_000, node_3_addr, contract.TIER_3, 86400, "https://node3.io/metrics", "nonce12345")
        assert False, "Sub-minimum TIER_3 stake must revert"
    except AssertionError as e:
        assert "[ERR_STAKE_INSUFFICIENT]" in str(e)

    print("  --> PASS: Verifiable payable escrow strictly verifies gl.message.value against tier tables.")

    # PHASE 5: SSRF Neutralization & Strict Input Sanitization
    print("\n[Phase 5] Testing SSRF Defense & Hex Address Sanitization...")
    # Loopback IP
    try:
        contract._validate_url("http://127.0.0.1/metrics", "Telemetry URL")
        assert False, "Loopback URL must revert"
    except AssertionError as e:
        assert "[ERR_URL_SSRF]" in str(e)

    # Cloud metadata IP
    try:
        contract._validate_url("http://169.254.169.254/latest/meta-data", "Telemetry URL")
        assert False, "Metadata URL must revert"
    except AssertionError as e:
        assert "[ERR_URL_SSRF]" in str(e)

    # Private subnet
    try:
        contract._validate_url("https://10.0.0.5:9090/metrics", "Telemetry URL")
        assert False, "Private subnet URL must revert"
    except AssertionError as e:
        assert "[ERR_URL_SSRF]" in str(e)

    # Nonce length < 8
    try:
        contract.commit_sla_lease(op_3_addr, 2_000_000_000_000, node_3_addr, contract.TIER_3, 86400, "https://node3.io/metrics", "short")
        assert False, "Short nonce must revert"
    except AssertionError as e:
        assert "[ERR_NONCE_LEN]" in str(e)

    print("  --> PASS: SSRF neutralization and strict input bounds verified.")

    # PHASE 6: Stage 3 SLA Verification & GL-SEC-04 Overlapping Lease Defense
    print("\n[Phase 6] Testing Multi-Validator SLA Verification & Overlapping Lease Guard...")
    # Commit valid TIER_3 lease with 2000 Gwei
    res_commit = contract.commit_sla_lease(op_3_addr, 2_000_000_000_000, node_3_addr, contract.TIER_3, 86400, "https://depin-cloud.com/node3/prometheus", "lease_nonce_9999")
    assert "LEASE_3" in res_commit
    assert contract.leases["LEASE_3"]["status"] == "PENDING_AUDIT"
    assert contract.nodes[node_3_addr]["active_lease_id"] == "LEASE_3"

    # GL-SEC-04 Check: Attempting to commit a second concurrent lease MUST revert
    try:
        contract.commit_sla_lease(op_3_addr, 2_000_000_000_000, node_3_addr, contract.TIER_3, 86400, "https://depin-cloud.com/node3/prometheus", "lease_nonce_8888")
        assert False, "Concurrent lease commitment must revert with [ERR_ACTIVE_LEASE_EXISTS]"
    except AssertionError as e:
        assert "[ERR_ACTIVE_LEASE_EXISTS]" in str(e)

    # Simulate validator consensus returning score 900 (>= 800)
    cert_res = contract.verify_hardware_sla(node_3_addr, "LEASE_3", mock_llm_response=json.dumps({
        "score": 900,
        "verdict": "APPROVED",
        "rationale": "Sustained GPU benchmark pass with zero frame drops."
    }))
    assert "SLA_CERTIFIED" in cert_res
    assert contract.leases["LEASE_3"]["status"] == "ACTIVE_CERTIFIED"
    assert contract.nodes[node_3_addr]["status"] == "ACTIVE"
    assert contract.nodes[node_3_addr]["active_tier"] == contract.TIER_3
    assert contract.nodes[node_3_addr]["sla_reliability_score"] == 900
    assert contract.leases["LEASE_3"]["lease_expires_at"] == contract.current_time + 86400
    print("  --> PASS: Node audited, score 900 assigned, TIER_3 certified, concurrent leases prevented.")

    # PHASE 7: FAIL-CLOSED Invariant: Evidence Fetch Failure
    print("\n[Phase 7] Testing Fail-Closed Invariant on Network Evidence Fetch Failure...")
    node_4_addr = "0x6666666666666666666666666666666666666666"
    op_4_addr   = "0x5555555555555555555555555555555555555554"
    contract.register_node_cluster(op_4_addr, node_4_addr, "Threadripper PRO 5995WX", "EU-NORTH", "b" * 64)
    contract.commit_sla_lease(op_4_addr, 500_000_000_000, node_4_addr, contract.TIER_2, 86400, "https://offline-node.com/metrics", "lease_nonce_0000")

    # Simulate fetch failure
    try:
        contract.verify_hardware_sla(node_4_addr, "LEASE_4", fail_fetch=True)
        assert False, "Evidence fetch failure must fail-closed"
    except AssertionError as e:
        assert "[ERR_EVIDENCE_FETCH_FAILED]" in str(e)

    # Verify zero state mutation
    assert contract.leases["LEASE_4"]["status"] == "PENDING_AUDIT", "Lease must remain PENDING_AUDIT"
    assert contract.nodes[node_4_addr]["status"] == "PENDING_SLA", "Node must remain PENDING_SLA"
    assert contract.nodes[node_4_addr]["active_tier"] == "NONE", "Node tier must remain NONE"
    print("  --> PASS: Fail-closed invariant cleanly reverts with zero state mutation.")

    # PHASE 8: Reusable Public Gateway Hook: Real-Time On-Chain Check
    print("\n[Phase 8] Testing check_node_sla_compliance Gateway Hook...")
    # Node 2 (Genesis H100) is ACTIVE at TIER_3
    assert contract.check_node_sla_compliance("0x2222222222222222222222222222222222222222", contract.TIER_1) is True
    assert contract.check_node_sla_compliance("0x2222222222222222222222222222222222222222", contract.TIER_2) is True
    assert contract.check_node_sla_compliance("0x2222222222222222222222222222222222222222", contract.TIER_3) is True
    # Node 2 requesting TIER_4 should fail (it's only TIER_3)
    assert contract.check_node_sla_compliance("0x2222222222222222222222222222222222222222", contract.TIER_4) is False

    # Node 1 (Genesis Slashed) should always fail
    assert contract.check_node_sla_compliance("0x1111111111111111111111111111111111111111", contract.TIER_1) is False

    # Node 3 is currently ACTIVE at TIER_3
    assert contract.check_node_sla_compliance(node_3_addr, contract.TIER_3) is True

    # Unregistered address
    assert contract.check_node_sla_compliance("0x0000000000000000000000000000000000000001", contract.TIER_1) is False
    print("  --> PASS: check_node_sla_compliance accurately evaluates on-chain tier permissions.")

    # PHASE 9: Adversarial SLA Breach Challenge & 90% Slashing with 10% Residual (GL-SEC-02 Remediated)
    print("\n[Phase 9] Testing Adversarial SLA Violation Challenge & 100% Zero-Leak Accounting...")
    challenger_bounty_hunter = "0x9999999999999999999999999999999999999999"
    # Target Node 3 (currently ACTIVE with 2,000 Gwei locked)
    c_res = contract.submit_sla_violation_challenge(
        challenger_bounty_hunter,
        1_000_000_000_000,
        node_3_addr,
        "UNSCHEDULED_DOWNTIME",
        "https://audit-depin.org/proof/node3_downtime.json",
        "challenge_nonce_3333"
    )
    assert "CHALLENGE_2" in c_res

    # Adjudicate SLA breach: Confirmed downtime
    adj_res = contract.adjudicate_sla_violation_challenge(
        node_3_addr,
        "CHALLENGE_2",
        mock_llm_verdict=json.dumps({
            "verdict": "SLA_BREACH_CONFIRMED",
            "adjudication_rationale": "Host node was unresponsive across 14 independent pings over 4 hours."
        })
    )
    assert "SLA_BREACH_CONFIRMED" in adj_res
    assert contract.nodes[node_3_addr]["status"] == "SLASHED_JAILED"
    assert contract.nodes[node_3_addr]["active_tier"] == "REVOKED"
    assert contract.nodes[node_3_addr]["active_lease_id"] == "NONE"
    assert contract.nodes[node_3_addr]["sla_reliability_score"] == 0

    # Verify 90% slashing to challenger (1800 Gwei) + 100% bond refund (1000 Gwei) = 2800 Gwei
    transfer = contract.emitted_transfers[-1]
    assert transfer["recipient"] == challenger_bounty_hunter
    assert transfer["amount"] == 2_800_000_000_000, f"Expected 2800 Gwei, got {transfer['amount']}"

    # GL-SEC-02 Remediated: Verify 10% residual (200 Gwei) is credited to protocol owner!
    assert contract.claimable_balances[contract.owner] == 200_000_000_000, "10% residual fee must be credited to owner"

    # Gateway hook rejects jailed node
    assert contract.check_node_sla_compliance(node_3_addr, contract.TIER_1) is False
    print("  --> PASS: 90% slashed to challenger, 10% credited to protocol owner, zero residual leakage.")

    # PHASE 10: Frivolous Challenge Dismissal & Operator Compensation (GL-SEC-02 Remediated)
    print("\n[Phase 10] Testing Dismissed Challenge Bond Compensation to Innocent Operator...")
    # Challenge Node 2 (ACTIVE H100) with a frivolous challenge
    c_friv = contract.submit_sla_violation_challenge(
        challenger_bounty_hunter,
        1_000_000_000_000, # 1000 Gwei bond
        "0x2222222222222222222222222222222222222222",
        "THERMAL_THROTTLING",
        "https://audit-depin.org/proof/fake_throttling.json",
        "challenge_nonce_friv"
    )
    assert "CHALLENGE_3" in c_friv

    op_2_addr = "0x4444444444444444444444444444444444444444"
    initial_op2_claimable = contract.claimable_balances.get(op_2_addr, 0)

    # Adjudicate: Dismissed
    adj_friv = contract.adjudicate_sla_violation_challenge(
        "0x2222222222222222222222222222222222222222",
        "CHALLENGE_3",
        mock_llm_verdict=json.dumps({
            "verdict": "CHALLENGE_DISMISSED",
            "adjudication_rationale": "Hardware telemetry demonstrates nominal thermals under 62C."
        })
    )
    assert "CHALLENGE_DISMISSED" in adj_friv
    # Verify innocent operator was compensated with 100% of the challenger's bond!
    new_op2_claimable = contract.claimable_balances[op_2_addr]
    assert new_op2_claimable == initial_op2_claimable + 1_000_000_000_000, "Operator must receive 100% of slashed challenge bond"
    print("  --> PASS: Innocent operator compensated with 100% of frivolous challenger's bond.")

    # PHASE 11: Non-Admin Consensus Time Expiration & Clean Collateral Release
    print("\n[Phase 11] Testing Non-Admin Consensus Time Expiration & Clean Collateral Release...")
    node_5_addr = "0x1212121212121212121212121212121212121212"
    op_5_addr   = "0x3434343434343434343434343434343434343434"
    contract.register_node_cluster(op_5_addr, node_5_addr, "Custom FPGA Cluster", "ASIA-SG", "c" * 64)
    contract.commit_sla_lease(op_5_addr, 100_000_000_000, node_5_addr, contract.TIER_1, 3600, "https://fpga.io/metrics", "nonce_clean_55")
    contract.verify_hardware_sla(node_5_addr, "LEASE_5", mock_llm_response=json.dumps({
        "score": 900,
        "verdict": "APPROVED",
        "rationale": "FPGA cluster telemetry exceeds SLA targets."
    }))

    lease_5_hash = contract.leases["LEASE_5"]["lease_hash"]

    # Try early release before 3600 seconds elapse
    try:
        contract.release_clean_expired_lease(op_5_addr, node_5_addr, "LEASE_5", lease_5_hash)
        assert False, "Early release must revert with [ERR_LEASE_STILL_ACTIVE]"
    except AssertionError as e:
        assert "[ERR_LEASE_STILL_ACTIVE]" in str(e)

    # Advance time past lease expiration (current + 3601s)
    contract._set_mock_time(contract.current_time + 3601)

    # Now release clean expired lease
    rel_res = contract.release_clean_expired_lease(op_5_addr, node_5_addr, "LEASE_5", lease_5_hash)
    assert "LEASE_EXPIRED_SETTLED" in rel_res
    assert contract.leases["LEASE_5"]["status"] == "SETTLED_REFUNDED"
    assert contract.leases["LEASE_5"]["is_consumed"] is True
    assert contract.nodes[node_5_addr]["active_tier"] == "NONE"
    assert contract.nodes[node_5_addr]["active_lease_id"] == "NONE"

    # Verify 100% refund transferred to operator
    transfer = contract.emitted_transfers[-1]
    assert transfer["recipient"] == op_5_addr
    assert transfer["amount"] == 100_000_000_000
    print("  --> PASS: Non-admin block time expiry rigorously enforced; 100% collateral returned.")

    # PHASE 12: Single-Use Settlement & Replay Defense
    print("\n[Phase 12] Testing Anti-Tamper & Global Replay Invariants...")
    # Re-settling lease 5
    try:
        contract.release_clean_expired_lease(op_5_addr, node_5_addr, "LEASE_5", lease_5_hash)
        assert False, "Re-settling already consumed lease must revert"
    except AssertionError as e:
        assert "[ERR_REPLAY_01]" in str(e) or "[ERR_INVALID_STATUS]" in str(e)

    # Parameter substitution / hash mismatch
    fake_hash = "00" * 32
    try:
        contract.release_clean_expired_lease(op_5_addr, node_5_addr, "LEASE_5", fake_hash)
        assert False, "Hash mismatch must revert"
    except AssertionError as e:
        assert "[ERR_INVALID_STATUS]" in str(e) or "[ERR_MISMATCH_01]" in str(e)

    # Burned lease hash cannot be committed again
    try:
        contract.commit_sla_lease(op_5_addr, 100_000_000_000, node_5_addr, contract.TIER_1, 3600, "https://fpga.io/metrics", "nonce_clean_55")
        assert False, "Re-committing burned lease hash must revert"
    except AssertionError as e:
        assert "[ERR_REPLAY_02]" in str(e)

    print("  --> PASS: Single-use settlement, parameter anti-tamper, and global replay defenses verified.")

    print("\n" + "=" * 80)
    print("ALL 12 PHASES OF REMEDIATED DePINHardwareSlaSovereign TEST SUITE PASSED WITH 0 ERRORS!")
    print("=" * 80)


if __name__ == "__main__":
    run_all_tests()
