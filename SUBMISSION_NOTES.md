Persistent on-chain Access Control Layer & Hardware SLA Compliance Engine for DePIN & GPU compute clusters. Reusable infrastructure primitive replacing the two-party court/escrow pattern.

Key Invariants:
1. 4-Tier Compute Staking: Clusters lease SLA tiers (STANDARD_CPU to HPC_DISTRIBUTED) backed by native GEN collateral escrowed strictly via @gl.public.write.payable (gl.message.value).
2. Autonomous Telemetry Audit: Ingests Prometheus metrics evaluated across 4 pillars (uptime, FLOPS, thermals, packet loss). Score >= 800 certifies SLA.
3. Fail-Closed Invariant: Reverts with [ERR_EVIDENCE_FETCH_FAILED] on failed/empty telemetry, mutating zero state.
4. Non-Admin Block Time: Expirations evaluate strictly against consensus block time (datetime.now).
5. Public Gateway: check_node_sla_compliance() provides real-time verification for external AI job routers.
6. Slashing Bounty: Whistleblowers submit breach proofs; confirmed breaches slash 90% collateral via emit_transfer().
