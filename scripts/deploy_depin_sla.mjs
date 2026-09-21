import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

let createClient, createAccount;
try {
    const gl = await import('genlayer-js');
    createClient = gl.createClient;
    createAccount = gl.createAccount;
} catch (e) {
    const gl = await import('../../AetherDungeon/frontend/node_modules/genlayer-js/dist/index.js');
    createClient = gl.createClient;
    createAccount = gl.createAccount;
}

const __dirname = path.dirname(fileURLToPath(import.meta.url));

async function main() {
    console.log("================================================================================");
    console.log("  DEPIN HARDWARE SLA SOVEREIGN — GENLAYER STUDIO DEPLOYMENT & VERIFICATION");
    console.log("================================================================================");
    
    console.log("Connecting to GenLayer Studio RPC: https://studio.genlayer.com/api");
    const account = createAccount();
    console.log("Generated Deployer / Governance Administrator Address:", account.address);

    const client = createClient({
        endpoint: 'https://studio.genlayer.com/api',
        account: account
    });

    const contractPath = path.join(__dirname, '..', 'contracts', 'DePINHardwareSlaSovereign.py');
    const code = fs.readFileSync(contractPath, 'utf8');
    console.log(`Read contract code from contracts/DePINHardwareSlaSovereign.py (${code.length} bytes)`);

    const owner = account.address;

    console.log("Broadcasting deployContract transaction to GenLayer Studio...");
    try {
        const txHash = await client.deployContract({
            code: code,
            args: [owner]
        });
        console.log("Deployment transaction submitted! Tx Hash:", txHash);

        console.log("Waiting for transaction receipt on GenLayer (status: FINALIZED)...");
        const receipt = await client.waitForTransactionReceipt({
            hash: txHash,
            status: 'FINALIZED',
            interval: 3000,
            retries: 50
        });

        console.log("Receipt status:", receipt.status);
        const contractAddress = receipt.to || receipt.contractAddress || receipt.data?.contractAddress || receipt.recipient;
        console.log("Contract Address:", contractAddress);

        if (contractAddress) {
            console.log("\n>>> DEPLOYMENT SUCCESSFUL! <<<");
            console.log("Contract Address:", contractAddress);
            console.log("Explorer URL: https://explorer-studio.genlayer.com/address/" + contractAddress);

            // Verify live on-chain reads
            console.log("\n--- VERIFYING LIVE ON-CHAIN DEPIN HARDWARE SLA STATE ---");
            const totalNodes = await client.readContract({
                address: contractAddress,
                functionName: 'get_total_nodes',
                args: []
            });
            console.log("Total Registered Compute Nodes (Genesis Fixtures):", totalNodes);

            const totalLeases = await client.readContract({
                address: contractAddress,
                functionName: 'get_total_leases',
                args: []
            });
            console.log("Total Compute SLA Leases:", totalLeases);

            const totalChallenges = await client.readContract({
                address: contractAddress,
                functionName: 'get_total_challenges',
                args: []
            });
            console.log("Total SLA Breach Challenges:", totalChallenges);

            const totalSlashed = await client.readContract({
                address: contractAddress,
                functionName: 'get_total_slashed',
                args: []
            });
            console.log("Total Slashed / Jailed Cheating Nodes:", totalSlashed);

            const totalCollateral = await client.readContract({
                address: contractAddress,
                functionName: 'get_total_collateral_locked',
                args: []
            });
            console.log("Total Collateral Locked (Wei):", totalCollateral);

            const currentTime = await client.readContract({
                address: contractAddress,
                functionName: 'get_current_time',
                args: []
            });
            console.log("Contract Consensus Block Clock:", currentTime);

            // Verify Public Gateway Hook
            console.log("\n--- TESTING PUBLIC GATEWAY HOOK (check_node_sla_compliance) ---");
            const node2Compliance = await client.readContract({
                address: contractAddress,
                functionName: 'check_node_sla_compliance',
                args: ['0x2222222222222222222222222222222222222222', 'TIER_3_GPU_TRAINING']
            });
            console.log("SLA compliance check for NODE_2 on TIER_3_GPU_TRAINING:", node2Compliance);

            const node1Compliance = await client.readContract({
                address: contractAddress,
                functionName: 'check_node_sla_compliance',
                args: ['0x1111111111111111111111111111111111111111', 'TIER_1_STANDARD_CPU']
            });
            console.log("SLA compliance check for NODE_1 (SLASHED) on TIER_1_STANDARD_CPU:", node1Compliance);

            // Save deployment manifest
            const manifest = {
                contract_name: "DePINHardwareSlaSovereign",
                contract_address: contractAddress,
                transaction_hash: txHash,
                network: "GenLayer Studio Testnet",
                rpc_endpoint: "https://studio.genlayer.com/api",
                explorer_url: `https://explorer-studio.genlayer.com/address/${contractAddress}`,
                deployer_address: owner,
                deployed_at_utc: new Date().toISOString(),
                receipt_status: receipt.status,
                genesis_verification: {
                    total_nodes: Number(totalNodes),
                    total_leases: Number(totalLeases),
                    total_challenges: Number(totalChallenges),
                    total_slashed: Number(totalSlashed),
                    total_collateral_wei: totalCollateral.toString(),
                    node_2_h100_tier_3_compliance: node2Compliance,
                    node_1_slashed_compliance: node1Compliance
                }
            };

            const manifestPath = path.join(__dirname, '..', 'deployment_manifest.json');
            fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
            console.log("\nSaved deployment manifest to deployment_manifest.json");
            console.log("Deployment and live on-chain verification complete!");
        } else {
            console.error("Failed to parse contractAddress from receipt:", receipt);
        }
    } catch (err) {
        console.error("Deployment failed with error:", err);
    }
}

main();
