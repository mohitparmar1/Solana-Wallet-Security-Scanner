import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { Connection, PublicKey, LAMPORTS_PER_SOL, clusterApiUrl } from "@solana/web3.js";

// Create an MCP server
const server = new McpServer({
    name: "Solana Wallet Risk Analyzer",
    version: "1.0.0",
});

// Initialize Solana connection
const connection = new Connection(clusterApiUrl("mainnet-beta"), "confirmed");

// Risk patterns database (in-memory storage)
class RiskDatabase {
    private suspiciousWallets: Set<string> = new Set();
    private suspiciousPrograms: Set<string> = new Set();
    private suspiciousPatterns: Set<string> = new Set();

    constructor() {
        // Initialize with some default patterns
        this.suspiciousPatterns.add("token-2022.approve");
        this.suspiciousPatterns.add("system.advance-nonce");
        this.suspiciousPatterns.add("unknown-program");
    }

    addSuspiciousWallet(address: string) {
        this.suspiciousWallets.add(address);
    }

    addSuspiciousProgram(address: string) {
        this.suspiciousPrograms.add(address);
    }

    addSuspiciousPattern(pattern: string) {
        this.suspiciousPatterns.add(pattern);
    }

    isSuspiciousWallet(address: string): boolean {
        return this.suspiciousWallets.has(address);
    }

    isSuspiciousProgram(address: string): boolean {
        return this.suspiciousPrograms.has(address);
    }

    getSuspiciousPatterns(): string[] {
        return Array.from(this.suspiciousPatterns);
    }

    getDatabase(): { wallets: string[], programs: string[], patterns: string[] } {
        return {
            wallets: Array.from(this.suspiciousWallets),
            programs: Array.from(this.suspiciousPrograms),
            patterns: Array.from(this.suspiciousPatterns)
        };
    }
}

const riskDB = new RiskDatabase();

// Tool to add suspicious wallets/programs
server.tool(
    "addSuspiciousAddress",
    "Add a suspicious wallet or program address to the risk database",
    {
        address: z.string(),
        type: z.enum(["wallet", "program"]),
        reason: z.string()
    },
    async ({ address, type, reason }) => {
        try {
            // Validate the address
            new PublicKey(address);

            if (type === "wallet") {
                riskDB.addSuspiciousWallet(address);
            } else {
                riskDB.addSuspiciousProgram(address);
            }

            return {
                content: [{
                    type: "text",
                    text: `✅ Successfully added suspicious ${type}:\nAddress: ${address}\nReason: ${reason}`
                }]
            };
        } catch (error) {
            return {
                content: [{ type: "text", text: `Error adding address: ${(error as Error).message}` }]
            };
        }
    }
);

// Tool to add suspicious patterns
server.tool(
    "addSuspiciousPattern",
    "Add a suspicious transaction pattern to the risk database",
    {
        pattern: z.string(),
        description: z.string()
    },
    async ({ pattern, description }) => {
        try {
            riskDB.addSuspiciousPattern(pattern);
            return {
                content: [{
                    type: "text",
                    text: `✅ Successfully added suspicious pattern:\nPattern: ${pattern}\nDescription: ${description}`
                }]
            };
        } catch (error) {
            return {
                content: [{ type: "text", text: `Error adding pattern: ${(error as Error).message}` }]
            };
        }
    }
);

// Tool to view the risk database
server.tool(
    "viewRiskDatabase",
    "View all suspicious addresses and patterns in the database",
    {},
    async () => {
        const db = riskDB.getDatabase();
        let report = `📋 Risk Database Contents\n`;
        report += `━━━━━━━━━━━━━━━━━━━━\n\n`;

        report += `🚫 Suspicious Wallets (${db.wallets.length}):\n`;
        db.wallets.forEach(wallet => {
            report += `• ${wallet}\n`;
        });
        report += '\n';

        report += `⚠️ Suspicious Programs (${db.programs.length}):\n`;
        db.programs.forEach(program => {
            report += `• ${program}\n`;
        });
        report += '\n';

        report += `🔍 Suspicious Patterns (${db.patterns.length}):\n`;
        db.patterns.forEach(pattern => {
            report += `• ${pattern}\n`;
        });

        return {
            content: [{ type: "text", text: report }]
        };
    }
);

// Modified wallet analysis tool
server.tool(
    "analyzeWalletRisk",
    "Analyzes a wallet's transaction history for potential security risks",
    {
        walletAddress: z.string(),
        daysToAnalyze: z.number().optional().default(30)
    },
    async ({ walletAddress, daysToAnalyze }) => {
        try {
            const pubkey = new PublicKey(walletAddress);
            let riskScore = 0;
            const warnings: string[] = [];
            const details = {
                suspiciousPrograms: new Set<string>(),
                highValueTransactions: [] as Array<{
                    signature: string;
                    amount: number;
                    timestamp: number;
                }>,
                unusualPatterns: new Set<string>(),
                suspiciousInteractions: new Set<string>()
            };

            // Check if the wallet itself is suspicious
            if (riskDB.isSuspiciousWallet(walletAddress)) {
                warnings.push("⚠️ This wallet address is marked as suspicious in the database");
                riskScore += 3;
            }

            // Get recent transactions
            const signatures = await connection.getSignaturesForAddress(
                pubkey,
                { limit: 100 }
            );

            // Analyze each transaction
            for (const sigInfo of signatures) {
                const tx = await connection.getParsedTransaction(sigInfo.signature);
                if (!tx || !tx.meta) continue;

                // Check for high-value transfers
                const valueTransferred = tx.meta.preBalances.reduce((acc, pre, idx) => {
                    const post = tx.meta!.postBalances[idx];
                    return acc + Math.abs(post - pre);
                }, 0) / LAMPORTS_PER_SOL;

                if (valueTransferred > 100) { // 100 SOL threshold
                    details.highValueTransactions.push({
                        signature: sigInfo.signature,
                        amount: valueTransferred,
                        timestamp: sigInfo.blockTime || 0
                    });
                    riskScore += 1;
                }

                // Check program interactions
                tx.transaction.message.accountKeys.forEach(key => {
                    const address = key.pubkey.toString();
                    if (riskDB.isSuspiciousProgram(address)) {
                        details.suspiciousPrograms.add(address);
                        riskScore += 2;
                    }
                });

                // Check for interactions with suspicious wallets
                tx.transaction.message.accountKeys.forEach(key => {
                    const address = key.pubkey.toString();
                    if (riskDB.isSuspiciousWallet(address)) {
                        details.suspiciousInteractions.add(address);
                        riskScore += 2;
                    }
                });

                // Check for suspicious patterns in logs
                const logs = tx.meta.logMessages || [];
                logs.forEach(log => {
                    riskDB.getSuspiciousPatterns().forEach(pattern => {
                        if (log.toLowerCase().includes(pattern.toLowerCase())) {
                            details.unusualPatterns.add(
                                `Found suspicious pattern: ${pattern} in transaction ${sigInfo.signature}`
                            );
                            riskScore += 1;
                        }
                    });
                });
            }

            // Generate report
            let report = `🔍 Wallet Risk Analysis Report\n`;
            report += `━━━━━━━━━━━━━━━━━━━━━━━━\n\n`;

            const riskLevel = riskScore > 5 ? 'HIGH' : riskScore > 2 ? 'MEDIUM' : 'LOW';
            report += `📊 Risk Level: ${getRiskEmoji(riskLevel)} ${riskLevel}\n\n`;

            if (warnings.length > 0) {
                report += `⚠️ Warnings:\n${warnings.join('\n')}\n\n`;
            }

            if (details.highValueTransactions.length > 0) {
                report += `💰 High-Value Transactions:\n`;
                details.highValueTransactions.forEach(tx => {
                    const date = new Date(tx.timestamp * 1000).toLocaleDateString();
                    report += `• ${tx.amount.toFixed(2)} SOL on ${date}\n`;
                    report += `  Signature: ${tx.signature}\n`;
                });
                report += '\n';
            }

            if (details.suspiciousPrograms.size > 0) {
                report += `🚨 Suspicious Program Interactions:\n`;
                details.suspiciousPrograms.forEach(program => {
                    report += `• ${program}\n`;
                });
                report += '\n';
            }

            if (details.suspiciousInteractions.size > 0) {
                report += `⚠️ Interactions with Suspicious Wallets:\n`;
                details.suspiciousInteractions.forEach(wallet => {
                    report += `• ${wallet}\n`;
                });
                report += '\n';
            }

            if (details.unusualPatterns.size > 0) {
                report += `📋 Unusual Patterns:\n`;
                details.unusualPatterns.forEach(pattern => {
                    report += `• ${pattern}\n`;
                });
                report += '\n';
            }

            report += `\n💡 Recommendations:\n`;
            if (riskLevel === 'HIGH') {
                report += `• Review all recent transactions carefully\n`;
                report += `• Consider moving funds to a new wallet\n`;
                report += `• Revoke permissions for suspicious programs\n`;
            } else if (riskLevel === 'MEDIUM') {
                report += `• Monitor wallet activity closely\n`;
                report += `• Review program permissions\n`;
            } else {
                report += `• Continue monitoring wallet activity\n`;
                report += `• Practice good security habits\n`;
            }

            return {
                content: [{ type: "text", text: report }]
            };
        } catch (error) {
            return {
                content: [{ type: "text", text: `Error analyzing wallet: ${(error as Error).message}` }]
            };
        }
    }
);

// Helper function for risk level emoji
function getRiskEmoji(riskLevel: 'LOW' | 'MEDIUM' | 'HIGH'): string {
    switch (riskLevel) {
        case 'LOW': return '🟢';
        case 'MEDIUM': return '🟡';
        case 'HIGH': return '🔴';
        default: return '⚪';
    }
}

// Add a prompt for more detailed analysis
server.prompt(
    'explain-wallet-risks',
    'Provide detailed explanation of wallet risks and recommendations',
    { walletAddress: z.string() },
    ({ walletAddress }) => ({
        messages: [{
            role: 'user',
            content: {
                type: 'text',
                text: `Analyze the wallet ${walletAddress} for security risks and provide detailed recommendations. Please:
1. Check for interactions with known malicious programs
2. Analyze transaction patterns
3. Identify any unusual activity
4. Provide specific security recommendations
Use the analyzeWalletRisk tool first, then provide additional context and explanation.`
            }
        }]
    })
);

// Start receiving messages on stdin and sending messages on stdout
const transport = new StdioServerTransport();
server.connect(transport);