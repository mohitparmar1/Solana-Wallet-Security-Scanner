import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { Connection, PublicKey, LAMPORTS_PER_SOL, clusterApiUrl } from "@solana/web3.js";
import { connectToDatabase } from "./db/connection";
import { SuspiciousWallet, SuspiciousProgram, SuspiciousPattern } from "./models/RiskData";

// Create an MCP server
const server = new McpServer({
    name: "Solana Wallet Risk Analyzer",
    version: "1.0.0",
});

// Initialize Solana connection
const connection = new Connection(clusterApiUrl("mainnet-beta"), "confirmed");

// Connect to MongoDB
connectToDatabase().catch(console.error);

// Risk Database class using MongoDB
class RiskDatabase {
    constructor() {
        // Initialize default patterns
        this.initializeDefaultPatterns();
    }

    private async initializeDefaultPatterns() {
        const defaultPatterns = [
            { pattern: "token-2022.approve", description: "Token approval" },
            { pattern: "system.advance-nonce", description: "Nonce advancement" },
            { pattern: "unknown-program", description: "Unknown program interaction" }
        ];

        for (const pattern of defaultPatterns) {
            await SuspiciousPattern.findOneAndUpdate(
                { pattern: pattern.pattern },
                pattern,
                { upsert: true }
            );
        }
    }

    async addSuspiciousWallet(address: string, reason: string) {
        await SuspiciousWallet.create({ address, reason });
    }

    async addSuspiciousProgram(address: string, reason: string) {
        await SuspiciousProgram.create({ address, reason });
    }

    async addSuspiciousPattern(pattern: string, description: string) {
        await SuspiciousPattern.create({ pattern, description });
    }

    async isSuspiciousWallet(address: string): Promise<boolean> {
        const wallet = await SuspiciousWallet.findOne({ address });
        return wallet !== null;
    }

    async isSuspiciousProgram(address: string): Promise<boolean> {
        const program = await SuspiciousProgram.findOne({ address });
        return program !== null;
    }

    async getSuspiciousPatterns(): Promise<string[]> {
        const patterns = await SuspiciousPattern.find();
        return patterns.map(p => p.pattern);
    }

    async getDatabase(): Promise<{
        wallets: string[],
        programs: string[],
        patterns: string[]
    }> {
        const [wallets, programs, patterns] = await Promise.all([
            SuspiciousWallet.find(),
            SuspiciousProgram.find(),
            SuspiciousPattern.find()
        ]);

        return {
            wallets: wallets.map(w => w.address),
            programs: programs.map(p => p.address),
            patterns: patterns.map(p => p.pattern)
        };
    }
}

const riskDB = new RiskDatabase();

// Tool to add suspicious wallets/programs with on-chain verification
server.tool(
    "addSuspiciousAddress",
    "Add a suspicious wallet or program address to the risk database with on-chain verification",
    {
        address: z.string(),
        type: z.enum(["wallet", "program"]),
        reason: z.string()
    },
    async ({ address, type, reason }) => {
        try {
            const pubkey = new PublicKey(address);

            // On-chain verification
            if (type === "program") {
                // Verify if it's actually a program account
                const accountInfo = await connection.getAccountInfo(pubkey);
                if (!accountInfo?.executable) {
                    return {
                        content: [{
                            type: "text",
                            text: `❌ Error: Address ${address} is not a program account. Please verify the address.`
                        }]
                    };
                }

                // Get program activity metrics
                const programAccounts = await connection.getProgramAccounts(pubkey, {
                    commitment: 'confirmed',
                });

                // Additional program analysis
                const recentSignatures = await connection.getSignaturesForAddress(pubkey, { limit: 10 });
                const programActivity = {
                    accountCount: programAccounts.length,
                    recentTransactions: recentSignatures.length,
                    lastActivity: recentSignatures[0]?.blockTime || 0
                };

                await riskDB.addSuspiciousProgram(address, JSON.stringify({
                    reason,
                    programActivity,
                    dateAdded: new Date().toISOString()
                }));

                return {
                    content: [{
                        type: "text",
                        text: `✅ Added suspicious program:\nAddress: ${address}\nReason: ${reason}\n\n📊 Program Stats:\n• Associated Accounts: ${programActivity.accountCount}\n• Recent Transactions: ${programActivity.recentTransactions}\n• Last Activity: ${new Date(programActivity.lastActivity * 1000).toLocaleDateString()}`
                    }]
                };

            } else {
                // Wallet verification and analysis
                const balance = await connection.getBalance(pubkey);
                const recentActivity = await connection.getSignaturesForAddress(pubkey, { limit: 10 });

                // Get token accounts
                const tokenAccounts = await connection.getParsedTokenAccountsByOwner(pubkey, {
                    programId: new PublicKey('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'), // Token Program
                });

                const walletAnalysis = {
                    balanceSOL: balance / LAMPORTS_PER_SOL,
                    tokenAccounts: tokenAccounts.value.length,
                    recentTransactions: recentActivity.length,
                    lastActivity: recentActivity[0]?.blockTime || 0
                };

                await riskDB.addSuspiciousWallet(address, JSON.stringify({
                    reason,
                    walletAnalysis,
                    dateAdded: new Date().toISOString()
                }));

                return {
                    content: [{
                        type: "text",
                        text: `✅ Added suspicious wallet:\nAddress: ${address}\nReason: ${reason}\n\n📊 Wallet Stats:\n• Balance: ${walletAnalysis.balanceSOL} SOL\n• Token Accounts: ${walletAnalysis.tokenAccounts}\n• Recent Transactions: ${walletAnalysis.recentTransactions}\n• Last Activity: ${new Date(walletAnalysis.lastActivity * 1000).toLocaleDateString()}`
                    }]
                };
            }

        } catch (error) {
            return {
                content: [{
                    type: "text",
                    text: `Error adding address: ${(error as Error).message}\nPlease verify the address and try again.`
                }]
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
            await riskDB.addSuspiciousPattern(pattern, description);
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
        const db = await riskDB.getDatabase();
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
            if (await riskDB.isSuspiciousWallet(walletAddress)) {
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
                const accountKeys = tx.transaction.message.accountKeys;
                for (const key of accountKeys) {
                    const address = key.pubkey.toString();
                    const isSuspicious = await riskDB.isSuspiciousProgram(address);
                    if (isSuspicious) {
                        details.suspiciousPrograms.add(address);
                        riskScore += 2;
                    }
                }

                // Check for interactions with suspicious wallets
                for (const key of accountKeys) {
                    const address = key.pubkey.toString();
                    const isSuspicious = await riskDB.isSuspiciousWallet(address);
                    if (isSuspicious) {
                        details.suspiciousInteractions.add(address);
                        riskScore += 2;
                    }
                }

                // Check for suspicious patterns in logs
                const logs = tx.meta.logMessages || [];
                const suspiciousPatterns = await riskDB.getSuspiciousPatterns();
                for (const log of logs) {
                    for (const pattern of suspiciousPatterns) {
                        if (log.toLowerCase().includes(pattern.toLowerCase())) {
                            details.unusualPatterns.add(
                                `Found suspicious pattern: ${pattern} in transaction ${sigInfo.signature}`
                            );
                            riskScore += 1;
                        }
                    }
                }
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
                for (const tx of details.highValueTransactions) {
                    const date = new Date(tx.timestamp * 1000).toLocaleDateString();
                    report += `• ${tx.amount.toFixed(2)} SOL on ${date}\n`;
                    report += `  Signature: ${tx.signature}\n`;
                }
                report += '\n';
            }

            if (details.suspiciousPrograms.size > 0) {
                report += `🚨 Suspicious Program Interactions:\n`;
                for (const program of details.suspiciousPrograms) {
                    report += `• ${program}\n`;
                }
                report += '\n';
            }

            if (details.suspiciousInteractions.size > 0) {
                report += `⚠️ Interactions with Suspicious Wallets:\n`;
                for (const wallet of details.suspiciousInteractions) {
                    report += `• ${wallet}\n`;
                }
                report += '\n';
            }

            if (details.unusualPatterns.size > 0) {
                report += `📋 Unusual Patterns:\n`;
                for (const pattern of details.unusualPatterns) {
                    report += `• ${pattern}\n`;
                }
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