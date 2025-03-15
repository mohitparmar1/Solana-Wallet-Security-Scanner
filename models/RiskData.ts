import mongoose from 'mongoose';

// Schema for suspicious wallets
const suspiciousWalletSchema = new mongoose.Schema({
    address: { type: String, required: true, unique: true },
    reason: { type: String },
    dateAdded: { type: Date, default: Date.now },
    analysis: {
        balanceSOL: { type: Number },
        tokenAccounts: { type: Number },
        recentTransactions: { type: Number },
        lastActivity: { type: Date },
        dateAnalyzed: { type: Date, default: Date.now }
    }
});

// Schema for suspicious programs
const suspiciousProgramSchema = new mongoose.Schema({
    address: { type: String, required: true, unique: true },
    reason: { type: String },
    dateAdded: { type: Date, default: Date.now },
    analysis: {
        accountCount: { type: Number },
        recentTransactions: { type: Number },
        lastActivity: { type: Date },
        dateAnalyzed: { type: Date, default: Date.now }
    }
});

// Schema for suspicious patterns
const suspiciousPatternSchema = new mongoose.Schema({
    pattern: { type: String, required: true, unique: true },
    description: { type: String },
    dateAdded: { type: Date, default: Date.now }
});

export const SuspiciousWallet = mongoose.model('SuspiciousWallet', suspiciousWalletSchema);
export const SuspiciousProgram = mongoose.model('SuspiciousProgram', suspiciousProgramSchema);
export const SuspiciousPattern = mongoose.model('SuspiciousPattern', suspiciousPatternSchema); 