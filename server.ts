import express from 'express';
import { createServer as createViteServer } from 'vite';
import path from 'path';
import crypto from 'crypto';
import rateLimit from 'express-rate-limit';
import cors from 'cors';

// --- CONFIGURATION ---
const PORT = 3000;
const OTP_LENGTH = 6;
const OTP_EXPIRY_MINUTES = 5;
const MAX_ATTEMPTS = 3;
const LOCKOUT_MINUTES = 15;

// --- DATA MODEL (In-Memory Database for Demo) ---
// In a production environment, this would be a real database like PostgreSQL, MySQL, or Redis.
interface OtpRecord {
  identifier: string; // email or phone
  otpHash: string;
  expiresAt: number;
  attempts: number;
  status: 'active' | 'used' | 'expired';
  lockedUntil: number | null;
}

const db = new Map<string, OtpRecord>();

// --- UTILITIES ---

// Cryptographically secure random OTP generator
function generateSecureOTP(length: number): string {
  const min = Math.pow(10, length - 1);
  const max = Math.pow(10, length) - 1;
  return crypto.randomInt(min, max + 1).toString();
}

// Hash OTP before storing (using SHA-256 with a salt)
// In production, consider bcrypt, argon2, or HMAC with a secret key.
function hashOTP(otp: string, identifier: string): string {
  const secret = process.env.OTP_SECRET || 'default_secret_for_demo';
  return crypto
    .createHmac('sha256', secret)
    .update(`${identifier}:${otp}`)
    .digest('hex');
}

// --- EXPRESS APP SETUP ---
async function startServer() {
  const app = express();
  
  app.use(express.json());
  app.use(cors());

  // --- RATE LIMITING ---
  // Prevent brute force attacks on the generate endpoint
  const generateLimiter = rateLimit({
    windowMs: 10 * 60 * 1000, // 10 minutes
    max: 3, // Limit each IP to 3 requests per `window`
    message: { error: 'Too many OTP requests from this IP, please try again after 10 minutes' },
    standardHeaders: true,
    legacyHeaders: false,
  });

  // Prevent brute force attacks on the verify endpoint
  const verifyLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // Limit each IP to 10 verification attempts per `window`
    message: { error: 'Too many verification attempts from this IP, please try again later' },
    standardHeaders: true,
    legacyHeaders: false,
  });

  // --- API ROUTES ---

  // 1. Generate OTP
  app.post('/api/generate-otp', generateLimiter, (req, res) => {
    const { identifier } = req.body;

    if (!identifier) {
      return res.status(400).json({ error: 'Identifier (email/phone) is required' });
    }

    const existingRecord = db.get(identifier);

    // Check if user is locked out
    if (existingRecord && existingRecord.lockedUntil && existingRecord.lockedUntil > Date.now()) {
      const remainingMinutes = Math.ceil((existingRecord.lockedUntil - Date.now()) / 60000);
      return res.status(403).json({ 
        error: `Account temporarily locked due to too many failed attempts. Try again in ${remainingMinutes} minutes.` 
      });
    }

    // Generate OTP
    const otp = generateSecureOTP(OTP_LENGTH);
    const otpHash = hashOTP(otp, identifier);
    const expiresAt = Date.now() + OTP_EXPIRY_MINUTES * 60 * 1000;

    // Store in DB
    db.set(identifier, {
      identifier,
      otpHash,
      expiresAt,
      attempts: 0,
      status: 'active',
      lockedUntil: null,
    });

    // --- MOCK DELIVERY SERVICE ---
    // In production, integrate with Twilio, SendGrid, AWS SNS, etc.
    console.log(`\n[MOCK DELIVERY] Sending OTP to ${identifier}`);
    console.log(`[MOCK DELIVERY] Your OTP is: ${otp}\n`);

    res.json({ 
      success: true, 
      message: 'OTP generated and sent successfully',
      expiresInMinutes: OTP_EXPIRY_MINUTES
    });
  });

  // 2. Verify OTP
  app.post('/api/verify-otp', verifyLimiter, (req, res) => {
    const { identifier, otp } = req.body;

    if (!identifier || !otp) {
      return res.status(400).json({ error: 'Identifier and OTP are required' });
    }

    const record = db.get(identifier);

    if (!record) {
      return res.status(404).json({ error: 'No active OTP found for this identifier' });
    }

    // Check if locked out
    if (record.lockedUntil && record.lockedUntil > Date.now()) {
      return res.status(403).json({ error: 'Account is locked. Please try again later.' });
    }

    // Check if expired
    if (Date.now() > record.expiresAt || record.status === 'expired') {
      record.status = 'expired';
      return res.status(400).json({ error: 'OTP has expired. Please request a new one.' });
    }

    // Check if already used
    if (record.status === 'used') {
      return res.status(400).json({ error: 'OTP has already been used' });
    }

    // Verify Hash
    const inputHash = hashOTP(otp, identifier);
    if (inputHash !== record.otpHash) {
      record.attempts += 1;
      
      // Lock account if max attempts reached
      if (record.attempts >= MAX_ATTEMPTS) {
        record.lockedUntil = Date.now() + LOCKOUT_MINUTES * 60 * 1000;
        record.status = 'expired';
        return res.status(403).json({ 
          error: `Maximum attempts reached. Account locked for ${LOCKOUT_MINUTES} minutes.` 
        });
      }

      return res.status(400).json({ 
        error: 'Invalid OTP', 
        attemptsRemaining: MAX_ATTEMPTS - record.attempts 
      });
    }

    // Success - Mark as used
    record.status = 'used';
    
    // In production, you would issue a JWT or session token here
    res.json({ 
      success: true, 
      message: 'OTP verified successfully',
      token: 'mock_jwt_token_here' 
    });
  });

  // 3. Resend OTP
  app.post('/api/resend-otp', generateLimiter, (req, res) => {
    // Resend logic is essentially the same as generate, but you might want to 
    // add specific business logic (like invalidating the old one explicitly).
    // For simplicity, we redirect to the generate endpoint.
    res.redirect(307, '/api/generate-otp');
  });

  // --- VITE MIDDLEWARE FOR FRONTEND ---
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
