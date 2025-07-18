const express = require('express');
const { ethers } = require('ethers');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const app = express();

// --- CONFIGURATION ---
const PORT = process.env.PORT || 3000;
const RPC_URL = 'https://rpc-testnet.qubetics.work';
const FAUCET_PRIVATE_KEY = process.env.FAUCET_PRIVATE_KEY;
const RECAPTCHA_SECRET_KEY = process.env.RECAPTCHA_SECRET_KEY;
const AMOUNT_TO_SEND = '1'; 
const COOLDOWN_HOURS = 24;
// --- END CONFIGURATION ---


const allowedOrigins = [
    'https://ticslab.xyz', 
    'https://www.ticslab.xyz', 
    'http://localhost:3000' // For local testing
];
const corsOptions = {
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  }
};
app.use(cors(corsOptions));
app.options('*', cors(corsOptions)); 

app.use(express.json());


if (!FAUCET_PRIVATE_KEY || !RECAPTCHA_SECRET_KEY) {
    console.error("FATAL ERROR: Environment variables FAUCET_PRIVATE_KEY and RECAPTCHA_SECRET_KEY must be set.");
    process.exit(1);
}

const provider = new ethers.providers.JsonRpcProvider(RPC_URL);
const wallet = new ethers.Wallet(FAUCET_PRIVATE_KEY, provider);

const requestLog = {};

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    standardHeaders: true,
    legacyHeaders: false,
});

app.get('/', (req, res) => {
    res.send('Qubetics Faucet Server is running.');
});

app.post('/request-funds', limiter, async (req, res) => {
    const { address, recaptcha } = req.body;
    const userIp = req.ip;
    const now = Date.now();

    if (!address || !recaptcha) {
        return res.status(400).json({ error: 'Address and reCAPTCHA are required.' });
    }
    if (!ethers.utils.isAddress(address)) {
        return res.status(400).json({ error: 'Invalid wallet address format.' });
    }

    try {
        const recaptchaUrl = `https://www.google.com/recaptcha/api/siteverify?secret=${RECAPTCHA_SECRET_KEY}&response=${recaptcha}&remoteip=${userIp}`;
        const recaptchaResult = await fetch(recaptchaUrl).then(r => r.json());
        if (!recaptchaResult.success) {
            return res.status(400).json({ error: 'reCAPTCHA verification failed.' });
        }
    } catch (e) {
        console.error(e);
        return res.status(500).json({ error: 'Failed to verify reCAPTCHA.' });
    }

    const cooldownMs = COOLDOWN_HOURS * 60 * 60 * 1000;
    if (requestLog[address] && (now - requestLog[address] < cooldownMs)) {
        return res.status(429).json({ error: `You can only request funds once every ${COOLDOWN_HOURS} hours.` });
    }
    if (requestLog[userIp] && (now - requestLog[userIp] < cooldownMs)) {
        return res.status(429).json({ error: `This IP has already requested funds recently.` });
    }

    try {
        console.log(`Sending ${AMOUNT_TO_SEND} TICS to ${address}`);
        const tx = await wallet.sendTransaction({
            to: address,
            value: ethers.utils.parseEther(AMOUNT_TO_SEND)
        });
        
        console.log(`Transaction sent! Hash: ${tx.hash}`);

        requestLog[address] = now;
        requestLog[userIp] = now;

        return res.status(200).json({ success: true, message: `${AMOUNT_TO_SEND} TICS sent successfully!`, txHash: tx.hash });

    } catch (error) {
        console.error("Transaction failed:", error);
        return res.status(500).json({ error: 'Failed to send transaction. The faucet may be out of funds.' });
    }
});

app.listen(PORT, () => {
    console.log(`Faucet server listening on port ${PORT}`);
    console.log(`Faucet address: ${wallet.address}`);
});
