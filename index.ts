import 'dotenv/config';

import express from 'express';
import cors from 'cors';
import type { CorsOptions } from 'cors';
import multer from 'multer';
import path from 'path';
import { promises as fsp } from 'fs';
import fs from 'fs';
import fetch from 'node-fetch';
import FormData from 'form-data';

// CESS SDK imports
import {
  CESS,
  CESSConfig,
  isKeyringReady,
  SDKError,
  downloadFile,
  GenGatewayAccessToken,
  ExtendedDownloadOptions,
  upload,
} from '@cessnetwork/api';

import { safeSignUnixTime } from '@cessnetwork/util';
import { Keyring } from '@polkadot/keyring';
import { stringToU8a, u8aToHex } from '@polkadot/util';
import bs58 from 'bs58';
import crypto from 'crypto';
import type { OssDetail, OssAuthorityList, Territory } from '@cessnetwork/types';

const app = express();

// ==================== CORS CONFIGURATION ====================
const envOrigins = process.env.CORS_ORIGINS
  ? process.env.CORS_ORIGINS.split(',')
      .map((origin) => origin.trim())
      .filter(Boolean)
  : [];

const devOrigins = ['http://localhost:5173', 'http://127.0.0.1:5173'];
const allowedOriginSet = new Set<string>([...envOrigins, ...devOrigins]);
const allowedOrigins = Array.from(allowedOriginSet.values());
const allowAllOrigins = allowedOrigins.length === 0;

const isOriginAllowed = (origin?: string | null): boolean => {
  if (!origin) return true;
  if (allowAllOrigins) return true;
  return allowedOriginSet.has(origin);
};

const corsOptions: CorsOptions = {
  origin(origin: string | undefined, callback: (err: Error | null, allowed?: boolean) => void) {
    if (isOriginAllowed(origin)) {
      callback(null, true);
      return;
    }
    callback(new Error(`CORS origin not allowed: ${origin}`));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin'],
  exposedHeaders: ['Content-Disposition'],
  maxAge: 86400,
};

// CORS middleware
app.use((req: express.Request, res: express.Response, next: express.NextFunction) => {
  const origin = req.headers.origin;
  const originIsAllowed = isOriginAllowed(origin);

  if (originIsAllowed) {
    res.setHeader('Access-Control-Allow-Origin', origin ?? '*');
    if (origin) {
      res.setHeader('Access-Control-Allow-Credentials', 'true');
    } else {
      res.removeHeader('Access-Control-Allow-Credentials');
    }
  } else if (allowedOrigins.length > 0) {
    res.setHeader('Access-Control-Allow-Origin', allowedOrigins[0]);
    res.removeHeader('Access-Control-Allow-Credentials');
  } else {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.removeHeader('Access-Control-Allow-Credentials');
  }

  res.setHeader('Vary', 'Origin');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'Content-Type, Authorization, X-Requested-With, Accept, Origin'
  );
  res.setHeader(
    'Access-Control-Allow-Methods',
    'GET, POST, PUT, PATCH, DELETE, OPTIONS'
  );
  res.setHeader('Access-Control-Expose-Headers', 'Content-Disposition');

  if (req.method === 'OPTIONS') {
    if (!originIsAllowed) {
      res.status(403).json({ error: `CORS origin not allowed: ${origin}` });
      return;
    }
    res.sendStatus(204);
    return;
  }

  if (!originIsAllowed) {
    res.status(403).json({ error: `CORS origin not allowed: ${origin}` });
    return;
  }

  next();
});

app.use(cors(corsOptions));
app.use(express.json());

// Error handler with CORS headers
app.use((err: any, _req: express.Request, res: express.Response, next: express.NextFunction) => {
  if (!res.headersSent) {
    const origin = res.getHeader('Access-Control-Allow-Origin');
    if (!origin) {
      res.setHeader('Access-Control-Allow-Origin', allowedOrigins[0] || '*');
    }
    if (!res.getHeader('Access-Control-Allow-Headers')) {
      res.setHeader(
        'Access-Control-Allow-Headers',
        'Content-Type, Authorization, X-Requested-With, Accept, Origin'
      );
    }
    if (!res.getHeader('Access-Control-Allow-Methods')) {
      res.setHeader(
        'Access-Control-Allow-Methods',
        'GET, POST, PUT, PATCH, DELETE, OPTIONS'
      );
    }
    res.setHeader('Access-Control-Expose-Headers', 'Content-Disposition');
  }
  next(err);
});

// ==================== CONFIGURATION ====================

// IMPORTANT: name this differently so it doesn't clash with SDK `upload`
const uploadMiddleware = multer({ dest: 'uploads/' });

const GATEWAY_URL = process.env.GATEWAY_URL!;
const TERRITORY = process.env.TERRITORY || 'default';
const PORT = Number(process.env.PORT || 8080);
const PRIVATE_KEY = process.env.CESS_PRIVATE_KEY || '';

if (!GATEWAY_URL || !PRIVATE_KEY) {
  console.error('Missing env GATEWAY_URL or CESS_PRIVATE_KEY');
  process.exit(1);
}

// ==================== CESS CLIENT INITIALIZATION ====================

let cess!: CESS;
let ready = false;
let readyP: Promise<void>;

let gatewayToken: string | null = null;
let gatewayTokenExpireAt: number | null = null;

async function getGatewayConfig(): Promise<{ baseUrl: string; token: string }> {
  const now = Date.now();
  const baseUrl = GATEWAY_URL.replace(/\/$/, '');

  // Reuse token if still valid
  if (gatewayToken && gatewayTokenExpireAt && now < gatewayTokenExpireAt) {
    return { baseUrl, token: gatewayToken };
  }

  const sign_message = Date.now().toString();
  const signature = safeSignUnixTime(sign_message, PRIVATE_KEY);

  const token = await GenGatewayAccessToken(baseUrl, {
    account: cess.getSignatureAcc(),
    message: sign_message,
    sign: u8aToHex(signature),
    expire: 1,
  });

  gatewayToken = token;
  gatewayTokenExpireAt = now + 60 * 60 * 1000;

  return { baseUrl, token };
}

async function init() {
  const cfg: CESSConfig = {
    rpcs: [process.env.RPC_URL || 'wss://testnet-rpc.cess.network/ws/'],
    privateKey: PRIVATE_KEY,
  };

  cess = await CESS.newClient(cfg);
  console.log('Connected to:', cess.getNetworkEnv());

  if (!isKeyringReady(cess.keyring)) {
    throw new SDKError('Keyring Pair is required', 'INVALID_KEYRING');
  }

  console.log('Signer address:', cess.getSignatureAcc());
  console.log('Balance:', (await cess.getBalances()).toString());
  ready = true;
}

readyP = init().catch((e) => {
  console.error('CESS init failed:', e);
  process.exit(1);
});

async function ensureReady(_req: express.Request, _res: express.Response, next: express.NextFunction) {
  if (!ready) await readyP;
  next();
}

// ==================== HELPER FUNCTIONS ====================

function normalizeGatewayUrl(url: string): string {
  return url.replace(/^https?:\/\//, '').replace(/\/$/, '').toLowerCase();
}

function buildUploadHeaders(territory: string, bucket: string) {
  const keyring = new Keyring({ type: 'sr25519', ss58Format: 42 });
  const pair = keyring.addFromUri(PRIVATE_KEY);
  const account = pair.address;

  const messageBytes = crypto.randomBytes(16);
  const message = messageBytes.toString('hex');

  const signatureBytes = pair.sign(stringToU8a(message));
  const signature = bs58.encode(signatureBytes);

  return {
    Bucket: bucket,
    Territory: territory,
    Account: account,
    Message: message,
    Signature: signature,
  };
}

function buildDownloadHeaders() {
  const keyring = new Keyring({ type: 'sr25519', ss58Format: 42 });
  const pair = keyring.addFromUri(PRIVATE_KEY);
  const account = pair.address;

  const messageBytes = crypto.randomBytes(16);
  const message = messageBytes.toString('hex');

  const signatureBytes = pair.sign(stringToU8a(message));
  const signature = bs58.encode(signatureBytes);

  return {
    Operation: 'download',
    Account: account,
    Message: message,
    Signature: signature,
  };
}

function serializeBigInt(obj: any): any {
  if (obj === null || obj === undefined) return obj;

  if (typeof obj === 'bigint') return obj.toString();

  if (Array.isArray(obj)) return obj.map((item) => serializeBigInt(item));

  if (typeof obj === 'object') {
    const serialized: any = {};
    for (const [key, value] of Object.entries(obj)) {
      serialized[key] = serializeBigInt(value);
    }
    return serialized;
  }

  return obj;
}

async function ensureTerritory() {
  const accountAddress = cess.getSignatureAcc();
  const myTerritory = TERRITORY;
  const curBlockHeight = await cess.queryBlockNumberByHash();

  let territory = (await cess.queryTerritory(accountAddress, myTerritory)) as Territory;

  if (!territory) {
    console.log('Creating territory...');
    const result = await cess.mintTerritory(1, myTerritory, 30);
    if (result.success) {
      console.log('✅ Territory minted!', { txHash: result.txHash });
      await new Promise((resolve) => setTimeout(resolve, 6000));
      territory = (await cess.queryTerritory(accountAddress, myTerritory)) as Territory;
    } else {
      throw new Error('Territory minting failed: ' + result.error);
    }
  } else if (territory.deadline - curBlockHeight <= 100800) {
    await cess.renewalTerritory(myTerritory, 10);
  } else if (territory.state !== 'Active' || curBlockHeight >= territory.deadline) {
    await cess.reactivateTerritory(myTerritory, 30);
  } else if (territory.remainingSpace <= 1024 * 1024 * 1024) {
    await cess.expandingTerritory(myTerritory, 1);
  }

  return territory;
}

async function ensureGatewayAuth() {
  const accountAddress = cess.getSignatureAcc();
  const ossAccList = (await cess.queryOssByAccountId()) as unknown as OssDetail[];

  if (ossAccList.length === 0) {
    throw new Error('No OSS gateways found on-chain.');
  }

  const targetGateway = normalizeGatewayUrl(GATEWAY_URL);

  let gatewayAcc: string | undefined;
  let gatewayDomain: string | undefined;

  for (const oss of ossAccList) {
    const ossDomain = normalizeGatewayUrl(oss.ossInfo.domain || '');
    if (ossDomain === targetGateway) {
      gatewayAcc = oss.account;
      gatewayDomain = oss.ossInfo.domain;
      break;
    }
  }

  if (!gatewayAcc) {
    const availableDomains = ossAccList
      .map((oss) => oss.ossInfo.domain)
      .filter(Boolean);
    throw new Error(
      `Gateway "${GATEWAY_URL}" not found.\n` +
        `Available gateways: ${availableDomains.join(', ')}\n` +
        `Please update GATEWAY_URL in your .env file.`
    );
  }

  const authList = (await cess.queryAuthorityListByAccountId(gatewayAcc)) as unknown as OssAuthorityList[];
  const authorizedAccounts = authList.map((item) => item.authorizedAcc);

  if (!authorizedAccounts.includes(accountAddress)) {
    console.log('Authorizing gateway...');
    const result = await cess.authorize(gatewayAcc);
    if (!result.success) {
      throw new Error('Authorization failed: ' + result.error);
    }
    console.log('✅ Authorization successful!', { txHash: result.txHash });
  } else {
    console.log('✅ Already authorized');
  }

  return { gatewayAcc, gatewayDomain };
}

// For balance debug
async function checkBalance() {
  const balance = await cess.getBalances();
  const asNumber = Number(balance);
  const hasEnough = asNumber > 0.5 * 1e18; // arbitrary threshold
  return {
    hasEnough,
    message: hasEnough
      ? 'Sufficient TCESS balance for uploads.'
      : 'Low TCESS balance. Use faucet: https://www.cess.network/faucet.html',
  };
}

// ------------- Upload wrappers -------------

interface UploadResponseLike {
  code: number;
  data?: any;
  error?: string;
}

/**
 * Manual fallback upload if SDK `upload` fails with JSON parse error.
 */
async function manualUploadToGateway(
  localPath: string,
  originalName: string,
  mimeType: string | undefined
): Promise<UploadResponseLike> {
  const bucket = process.env.BUCKET_NAME || 'default';
  const territory = TERRITORY;
  const headers = buildUploadHeaders(territory, bucket);

  const formData = new FormData();
  formData.append('file', fs.createReadStream(localPath), {
    filename: originalName || 'upload.bin',
    contentType: mimeType || 'application/octet-stream',
  });

  const uploadUrl = `${GATEWAY_URL.replace(/\/$/, '')}/file`;
  console.log('[fallback] Uploading to:', uploadUrl);

  const response = await fetch(uploadUrl, {
    method: 'PUT',
    body: formData as any,
    headers: {
      ...headers,
      ...(formData as any).getHeaders?.(),
    } as any,
  });

  const rawText = await response.text();
  console.log('[fallback] Upload response:', {
    status: response.status,
    body: rawText,
  });

  if (!response.ok) {
    return {
      code: response.status,
      error: rawText,
    };
  }

  let data: any = rawText.trim();
  try {
    const json = JSON.parse(rawText);
    data = json;
  } catch {
    // plain text body
  }

  return {
    code: 200,
    data,
  };
}

/**
 * Try official SDK `upload` first.
 * If it fails with the CESS JSON parse error, fallback to manual upload.
 */
async function uploadViaSdkOrFallback(
  localPath: string,
  originalName: string,
  mimeType: string | undefined
): Promise<UploadResponseLike> {
  const gatewayConfig = await getGatewayConfig();

  try {
    console.log('[SDK] Calling upload(...) with gatewayConfig:', gatewayConfig.baseUrl);
    const result = (await upload(gatewayConfig as any, localPath, {
      territory: TERRITORY,
      uploadFileWithProgress: (progress: any) => {
        process.stdout.write(
          `\r[SDK] Upload progress: ${progress.percentage}% (${progress.loaded}/${progress.total} bytes) - ${progress.file}`
        );
      },
    })) as UploadResponseLike;

    console.log('\n[SDK] Upload result:', result);
    return result;
  } catch (err: any) {
    const msg = String(err?.message || err);
    console.error('[SDK] upload error:', msg);

    // If it's not the JSON parse error from the gateway, rethrow
    if (!msg.includes('Unexpected non-whitespace character after JSON')) {
      throw err;
    }

    console.log(
      '[SDK] Detected JSON parse error from gateway response, using manual upload fallback...'
    );
    return await manualUploadToGateway(localPath, originalName, mimeType);
  }
}

// ==================== DEBUG ENDPOINTS ====================

app.get('/api/debug/account', ensureReady, async (_req, res) => {
  try {
    const keyring = new Keyring({ type: 'sr25519', ss58Format: 42 });
    const pair = keyring.addFromUri(PRIVATE_KEY);
    const address = pair.address;

    res.json({
      privateKeyType: PRIVATE_KEY.startsWith('//') ? 'Substrate URI' : 'Mnemonic',
      address: address,
      cessAddress: cess.getSignatureAcc(),
      balance: (await cess.getBalances()).toString(),
    });
  } catch (e: any) {
    res.status(500).json({ error: e.message || String(e) });
  }
});

app.get('/api/debug/gateways', ensureReady, async (_req, res) => {
  try {
    const ossAccList = (await cess.queryOssByAccountId()) as unknown as OssDetail[];
    const targetGateway = normalizeGatewayUrl(GATEWAY_URL);

    const gateways = ossAccList.map((oss) => {
      const domain = oss.ossInfo.domain || '';
      const normalized = normalizeGatewayUrl(domain);
      return {
        domain: domain,
        normalized: normalized,
        account: oss.account,
        matches: normalized === targetGateway,
      };
    });

    res.json({
      targetGateway: GATEWAY_URL,
      normalizedTarget: targetGateway,
      availableGateways: gateways,
      foundMatch: gateways.some((g) => g.matches),
    });
  } catch (e: any) {
    res.status(500).json({ error: e.message || String(e) });
  }
});

app.get('/api/debug/balance', ensureReady, async (_req, res) => {
  try {
    const balance = await cess.getBalances();
    const balanceCheck = await checkBalance();

    res.json({
      address: cess.getSignatureAcc(),
      balance: balance.toString(),
      balanceFormatted: (Number(balance) / 1e18).toFixed(4) + ' TCESS',
      hasEnoughBalance: balanceCheck.hasEnough,
      message: balanceCheck.message,
      faucetUrl: 'https://www.cess.network/faucet.html',
    });
  } catch (e: any) {
    res.status(500).json({ error: e.message || String(e) });
  }
});

// ==================== MAIN API ENDPOINTS ====================

app.post('/api/ensure-territory', ensureReady, async (req, res) => {
  try {
    const origin = req.headers.origin ?? allowedOrigins[0] ?? '*';
    res.setHeader('Access-Control-Allow-Origin', origin);
    if (origin !== '*') {
      res.setHeader('Access-Control-Allow-Credentials', 'true');
    }
    console.log('[ensure-territory] request from', origin, 'at', new Date().toISOString());

    await ensureTerritory();
    await ensureGatewayAuth();

    res.json({ ok: true });
  } catch (e: any) {
    console.error('[ensure-territory] error:', e);
    res.status(500).json({ ok: false, error: e.message || String(e) });
  }
});

app.post('/api/upload', ensureReady, uploadMiddleware.single('file'), async (req, res) => {
  const localPath = req.file?.path;

  try {
    if (!localPath) throw new Error('No file uploaded');

    // Chain-side prerequisites
    await ensureTerritory();
    await ensureGatewayAuth();

    // 🔹 Try SDK upload first, fallback if needed
    const result = await uploadViaSdkOrFallback(
      localPath,
      req.file!.originalname,
      req.file!.mimetype
    );

    if (result.code !== 200) {
      throw new Error(`Upload failed: ${result.error || 'Unknown error'}`);
    }

    // Extract FID from possible response shapes
    let fid = '';
    const data = result.data;

    if (typeof data === 'string') {
      fid = data;
    } else if (data?.fid) {
      fid = data.fid;
    } else if (data?.data?.fid) {
      fid = data.data.fid;
    } else if (data?.data) {
      fid = data.data;
    }

    fid = (fid || '').toString().trim();

    if (!fid) {
      throw new Error('No FID returned from gateway/SDK response');
    }

    console.log('Upload FID:', fid);

    // Optional: verify file registration on chain
    console.log('Verifying file registration on blockchain...');
    await new Promise((resolve) => setTimeout(resolve, 2000));

    let verified = false;
    let attempts = 0;
    const maxAttempts = 10;

    while (!verified && attempts < maxAttempts) {
      const dealMap = await cess.queryDealMap(fid);
      const fileMeta = await cess.queryFileByFid(fid);

      if (dealMap || fileMeta) {
        verified = true;
        console.log('✅ File registered on blockchain!');
        break;
      }

      attempts++;
      console.log(
        `Waiting for blockchain registration... (attempt ${attempts}/${maxAttempts})`
      );
      await new Promise((resolve) => setTimeout(resolve, 2000));
    }

    if (!verified) {
      console.warn('⚠️ File uploaded but not yet visible on blockchain');
    }

    res.json({
      fid,
      verified,
      message: verified
        ? 'File uploaded and registered on blockchain'
        : 'File uploaded but blockchain registration pending',
      via: 'sdk-or-fallback',
    });
  } catch (e: any) {
    console.error('[UPLOAD] Error:', e);
    res.status(500).json({ error: e.message || String(e) });
  } finally {
    if (localPath) fsp.unlink(localPath).catch(() => {});
  }
});

app.post('/api/upload-json', ensureReady, async (req, res) => {
  try {
    const jsonData = req.body;

    if (!jsonData) {
      return res.status(400).json({ error: 'Missing JSON body' });
    }

    // 1) Convert JSON to string
    const jsonString =
      typeof jsonData === 'string'
        ? jsonData
        : JSON.stringify(jsonData, null, 2);

    // 2) Create a temporary JSON file
    const tmpDir = path.join('uploads', 'json');
    await fsp.mkdir(tmpDir, { recursive: true });

    const tmpPath = path.join(tmpDir, `json_${Date.now()}.json`);
    await fsp.writeFile(tmpPath, jsonString, 'utf8');

    // 3) Ensure territory & gateway authorization
    await ensureTerritory();
    await ensureGatewayAuth();

    // 4) Get gateway config + official token
    const gatewayConfig = await getGatewayConfig();

    // 5) Upload using official CESS upload()
    const uploadResult: any = await upload(gatewayConfig as any, tmpPath, {
      territory: TERRITORY,
    });

    // Cleanup temp file
    await fsp.unlink(tmpPath).catch(() => {});

    if (uploadResult.code !== 200) {
      throw new Error(
        `CESS upload failed: ${uploadResult.error || 'Unknown error'}`
      );
    }

    // 6) Extract FID
    let fid = '';
    const d = uploadResult.data;

    if (typeof d === 'string') fid = d;
    else if (d?.fid) fid = d.fid;
    else if (d?.data?.fid) fid = d.data.fid;
    else if (d?.data) fid = d.data;

    fid = fid.toString().trim();

    if (!fid) {
      throw new Error('No FID returned from CESS upload');
    }

    res.json({
      success: true,
      fid,
      message: 'JSON uploaded to CESS successfully',
    });
  } catch (e: any) {
    res.status(500).json({
      error: e.message || String(e),
    });
  }
});

// Download using official SDK `downloadFile`
app.get('/api/download/:fid', ensureReady, async (req, res) => {
  try {
    const fid = req.params.fid;
    console.log('=== Download Request ===');
    console.log('FID:', fid);
    console.log('Gateway URL:', GATEWAY_URL);

    const dealMap = await cess.queryDealMap(fid);
    const fileMeta = await cess.queryFileByFid(fid);

    if (!dealMap && !fileMeta) {
      return res.status(404).json({
        error: 'File not found on blockchain',
        fid,
      });
    }

    if (dealMap && !fileMeta) {
      return res.status(202).json({
        error: 'File is still distributing',
        fid,
        state: 'Distributing',
        message: 'File is being distributed to storage nodes. Please wait.',
      });
    }

    const gatewayConfig = await getGatewayConfig();
    console.log('Gateway config:', {
      baseUrl: gatewayConfig.baseUrl,
      hasToken: !!gatewayConfig.token,
    });

    const tmpPath = path.join('downloads', `${fid}.json`);
    await fsp.mkdir(path.dirname(tmpPath), { recursive: true });

    const downloadOptions: ExtendedDownloadOptions = {
      fid,
      savePath: tmpPath,
      overwrite: true,
      createDirectories: true,
    };

    const downloadResult = await downloadFile(gatewayConfig as any, downloadOptions);
    console.log('downloadResult:', downloadResult);

    if (!downloadResult.success) {
      return res.status(502).json({
        error: 'Gateway download failed',
        fid,
        details: downloadResult.error || 'Unknown error',
      });
    }

    res.download(tmpPath, (err) => {
      fsp.unlink(tmpPath).catch(() => {});
      if (err) {
        console.error('Download send error:', err);
      }
    });
  } catch (e: any) {
    console.error('[DOWNLOAD] Error:', e);
    res.status(500).json({
      error: e.message || String(e),
      fid: req.params.fid,
    });
  }
});

// API: Download file - Try download regardless of status
app.get('/api/download-new/:fid', ensureReady, async (req, res) => {
  try {
    const fid = req.params.fid;
    
    // Build download URL (like Rust SDK - no status check first!)
    let gatewayUrl = GATEWAY_URL;
    if (!gatewayUrl.endsWith('/')) {
      gatewayUrl = gatewayUrl + '/';
    }
    
    const downloadUrl = `${gatewayUrl}file/download/${fid}`;
    const headers = buildDownloadHeaders();
    
    console.log('Attempting download:', {
      fid: fid,
      url: downloadUrl,
      account: headers.Account,
    });
    
    // Try to download directly (like Rust SDK does)
    const response = await fetch(downloadUrl, {
      method: 'GET',
      headers: headers as any,
    });
    
    // Check response
    if (!response.ok) {
      const errorText = await response.text();
      console.error('Download failed:', {
        status: response.status,
        error: errorText,
      });
      
      // Only check blockchain status if download fails
      if (response.status === 404) {
        const dealMap = await cess.queryDealMap(fid);
        const fileMeta = await cess.queryFileByFid(fid);
        
        if (dealMap && !fileMeta) {
          return res.status(202).json({
            error: 'File is still distributing',
            fid: fid,
            state: 'Distributing',
            suggestion: 'File may be available soon. Try again in a few minutes.',
          });
        }
      }
      
      throw new Error(`Download failed (${response.status}): ${errorText}`);
    }
    
    // Download successful!
    const tmpPath = path.join('downloads', `${fid}.bin`);
    await fsp.mkdir(path.dirname(tmpPath), { recursive: true });
    
    const buffer = await response.buffer();
    await fsp.writeFile(tmpPath, buffer);
    
    console.log(`✅ File downloaded successfully: ${tmpPath} (${buffer.length} bytes)`);
    
    res.download(tmpPath, (err) => {
      fsp.unlink(tmpPath).catch(() => {});
      if (err) console.error('Download send error:', err);
    });
  } catch (e: any) {
    console.error('[DOWNLOAD] Error:', e);
    res.status(500).json({ error: e.message || String(e) });
  }
});

app.get('/api/cess/json/:fid', ensureReady, async (req, res) => {
  const fid = req.params.fid;

  try {
    // 1) Check on-chain that file exists
    const fileMeta = await cess.queryFileByFid(fid);
    if (!fileMeta) {
      return res.status(404).json({ error: 'File not found on blockchain', fid });
    }

    // 2) Get gateway config (SDK-style, same as download endpoint)
    const gatewayConfig = await getGatewayConfig();

    // 3) Download to a temp file
    const tmpPath = path.join('downloads', `${fid}.json`);
    await fsp.mkdir(path.dirname(tmpPath), { recursive: true });

    const downloadOptions: ExtendedDownloadOptions = {
      fid,
      savePath: tmpPath,
      overwrite: true,
      createDirectories: true,
    };

    const downloadResult = await downloadFile(gatewayConfig as any, downloadOptions);
    if (!downloadResult.success) {
      return res.status(502).json({
        error: 'Gateway download failed',
        fid,
        details: downloadResult.error || 'Unknown error',
      });
    }

    // 4) Read file and parse JSON
    const content = await fsp.readFile(tmpPath, 'utf8');

    let json;
    try {
      json = JSON.parse(content);
    } catch {
      return res.status(500).json({
        error: 'File content is not valid JSON',
        fid,
      });
    }

    // 5) Cleanup temp and return JSON
    await fsp.unlink(tmpPath).catch(() => {});
    res.json(json);
  } catch (e: any) {
    console.error('[CESS JSON FETCH] Error:', e);
    res.status(500).json({ error: e.message || String(e), fid });
  }
});

app.get('/api/file-status/:fid', ensureReady, async (req, res) => {
  try {
    const fid = req.params.fid;
    const account = cess.getSignatureAcc();
    
    const dealMap = await cess.queryDealMap(fid);
    const fileMeta = await cess.queryFileByFid(fid);
    const userFileList = await cess.queryUserHoldFileList(account);
    
    const fileInUserList = userFileList?.some((file: any) => {
      const fileFid = file?.fileHash || file?.fid || '';
      return fileFid.toLowerCase() === fid.toLowerCase();
    });
    
    let status = 'Unknown';
    let canDownload = false;
    let message = '';
    let estimatedWait = null;
    
    if (!dealMap && !fileMeta) {
      status = 'Not Found';
      message = 'File does not exist on blockchain';
    } else if (dealMap && !fileMeta) {
      status = 'Distributing';
      message = 'File is being distributed to storage nodes';
      canDownload = false;
      estimatedWait = '1-10 minutes';
    } else if (fileMeta) {
      status = 'Stored';
      message = 'File is stored on blockchain';
      canDownload = true;
    }
    
    // Try to check gateway availability
    let gatewayAvailable = false;
    try {
      let gatewayUrl = GATEWAY_URL;
      gatewayUrl = gatewayUrl.replace(/\/$/, '');
      const downloadUrl = `${gatewayUrl}/download/${fid}`;
      const headers = buildDownloadHeaders();
      
      const testResponse = await fetch(downloadUrl, {
        method: 'HEAD', // Just check if it exists
        headers: headers as any,
      });
      
      gatewayAvailable = testResponse.ok;
    } catch (e) {
      // Gateway check failed, but that's okay
    }
    
    res.json({
      fid: fid,
      status: status,
      canDownload: canDownload && gatewayAvailable,
      message: message,
      estimatedWait: estimatedWait,
      dealMap: dealMap ? serializeBigInt(dealMap) : null,
      fileMeta: fileMeta ? serializeBigInt(fileMeta) : null,
      fileInUserList: fileInUserList || false,
      gatewayAvailable: gatewayAvailable,
      account: account,
      recommendation: !gatewayAvailable && fileMeta 
        ? 'File is stored but gateway may need time to sync. Wait 1-2 minutes and try download again.'
        : null,
    });
  } catch (e: any) {
    res.status(500).json({ error: e.message || String(e) });
  }
});


// (Other endpoints like /api/file-info, /api/file-status, etc. can stay as you had them)

// ==================== SERVER START ====================
app.listen(PORT, () => {
  console.log(`CESS API listening on http://localhost:${PORT}`);
  console.log(`Gateway: ${GATEWAY_URL}`);
  console.log(`Territory: ${TERRITORY}`);
});
