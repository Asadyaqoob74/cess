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
} from '@cessnetwork/api';
import { Keyring } from '@polkadot/keyring';
import { stringToU8a } from '@polkadot/util';
import bs58 from 'bs58';
import crypto from 'crypto';
import type {
  OssDetail,
  OssAuthorityList,
  Territory,
} from '@cessnetwork/types';

const app = express();

// ==================== CORS CONFIGURATION ====================
const envOrigins = process.env.CORS_ORIGINS
  ? process.env.CORS_ORIGINS.split(',').map((origin) => origin.trim()).filter(Boolean)
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
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
    }
    res.setHeader('Access-Control-Expose-Headers', 'Content-Disposition');
  }
  next(err);
});

// ==================== CONFIGURATION ====================
const upload = multer({ dest: 'uploads/' });
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

async function getGatewayConfig(): Promise<GatewayConfig> {
  const now = Date.now();
  const baseUrl = GATEWAY_URL.replace(/\/$/, '');

  // Reuse token if still valid
  if (gatewayToken && gatewayTokenExpireAt && now < gatewayTokenExpireAt) {
    return { baseUrl, token: gatewayToken };
  }

  // 1) Sign a message with your mnemonic (CESS_PRIVATE_KEY)
  const sign_message = Date.now().toString();
  const signature = safeSignUnixTime(sign_message, PRIVATE_KEY); // PRIVATE_KEY is your mnemonic
  // 2) Ask chain to generate a gateway access token
  const token = await GenGatewayAccessToken(baseUrl, {
    account: cess.getSignatureAcc(),
    message: sign_message,
    sign: u8aToHex(signature),
    expire: 1, // hours
  });

  gatewayToken = token;
  gatewayTokenExpireAt = now + 60 * 60 * 1000;

  return { baseUrl, token };
}


async function init() {
  const cfg: CESSConfig = {
    rpcs: [process.env.RPC_URL || "wss://testnet-rpc.cess.network"],
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
  return url
    .replace(/^https?:\/\//, '')
    .replace(/\/$/, '')
    .toLowerCase();
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

  // same as upload
  const messageBytes = crypto.randomBytes(16);
  const message = messageBytes.toString('hex');

  // ✅ sign ASCII bytes of the hex string
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
  if (obj === null || obj === undefined) {
    return obj;
  }
  
  if (typeof obj === 'bigint') {
    return obj.toString();
  }
  
  if (Array.isArray(obj)) {
    return obj.map(item => serializeBigInt(item));
  }
  
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
  
  let territory = await cess.queryTerritory(accountAddress, myTerritory) as Territory;
  
  if (!territory) {
    console.log('Creating territory...');
    const result = await cess.mintTerritory(1, myTerritory, 30);
    if (result.success) {
      console.log('✅ Territory minted!', { txHash: result.txHash });
      await new Promise(resolve => setTimeout(resolve, 6000));
      territory = await cess.queryTerritory(accountAddress, myTerritory) as Territory;
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
  const ossAccList = await cess.queryOssByAccountId() as unknown as OssDetail[];
  
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
    const availableDomains = ossAccList.map(oss => oss.ossInfo.domain).filter(Boolean);
    throw new Error(
      `Gateway "${GATEWAY_URL}" not found.\n` +
      `Available gateways: ${availableDomains.join(', ')}\n` +
      `Please update GATEWAY_URL in your .env file.`
    );
  }
  
  const authList = await cess.queryAuthorityListByAccountId(gatewayAcc) as unknown as OssAuthorityList[];
  const authorizedAccounts = authList.map(item => item.authorizedAcc);
  
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
    const ossAccList = await cess.queryOssByAccountId() as unknown as OssDetail[];
    const targetGateway = normalizeGatewayUrl(GATEWAY_URL);
    
    const gateways = ossAccList.map(oss => {
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
      foundMatch: gateways.some(g => g.matches),
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

app.post('/api/upload', ensureReady, upload.single('file'), async (req, res) => {
  const localPath = req.file?.path;
  
  try {
    if (!localPath) throw new Error('No file uploaded');
    
    await ensureTerritory();
    await ensureGatewayAuth();
    
    const bucket = process.env.BUCKET_NAME || 'default';
    const territory = TERRITORY;
    const headers = buildUploadHeaders(territory, bucket);
    
    const formData = new FormData();
    formData.append('file', fs.createReadStream(localPath), {
      filename: req.file!.originalname || 'upload.bin',
      contentType: req.file!.mimetype || 'application/octet-stream',
    });
    
    const uploadUrl = `${GATEWAY_URL.replace(/\/$/, '')}/file`;
    console.log('Uploading to:', uploadUrl);
    
    const response = await fetch(uploadUrl, {
      method: 'PUT',
      body: formData,
      headers: {
        ...headers,
        ...formData.getHeaders(),
      } as any,
    });
    
    const rawText = await response.text();
    console.log('Upload response:', {
      status: response.status,
      body: rawText,
    });
    
    if (!response.ok) {
      throw new Error(`Upload failed (${response.status}): ${rawText}`);
    }
    
    let fid = '';
    try {
      const json = JSON.parse(rawText);
      fid = json?.data?.fid || json?.fid || json?.data || '';
    } catch {
      fid = rawText.trim();
    }
    
    if (!fid) {
      throw new Error('No FID returned: ' + rawText);
    }
    
    // Verify file was registered on blockchain
    console.log('Verifying file registration on blockchain...');
    await new Promise(resolve => setTimeout(resolve, 2000));
    
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
      console.log(`Waiting for blockchain registration... (attempt ${attempts}/${maxAttempts})`);
      await new Promise(resolve => setTimeout(resolve, 2000));
    }
    
    if (!verified) {
      console.warn('⚠️ File uploaded but not yet visible on blockchain');
    }
    
    res.json({ 
      fid: fid,
      verified: verified,
      message: verified 
        ? 'File uploaded and registered on blockchain' 
        : 'File uploaded but blockchain registration pending',
    });
  } catch (e: any) {
    console.error('[UPLOAD] Error:', e);
    res.status(500).json({ error: e.message || String(e) });
  } finally {
    if (localPath) fsp.unlink(localPath).catch(() => {});
  }
});

app.post('/api/upload-object', ensureReady, async (req, res) => {
  try {
    const { data } = req.body;
    if (!data) throw new Error('No data provided');
    
    await ensureTerritory();
    await ensureGatewayAuth();
    
    const bucket = process.env.BUCKET_NAME || 'default';
    const territory = TERRITORY;
    const headers = buildUploadHeaders(territory, bucket);
    
    const tempPath = path.join('uploads', `temp_${Date.now()}.txt`);
    await fsp.mkdir(path.dirname(tempPath), { recursive: true });
    await fsp.writeFile(tempPath, data, 'utf-8');
    
    try {
      const formData = new FormData();
      formData.append('file', fs.createReadStream(tempPath), {
        filename: 'object.txt',
        contentType: 'text/plain',
      });
      
      const uploadUrl = `${GATEWAY_URL.replace(/\/$/, '')}/file`;
      
      const response = await fetch(uploadUrl, {
        method: 'PUT',
        body: formData,
        headers: {
          ...headers,
          ...formData.getHeaders(),
        } as any,
      });
      
      const rawText = await response.text();
      
      if (!response.ok) {
        throw new Error(`Gateway error (${response.status}): ${rawText}`);
      }
      
      let fid = '';
      try {
        const json = JSON.parse(rawText);
        fid = json?.data?.fid || json?.fid || json?.data || '';
      } catch {
        fid = rawText.trim();
      }
      
      if (!fid) {
        throw new Error('No FID in gateway response: ' + rawText);
      }
      
      res.json({ fid });
    } finally {
      await fsp.unlink(tempPath).catch(() => {});
    }
  } catch (e: any) {
    console.error('[UPLOAD-OBJECT] Error:', e);
    res.status(500).json({ error: e.message || String(e) });
  }
});

// Fix the buildDownloadHeaders function to match Rust SDK exactly


// Fix the download endpoint URL construction
app.get('/api/download/:fid', ensureReady, async (req, res) => {
  try {
    const fid = req.params.fid;
    console.log('=== Download Request ===');
    console.log('FID:', fid);
    console.log('Gateway URL:', GATEWAY_URL);

    // 1) Check on-chain status (your existing logic)
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

    // 2) Get gateway config (baseUrl + token) using the SDK flow
    const gatewayConfig = await getGatewayConfig();
    console.log('Gateway config:', {
      baseUrl: gatewayConfig.baseUrl,
      hasToken: !!gatewayConfig.token,
    });

    // 3) Choose a temp path to download to
    const tmpPath = path.join('downloads', `${fid}.bin`);
    await fsp.mkdir(path.dirname(tmpPath), { recursive: true });

    // 4) Use the official SDK download helper
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

    // 5) Stream the file back to the client
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


app.get('/api/download-wait/:fid', ensureReady, async (req, res) => {
  try {
    const fid = req.params.fid;
    const maxWaitTime = 5 * 60 * 1000;
    const checkInterval = 10 * 1000;
    const startTime = Date.now();
    
    while (Date.now() - startTime < maxWaitTime) {
      const dealMap = await cess.queryDealMap(fid);
      const fileMeta = await cess.queryFileByFid(fid);
      
      if (fileMeta) {
        console.log('File is ready, downloading...');
        
        let gatewayUrl = GATEWAY_URL;
        if (!gatewayUrl.endsWith('/')) {
          gatewayUrl = gatewayUrl + '/';
        }
        
        const downloadUrl = `${gatewayUrl}download/${fid}`;
        const headers = buildDownloadHeaders();
        
        const response = await fetch(downloadUrl, {
          method: 'GET',
          headers: headers as any,
        });
        
        if (!response.ok) {
          const errorText = await response.text();
          throw new Error(`Download failed (${response.status}): ${errorText}`);
        }
        
        const tmpPath = path.join('downloads', `${fid}.bin`);
        await fsp.mkdir(path.dirname(tmpPath), { recursive: true });
        
        const buffer = await response.buffer();
        await fsp.writeFile(tmpPath, buffer);
        
        return res.download(tmpPath, (err) => {
          fsp.unlink(tmpPath).catch(() => {});
          if (err) console.error('Download send error:', err);
        });
      }
      
      if (dealMap) {
        console.log('File still distributing, waiting...');
        await new Promise(resolve => setTimeout(resolve, checkInterval));
        continue;
      }
      
      throw new Error('File not found on blockchain');
    }
    
    res.status(408).json({
      error: 'Timeout waiting for file distribution',
      fid: fid,
      suggestion: 'File is taking longer than expected. Try again later.',
    });
  } catch (e: any) {
    res.status(500).json({ error: e.message || String(e) });
  }
});

app.get('/api/file-info/:fid', ensureReady, async (req, res) => {
  try {
    const fid = req.params.fid;
    const account = cess.getSignatureAcc();
    
    const dealMap = await cess.queryDealMap(fid);
    const fileMeta = await cess.queryFileByFid(fid);
    const userFileList = await cess.queryUserHoldFileList(account);
    
    const serializedDealMap = dealMap ? serializeBigInt(dealMap) : null;
    const serializedFileMeta = fileMeta ? serializeBigInt(fileMeta) : null;
    const serializedUserFiles = userFileList ? serializeBigInt(userFileList) : null;
    
    const fileInUserList = userFileList?.some((file: any) => {
      const fileFid = file?.fileHash || file?.fid || '';
      return fileFid.toLowerCase() === fid.toLowerCase();
    });
    
    res.json({
      fid: fid,
      account: account,
      dealMap: serializedDealMap,
      fileMeta: serializedFileMeta,
      userFileList: serializedUserFiles,
      fileInUserList: fileInUserList || false,
      state: dealMap ? 'Distributing' : (fileMeta ? 'Stored' : 'Not Found on Blockchain'),
      canDownload: !!fileMeta,
      distributionStuck: dealMap ? 'File has been distributing for a long time' : null,
    });
  } catch (e: any) {
    res.status(500).json({ error: e.message || String(e) });
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

app.get('/api/debug/download-test/:fid', ensureReady, async (req, res) => {
  try {
    const fid = req.params.fid;
    
    let gatewayUrl = GATEWAY_URL;
    if (!gatewayUrl.endsWith('/')) {
      gatewayUrl = gatewayUrl + '/';
    }
    const downloadUrl = `${gatewayUrl}download/${fid}`;
    
    const headers = buildDownloadHeaders();
    
    res.json({
      fid: fid,
      gatewayUrl: GATEWAY_URL,
      normalizedGatewayUrl: gatewayUrl,
      downloadUrl: downloadUrl,
      headers: {
        Operation: headers.Operation,
        Account: headers.Account,
        Message: headers.Message,
        Signature: headers.Signature,
      },
      accountFromCess: cess.getSignatureAcc(),
      accountFromHeaders: headers.Account,
      match: cess.getSignatureAcc() === headers.Account,
    });
  } catch (e: any) {
    res.status(500).json({ error: e.message || String(e) });
  }
});
// Add this endpoint with the other debug endpoints

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

// ==================== SERVER START ====================
app.listen(PORT, () => {
  console.log(`CESS API listening on http://localhost:${PORT}`);
  console.log(`Gateway: ${GATEWAY_URL}`);
  console.log(`Territory: ${TERRITORY}`);
});