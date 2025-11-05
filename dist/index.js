import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import multer from 'multer';
import path from 'path';
import { promises as fsp } from 'fs';
import fs from 'fs';
import fetch from 'node-fetch';
import FormData from 'form-data';
// CESS SDK imports
import { CESS, isKeyringReady, SDKError, } from '@cessnetwork/api';
import { Keyring } from '@polkadot/keyring';
import { stringToU8a } from '@polkadot/util';
import bs58 from 'bs58';
import crypto from 'crypto';
const app = express();
app.use(cors());
app.use(express.json());
const upload = multer({ dest: 'uploads/' });
const GATEWAY_URL = process.env.GATEWAY_URL;
const TERRITORY = process.env.TERRITORY || 'default';
const PORT = Number(process.env.PORT || 8080);
const PRIVATE_KEY = process.env.CESS_PRIVATE_KEY || '';
if (!GATEWAY_URL || !PRIVATE_KEY) {
    console.error('Missing env GATEWAY_URL or CESS_PRIVATE_KEY');
    process.exit(1);
}
let cess;
let ready = false;
let readyP;
// Initialize CESS client (Step 1)
async function init() {
    const cfg = {
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
async function ensureReady(_req, _res, next) {
    if (!ready)
        await readyP;
    next();
}
// Helper: Normalize gateway URL
function normalizeGatewayUrl(url) {
    return url
        .replace(/^https?:\/\//, '')
        .replace(/\/$/, '')
        .toLowerCase();
}
// Helper: Build upload headers (matches Rust SDK exactly)
function buildUploadHeaders(territory, bucket) {
    const keyring = new Keyring({ type: 'sr25519', ss58Format: 42 });
    const pair = keyring.addFromUri(PRIVATE_KEY);
    const account = pair.address;
    // Generate random 16-byte message (hex string, like Rust get_random_code)
    const messageBytes = crypto.randomBytes(16);
    const message = messageBytes.toString('hex');
    // Sign message (as bytes, like Rust)
    const signatureBytes = pair.sign(stringToU8a(message));
    const signature = bs58.encode(signatureBytes); // Base58, like Rust to_base58()
    return {
        Bucket: bucket,
        Territory: territory,
        Account: account,
        Message: message,
        Signature: signature,
    };
}
// Helper: Build download headers
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
// Helper: Ensure territory exists (Step 3)
async function ensureTerritory() {
    const accountAddress = cess.getSignatureAcc();
    const myTerritory = TERRITORY;
    const curBlockHeight = await cess.queryBlockNumberByHash();
    let territory = await cess.queryTerritory(accountAddress, myTerritory);
    if (!territory) {
        console.log('Creating territory...');
        const result = await cess.mintTerritory(1, myTerritory, 30);
        if (result.success) {
            console.log('✅ Territory minted!', { txHash: result.txHash });
            await new Promise(resolve => setTimeout(resolve, 6000));
            territory = await cess.queryTerritory(accountAddress, myTerritory);
        }
        else {
            throw new Error('Territory minting failed: ' + result.error);
        }
    }
    else if (territory.deadline - curBlockHeight <= 100800) {
        await cess.renewalTerritory(myTerritory, 10);
    }
    else if (territory.state !== 'Active' || curBlockHeight >= territory.deadline) {
        await cess.reactivateTerritory(myTerritory, 30);
    }
    else if (territory.remainingSpace <= 1024 * 1024 * 1024) {
        await cess.expandingTerritory(myTerritory, 1);
    }
    return territory;
}
// Helper: Ensure gateway authorization (Step 4)
async function ensureGatewayAuth() {
    const accountAddress = cess.getSignatureAcc();
    const ossAccList = await cess.queryOssByAccountId();
    if (ossAccList.length === 0) {
        throw new Error('No OSS gateways found on-chain.');
    }
    const targetGateway = normalizeGatewayUrl(GATEWAY_URL);
    let gatewayAcc;
    let gatewayDomain;
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
        throw new Error(`Gateway "${GATEWAY_URL}" not found.\n` +
            `Available gateways: ${availableDomains.join(', ')}\n` +
            `Please update GATEWAY_URL in your .env file.`);
    }
    const authList = await cess.queryAuthorityListByAccountId(gatewayAcc);
    const authorizedAccounts = authList.map(item => item.authorizedAcc);
    if (!authorizedAccounts.includes(accountAddress)) {
        console.log('Authorizing gateway...');
        const result = await cess.authorize(gatewayAcc);
        if (!result.success) {
            throw new Error('Authorization failed: ' + result.error);
        }
        console.log('✅ Authorization successful!', { txHash: result.txHash });
    }
    else {
        console.log('✅ Already authorized');
    }
    return { gatewayAcc, gatewayDomain };
}
// ==================== DEBUG ENDPOINTS ====================
// Debug endpoint: Check account info
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
    }
    catch (e) {
        res.status(500).json({ error: e.message || String(e) });
    }
});
// Debug endpoint: List available gateways
app.get('/api/debug/gateways', ensureReady, async (_req, res) => {
    try {
        const ossAccList = await cess.queryOssByAccountId();
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
    }
    catch (e) {
        res.status(500).json({ error: e.message || String(e) });
    }
});
// ==================== MAIN API ENDPOINTS ====================
// API: Ensure territory + authorization
app.post('/api/ensure-territory', ensureReady, async (_req, res) => {
    try {
        await ensureTerritory();
        await ensureGatewayAuth();
        res.json({ ok: true });
    }
    catch (e) {
        console.error(e);
        res.status(500).json({ ok: false, error: e.message || String(e) });
    }
});
// API: Upload file - Direct signature auth (like Rust SDK)
// Enhanced upload endpoint with blockchain verification
app.post('/api/upload', ensureReady, upload.single('file'), async (req, res) => {
    const localPath = req.file?.path;
    try {
        if (!localPath)
            throw new Error('No file uploaded');
        await ensureTerritory();
        await ensureGatewayAuth();
        const bucket = process.env.BUCKET_NAME || 'default';
        const territory = TERRITORY;
        const headers = buildUploadHeaders(territory, bucket);
        const formData = new FormData();
        formData.append('file', fs.createReadStream(localPath), {
            filename: req.file.originalname || 'upload.bin',
            contentType: req.file.mimetype || 'application/octet-stream',
        });
        const uploadUrl = `${GATEWAY_URL.replace(/\/$/, '')}/file`;
        console.log('Uploading to:', uploadUrl);
        const response = await fetch(uploadUrl, {
            method: 'PUT',
            body: formData,
            headers: {
                ...headers,
                ...formData.getHeaders(),
            },
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
        }
        catch {
            fid = rawText.trim();
        }
        if (!fid) {
            throw new Error('No FID returned: ' + rawText);
        }
        // IMPORTANT: Verify file was registered on blockchain
        console.log('Verifying file registration on blockchain...');
        // Wait a bit for blockchain registration
        await new Promise(resolve => setTimeout(resolve, 2000));
        // Check if file appears in deal map or file meta
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
            // Still return FID - it might register later
        }
        res.json({
            fid: fid,
            verified: verified,
            message: verified
                ? 'File uploaded and registered on blockchain'
                : 'File uploaded but blockchain registration pending',
        });
    }
    catch (e) {
        console.error('[UPLOAD] Error:', e);
        res.status(500).json({ error: e.message || String(e) });
    }
    finally {
        if (localPath)
            fsp.unlink(localPath).catch(() => { });
    }
});
// API: Upload object (string data) - Like Rust upload_object()
app.post('/api/upload-object', ensureReady, async (req, res) => {
    try {
        const { data } = req.body;
        if (!data)
            throw new Error('No data provided');
        // Ensure territory and authorization
        await ensureTerritory();
        await ensureGatewayAuth();
        const bucket = process.env.BUCKET_NAME || 'default';
        const territory = TERRITORY;
        const headers = buildUploadHeaders(territory, bucket);
        // Write data to temp file
        const tempPath = path.join('uploads', `temp_${Date.now()}.txt`);
        await fsp.mkdir(path.dirname(tempPath), { recursive: true });
        await fsp.writeFile(tempPath, data, 'utf-8');
        try {
            // Create FormData
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
                },
            });
            const rawText = await response.text();
            if (!response.ok) {
                throw new Error(`Gateway error (${response.status}): ${rawText}`);
            }
            let fid = '';
            try {
                const json = JSON.parse(rawText);
                fid = json?.data?.fid || json?.fid || json?.data || '';
            }
            catch {
                fid = rawText.trim();
            }
            if (!fid) {
                throw new Error('No FID in gateway response: ' + rawText);
            }
            res.json({ fid });
        }
        finally {
            await fsp.unlink(tempPath).catch(() => { });
        }
    }
    catch (e) {
        console.error('[UPLOAD-OBJECT] Error:', e);
        res.status(500).json({ error: e.message || String(e) });
    }
});
// API: Download file - Direct signature auth
// Helper: Get CESS SS58 address (matches Rust get_pair_address_as_ss58_address)
function getCessAccountAddress() {
    const keyring = new Keyring({ type: 'sr25519', ss58Format: 42 }); // CESS format
    const pair = keyring.addFromUri(PRIVATE_KEY);
    return pair.address; // Already in SS58 format 42
}
// API: Check file status on blockchain
// Helper: Convert BigInt to string for JSON serialization
// API: Check file status on blockchain - FIXED for BigInt
// Helper: Serialize BigInt for JSON
function serializeBigInt(obj) {
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
        const serialized = {};
        for (const [key, value] of Object.entries(obj)) {
            serialized[key] = serializeBigInt(value);
        }
        return serialized;
    }
    return obj;
}
// API: Enhanced file info with detailed status
app.get('/api/file-info/:fid', ensureReady, async (req, res) => {
    try {
        const fid = req.params.fid;
        const account = cess.getSignatureAcc();
        // Check deal map (distributing)
        const dealMap = await cess.queryDealMap(fid);
        // Check file metadata (stored)
        const fileMeta = await cess.queryFileByFid(fid);
        // Check user's file list (to see if file is registered to user)
        const userFileList = await cess.queryUserHoldFileList(account);
        // Serialize BigInt values
        const serializedDealMap = dealMap ? serializeBigInt(dealMap) : null;
        const serializedFileMeta = fileMeta ? serializeBigInt(fileMeta) : null;
        const serializedUserFiles = userFileList ? serializeBigInt(userFileList) : null;
        // Check if file is in user's list
        const fileInUserList = userFileList?.some((file) => {
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
    }
    catch (e) {
        res.status(500).json({ error: e.message || String(e) });
    }
});
// API: Check if file exists at all
app.get('/api/file-exists/:fid', ensureReady, async (req, res) => {
    try {
        const fid = req.params.fid;
        // Try multiple queries
        const dealMap = await cess.queryDealMap(fid);
        const fileMeta = await cess.queryFileByFid(fid);
        res.json({
            fid: fid,
            existsInDealMap: !!dealMap,
            existsInFileMeta: !!fileMeta,
            exists: !!(dealMap || fileMeta),
            dealMapDetails: dealMap ? serializeBigInt(dealMap) : null,
            fileMetaDetails: fileMeta ? serializeBigInt(fileMeta) : null,
        });
    }
    catch (e) {
        res.status(500).json({ error: e.message || String(e) });
    }
});
// API: Test download with detailed logging
app.get('/api/test-download/:fid', ensureReady, async (req, res) => {
    try {
        const fid = req.params.fid;
        // Check file status first
        const dealMap = await cess.queryDealMap(fid);
        const fileMeta = await cess.queryFileByFid(fid);
        if (!dealMap && !fileMeta) {
            return res.status(404).json({
                error: 'File not found on blockchain',
                fid: fid,
                suggestion: 'File may not have been uploaded, or FID is incorrect',
            });
        }
        if (dealMap && !fileMeta) {
            return res.status(202).json({
                error: 'File is still distributing to storage nodes',
                fid: fid,
                dealMap: dealMap,
                suggestion: 'Wait a few minutes and try again',
            });
        }
        // Build download URL
        let gatewayUrl = GATEWAY_URL;
        if (!gatewayUrl.endsWith('/')) {
            gatewayUrl = gatewayUrl + '/';
        }
        const downloadUrl = `${gatewayUrl}download/${fid}`;
        // Build headers
        const headers = buildDownloadHeaders();
        console.log('=== Download Test Debug ===');
        console.log('FID:', fid);
        console.log('Download URL:', downloadUrl);
        console.log('Account:', headers.Account);
        console.log('Message:', headers.Message);
        console.log('Signature (first 20 chars):', headers.Signature.substring(0, 20));
        // Make request
        const response = await fetch(downloadUrl, {
            method: 'GET',
            headers: headers,
        });
        const responseText = await response.text();
        console.log('Response Status:', response.status);
        console.log('Response Headers:', Object.fromEntries(response.headers.entries()));
        console.log('Response Body (first 200 chars):', responseText.substring(0, 200));
        if (!response.ok) {
            return res.status(response.status).json({
                error: `Download failed (${response.status})`,
                fid: fid,
                url: downloadUrl,
                account: headers.Account,
                response: responseText,
                fileMeta: fileMeta,
            });
        }
        res.json({
            success: true,
            fid: fid,
            size: responseText.length,
            contentType: response.headers.get('content-type'),
            preview: responseText.substring(0, 100),
        });
    }
    catch (e) {
        res.status(500).json({ error: e.message || String(e) });
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
        const downloadUrl = `${gatewayUrl}download/${fid}`;
        const headers = buildDownloadHeaders();
        console.log('Attempting download:', {
            fid: fid,
            url: downloadUrl,
            account: headers.Account,
        });
        // Try to download directly (like Rust SDK does)
        const response = await fetch(downloadUrl, {
            method: 'GET',
            headers: headers,
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
            fsp.unlink(tmpPath).catch(() => { });
            if (err)
                console.error('Download send error:', err);
        });
    }
    catch (e) {
        console.error('[DOWNLOAD] Error:', e);
        res.status(500).json({ error: e.message || String(e) });
    }
});
// API: Force download (bypasses status check)
app.get('/api/force-download/:fid', ensureReady, async (req, res) => {
    try {
        const fid = req.params.fid;
        let gatewayUrl = GATEWAY_URL;
        if (!gatewayUrl.endsWith('/')) {
            gatewayUrl = gatewayUrl + '/';
        }
        const downloadUrl = `${gatewayUrl}download/${fid}`;
        const headers = buildDownloadHeaders();
        console.log('Force downloading (ignoring blockchain status):', downloadUrl);
        const response = await fetch(downloadUrl, {
            method: 'GET',
            headers: headers,
        });
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Download failed (${response.status}): ${errorText}`);
        }
        const tmpPath = path.join('downloads', `${fid}.bin`);
        await fsp.mkdir(path.dirname(tmpPath), { recursive: true });
        const buffer = await response.buffer();
        await fsp.writeFile(tmpPath, buffer);
        res.download(tmpPath, (err) => {
            fsp.unlink(tmpPath).catch(() => { });
            if (err)
                console.error('Download send error:', err);
        });
    }
    catch (e) {
        res.status(500).json({ error: e.message || String(e) });
    }
});
// API: Download file - FIXED URL format
// API: Download with auto-retry (waits for distribution)
app.get('/api/download-wait/:fid', ensureReady, async (req, res) => {
    try {
        const fid = req.params.fid;
        const maxWaitTime = 5 * 60 * 1000; // 5 minutes
        const checkInterval = 10 * 1000; // Check every 10 seconds
        const startTime = Date.now();
        // Poll until file is stored
        while (Date.now() - startTime < maxWaitTime) {
            const dealMap = await cess.queryDealMap(fid);
            const fileMeta = await cess.queryFileByFid(fid);
            if (fileMeta) {
                // File is stored, proceed with download
                console.log('File is ready, downloading...');
                let gatewayUrl = GATEWAY_URL;
                if (!gatewayUrl.endsWith('/')) {
                    gatewayUrl = gatewayUrl + '/';
                }
                const downloadUrl = `${gatewayUrl}download/${fid}`;
                const headers = buildDownloadHeaders();
                const response = await fetch(downloadUrl, {
                    method: 'GET',
                    headers: headers,
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
                    fsp.unlink(tmpPath).catch(() => { });
                    if (err)
                        console.error('Download send error:', err);
                });
            }
            if (dealMap) {
                console.log('File still distributing, waiting...');
                await new Promise(resolve => setTimeout(resolve, checkInterval));
                continue;
            }
            // File not found
            throw new Error('File not found on blockchain');
        }
        // Timeout
        res.status(408).json({
            error: 'Timeout waiting for file distribution',
            fid: fid,
            suggestion: 'File is taking longer than expected. Try again later.',
        });
    }
    catch (e) {
        res.status(500).json({ error: e.message || String(e) });
    }
});
// API: Download file - UPDATED with better error handling
// API: Download file - Try even if distributing
app.get('/api/download/:fid', ensureReady, async (req, res) => {
    try {
        const fid = req.params.fid;
        // Check status but don't block if distributing
        const dealMap = await cess.queryDealMap(fid);
        const fileMeta = await cess.queryFileByFid(fid);
        // If file exists (even if distributing), try to download
        if (!dealMap && !fileMeta) {
            return res.status(404).json({
                error: 'File not found on blockchain',
                fid: fid,
            });
        }
        // Try download even if status shows "Distributing"
        let gatewayUrl = GATEWAY_URL;
        if (!gatewayUrl.endsWith('/')) {
            gatewayUrl = gatewayUrl + '/';
        }
        const downloadUrl = `${gatewayUrl}download/${fid}`;
        const headers = buildDownloadHeaders();
        console.log('Attempting download (status may show distributing):', {
            fid: fid,
            dealMap: !!dealMap,
            fileMeta: !!fileMeta,
        });
        const response = await fetch(downloadUrl, {
            method: 'GET',
            headers: headers,
        });
        if (!response.ok) {
            const errorText = await response.text();
            if (response.status === 404 && dealMap) {
                return res.status(202).json({
                    error: 'File is still distributing',
                    fid: fid,
                    state: 'Distributing',
                    suggestion: 'File is being distributed to storage nodes. Please wait and try again later.',
                });
            }
            throw new Error(`Download failed (${response.status}): ${errorText}`);
        }
        // File downloaded successfully!
        const tmpPath = path.join('downloads', `${fid}.bin`);
        await fsp.mkdir(path.dirname(tmpPath), { recursive: true });
        const buffer = await response.buffer();
        await fsp.writeFile(tmpPath, buffer);
        console.log(`✅ File downloaded successfully: ${tmpPath} (${buffer.length} bytes)`);
        res.download(tmpPath, (err) => {
            fsp.unlink(tmpPath).catch(() => { });
            if (err)
                console.error('Download send error:', err);
        });
    }
    catch (e) {
        console.error('[DOWNLOAD] Error:', e);
        res.status(500).json({ error: e.message || String(e) });
    }
});
// API: Query file status
app.get('/api/status/:fid', ensureReady, async (req, res) => {
    try {
        const fid = req.params.fid;
        const dealMap = await cess.queryDealMap(fid);
        if (dealMap) {
            res.json({ state: 'Distributing', dealMap });
        }
        else {
            const meta = await cess.queryFileByFid(fid);
            res.json({ state: 'Stored', meta });
        }
    }
    catch (e) {
        res.status(500).json({ error: e.message || String(e) });
    }
});
app.listen(PORT, () => {
    console.log(`CESS API listening on http://localhost:${PORT}`);
    console.log(`Gateway: ${GATEWAY_URL}`);
    console.log(`Territory: ${TERRITORY}`);
});
