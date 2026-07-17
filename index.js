const http = require('http');
const https = require('https');
const crypto = require('crypto');

const WEBHOOK_URL = process.env.WEBHOOK_URL || null;
const WEBHOOK_VERIFICATION_TOKEN = process.env.WEBHOOK_VERIFICATION_TOKEN || 'rc-webhook-verify-token';
let webhookSubscriptionId = null;
let webhookRenewalTimer = null;

const RC_CLIENT_ID = process.env.RC_CLIENT_ID;
const RC_CLIENT_SECRET = process.env.RC_CLIENT_SECRET;
const RC_JWT = process.env.RC_JWT;

let tokenCache = null;
let tokenExpiry = 0;

// --- RC API Rate Limiter (max 2 concurrent requests) ---
let rcActiveRequests = 0;
const RC_MAX_CONCURRENT = 3;
const rcQueue = [];
let rcRateLimitedUntil = 0;

function rcThrottle(fn) {
  return new Promise((resolve, reject) => {
    const now = Date.now();
    if (now < rcRateLimitedUntil) {
      return reject(new Error('RC error CMN-301: Request rate exceeded (cooldown)'));
    }
    const run = () => {
      rcActiveRequests++;
      fn().then(result => {
        resolve(result);
      }).catch(err => {
        if (err.message && err.message.includes('CMN-301')) {
          rcRateLimitedUntil = Date.now() + 120000;
          console.log('[RATE LIMIT] CMN-301 hit, cooling down 2 minutes');
        }
        reject(err);
      }).finally(() => {
        rcActiveRequests--;
        if (rcQueue.length > 0) rcQueue.shift()();
      });
    };
    if (rcActiveRequests < RC_MAX_CONCURRENT) {
      run();
    } else {
      rcQueue.push(run);
    }
  });
}

// --- Caching ---
const presenceCache = new Map();
const PRESENCE_TTL = 60 * 1000; // 60 seconds - RC heavy API limit is 10 req/60sec per extension, webhook updates instantly

const queueMembersCache = new Map();
const QUEUE_MEMBERS_TTL = 30 * 60 * 1000; // 30 minutes

let queuesCache = null;
let queuesCacheExpiry = 0;
const QUEUES_TTL = 5 * 60 * 1000; // 5 minutes

let extensionsCache = null;
let extensionsCacheExpiry = 0;
const EXTENSIONS_TTL = 10 * 60 * 1000; // 10 minutes

async function getPresenceCached(token, extensionId) {
  const now = Date.now();
  const cached = presenceCache.get(extensionId);
  if (cached && now < cached.expiry) return cached.data;
  try {
    const data = await rcThrottle(() => getPresence(token, extensionId));
    if (data) presenceCache.set(extensionId, { data, expiry: now + PRESENCE_TTL });
    return data;
  } catch (err) {
    if (err.message && err.message.includes('CMN-301')) {
      if (cached) {
        presenceCache.set(extensionId, { data: cached.data, expiry: now + 20 * 1000 });
        return cached.data;
      }
    }
    if (cached) return cached.data;
    throw err;
  }
}

async function getQueueMembersCached(token, queueId) {
  const now = Date.now();
  const cached = queueMembersCache.get(queueId);
  if (cached && now < cached.expiry) return cached.data;
  try {
    const data = await rcThrottle(() => getQueueMembers(token, queueId));
    queueMembersCache.set(queueId, { data, expiry: now + QUEUE_MEMBERS_TTL });
    return data;
  } catch (err) {
    if (cached) return cached.data;
    throw err;
  }
}

async function getQueuesCached(token) {
  const now = Date.now();
  if (queuesCache && now < queuesCacheExpiry) return queuesCache;
  try {
    const data = await rcThrottle(() => getQueues(token));
    queuesCache = data;
    queuesCacheExpiry = now + QUEUES_TTL;
    return data;
  } catch (err) {
    if (queuesCache) return queuesCache;
    throw err;
  }
}

async function getExtensionsCached(token) {
  const now = Date.now();
  if (extensionsCache && now < extensionsCacheExpiry) return extensionsCache;
  try {
    const data = await getExtensions(token);
    extensionsCache = data;
    extensionsCacheExpiry = now + EXTENSIONS_TTL;
    return data;
  } catch (err) {
    if (extensionsCache) return extensionsCache;
    throw err;
  }
}

// --- State map ---
const STATE_NAME_MAP = {
  'AL': 'Alabama', 'AK': 'Alaska', 'AZ': 'Arizona', 'AR': 'Arkansas',
  'CA': 'California', 'CO': 'Colorado', 'CT': 'Connecticut', 'DE': 'Delaware',
  'FL': 'Florida', 'GA': 'Georgia', 'HI': 'Hawaii', 'ID': 'Idaho',
  'IL': 'Illinois', 'IN': 'Indiana', 'IA': 'Iowa', 'KS': 'Kansas',
  'KY': 'Kentucky', 'LA': 'Louisiana', 'ME': 'Maine', 'MD': 'Maryland',
  'MA': 'Massachusetts', 'MI': 'Michigan', 'MN': 'Minnesota', 'MS': 'Mississippi',
  'MO': 'Missouri', 'MT': 'Montana', 'NE': 'Nebraska', 'NV': 'Nevada',
  'NH': 'New Hampshire', 'NJ': 'New Jersey', 'NM': 'New Mexico', 'NY': 'New York',
  'NC': 'North Carolina', 'ND': 'North Dakota', 'OH': 'Ohio', 'OK': 'Oklahoma',
  'OR': 'Oregon', 'PA': 'Pennsylvania', 'RI': 'Rhode Island', 'SC': 'South Carolina',
  'SD': 'South Dakota', 'TN': 'Tennessee', 'TX': 'Texas', 'UT': 'Utah',
  'VT': 'Vermont', 'VA': 'Virginia', 'WA': 'Washington', 'DC': 'Washington, DC',
  'WV': 'West Virginia', 'WI': 'Wisconsin', 'WY': 'Wyoming'
};

// --- Agent map (legacy) ---
const AGENT_MAP = {
  '0000as': 'MI - April Simpson',
  '0000by': 'MI - Bebeto Yewah',
  '0000dt': 'MI - Dylan Trout',
  '0000lt': 'MI - Lee Trawick',
};

// --- Tampa queue shortcuts ---
// Add Tampa queue names here once confirmed by Mark/Edmar
const TAMPA_QUEUE_SHORTCUTS = {
  // '/queue/tampa-vip': 'Tampa VIP Response',
  // '/queue/tampa-general': 'Tampa General',
};

// --- RC API functions ---
async function getAccessToken() {
  const now = Date.now();
  if (tokenCache && now < tokenExpiry) return tokenCache;
  return new Promise((resolve, reject) => {
    const credentials = Buffer.from(`${RC_CLIENT_ID}:${RC_CLIENT_SECRET}`).toString('base64');
    const body = `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${RC_JWT}`;
    const options = {
      hostname: 'platform.ringcentral.com',
      path: '/restapi/oauth/token',
      method: 'POST',
      headers: {
        'Authorization': `Basic ${credentials}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      }
    };
    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          if (json.access_token) {
            tokenCache = json.access_token;
            tokenExpiry = now + (55 * 60 * 1000);
            resolve(tokenCache);
          } else {
            reject(new Error('No access token: ' + data));
          }
        } catch(e) {
          reject(new Error('Failed to parse token response: ' + data));
        }
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

async function getQueues(token) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: 'platform.ringcentral.com',
      path: '/restapi/v1.0/account/~/call-queues?perPage=200',
      method: 'GET',
      headers: { 'Authorization': `Bearer ${token}` }
    };
    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          if (json.errorCode && json.errorCode.includes('CMN-301')) reject(new Error('RC error CMN-301: Request rate exceeded'));
          else resolve(json);
        }
        catch(e) { reject(new Error('Failed to parse queues: ' + data)); }
      });
    });
    req.on('error', reject);
    req.end();
  });
}

async function getQueueMembers(token, queueId) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: 'platform.ringcentral.com',
      path: `/restapi/v1.0/account/~/call-queues/${queueId}/members?perPage=200`,
      method: 'GET',
      headers: { 'Authorization': `Bearer ${token}` }
    };
    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          if (json.errorCode) reject(new Error(`RC error ${json.errorCode}: ${json.message}`));
          else resolve(json);
        }
        catch(e) { reject(new Error('Failed to parse members: ' + data)); }
      });
    });
    req.on('error', reject);
    req.end();
  });
}

async function getPresence(token, extensionId) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: 'platform.ringcentral.com',
      path: `/restapi/v1.0/account/~/extension/${extensionId}/presence`,
      method: 'GET',
      headers: { 'Authorization': `Bearer ${token}` }
    };
    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          if (json.errorCode && json.errorCode.includes('CMN-301')) {
            reject(new Error('RC error CMN-301: Request rate exceeded'));
          } else {
            resolve(json);
          }
        }
        catch(e) { resolve(null); }
      });
    });
    req.on('error', () => resolve(null));
    req.end();
  });
}

async function getExtensions(token) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: 'platform.ringcentral.com',
      path: '/restapi/v1.0/account/~/extension?perPage=200&type=User&status=Enabled',
      method: 'GET',
      headers: { 'Authorization': `Bearer ${token}` }
    };
    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch(e) { reject(new Error('Failed to parse extensions: ' + data)); }
      });
    });
    req.on('error', reject);
    req.end();
  });
}

// --- Availability check functions ---
async function checkQueueAvailability(queueName) {
  const token = await getAccessToken();
  const queuesData = await getQueuesCached(token);
  const queues = queuesData.records || [];

  const matchedQueue = queues.find(q =>
    q.name.toLowerCase() === queueName.toLowerCase()
  );

  if (!matchedQueue) {
    return { available: false, agents: 0, reason: `No queue found for: ${queueName}` };
  }

  const membersData = await getQueueMembersCached(token, matchedQueue.id);
  const members = membersData.records || [];

  const presenceResults = await Promise.all(
    members.map(m => getPresenceCached(token, m.id).catch(() => null))
  );

  const availableAgents = presenceResults.filter(p => {
    if (!p) return false;
    return (
      p.presenceStatus === 'Available' &&
      p.dndStatus === 'TakeAllCalls' &&
      p.telephonyStatus === 'NoCall'
    );
  });

  const activeCalls = presenceResults.filter(p => {
    if (!p) return false;
    return p.telephonyStatus === 'CallConnected' || p.telephonyStatus === 'OnHold' || p.telephonyStatus === 'Ringing';
  }).length;

  return {
    available: availableAgents.length > 0,
    agents: availableAgents.length,
    active_calls: activeCalls,
    total_members: members.length,
    queue: matchedQueue.name
  };
}

async function checkAvailabilityWithMinAgents(stateUpper, office, minAgents) {
  const result = await checkAvailability(stateUpper, office);
  if (minAgents && result.agents < minAgents) {
    return { ...result, available: false, reason: `Not enough agents: ${result.agents} available, ${minAgents} required` };
  }
  return result;
}

async function checkAvailability(stateUpper, office) {
  const stateName = STATE_NAME_MAP[stateUpper] || stateUpper;
  const queueName = office ? `${stateName} - ${office}` : stateName;
  const result = await checkQueueAvailability(queueName);
  return { ...result, state: stateUpper, state_name: stateName, office: office || 'main' };
}

// --- RC Webhook Subscription ---
async function createWebhookSubscription(token) {
  if (!WEBHOOK_URL) {
    console.log('WEBHOOK_URL not set, skipping webhook subscription');
    return;
  }
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({
      eventFilters: [
        '/restapi/v1.0/account/~/extension/~/presence?detailedTelephonyState=true'
      ],
      deliveryMode: {
        transportType: 'WebHook',
        address: `${WEBHOOK_URL}/webhook/presence`,
        verificationToken: WEBHOOK_VERIFICATION_TOKEN
      },
      expiresIn: 86400
    });
    const options = {
      hostname: 'platform.ringcentral.com',
      path: '/restapi/v1.0/subscription',
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body)
      }
    };
    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          if (json.id) {
            webhookSubscriptionId = json.id;
            console.log(`RC webhook subscription created: ${json.id}`);
            scheduleWebhookRenewal();
            resolve(json);
          } else {
            console.error('Webhook subscription failed:', data);
            resolve(null);
          }
        } catch(e) { resolve(null); }
      });
    });
    req.on('error', (err) => { console.error('Webhook subscription error:', err.message); resolve(null); });
    req.write(body);
    req.end();
  });
}

function scheduleWebhookRenewal() {
  if (webhookRenewalTimer) clearTimeout(webhookRenewalTimer);
  webhookRenewalTimer = setTimeout(async () => {
    try {
      console.log('Renewing RC webhook subscription...');
      const token = await getAccessToken();
      await createWebhookSubscription(token);
    } catch(err) {
      console.error('Webhook renewal failed:', err.message);
    }
  }, 23 * 60 * 60 * 1000);
}

function handleWebhookPresence(body) {
  try {
    const data = JSON.parse(body);
    const presence = data.body || data;
    const extensionId = presence.extensionId ||
      (presence.extension && presence.extension.id) ||
      (data.body && data.body.extension && data.body.extension.id);
    if (!extensionId) {
      console.log('[WEBHOOK] No extensionId found in payload:', JSON.stringify(data).slice(0, 300));
      return;
    }
    const prev = presenceCache.get(String(extensionId));
    const prevStatus = prev ? `${prev.data.presenceStatus}/${prev.data.telephonyStatus}` : 'none';
    presenceCache.set(String(extensionId), {
      data: presence,
      expiry: Date.now() + (60 * 1000)
    });
    console.log(`[WEBHOOK] ext ${extensionId}: ${prevStatus} → ${presence.presenceStatus}/${presence.telephonyStatus} dnd=${presence.dndStatus}`);
  } catch(e) {
    console.error('[WEBHOOK] Parse error:', e.message, body.slice(0, 200));
  }
}

// --- Cache warmup ---
async function warmupCache() {
  try {
    const token = await getAccessToken();
    const queuesData = await getQueuesCached(token);
    const queues = queuesData.records || [];
    await Promise.all(
      queues.map(q => getQueueMembersCached(token, q.id).catch(() => null))
    );
    console.log(`Cache warmed: ${queues.length} queues (presence fetched on-demand)`);
  } catch (err) {
    console.error('Cache warmup failed:', err.message);
  }
}

// --- HTTP Server ---
const server = http.createServer(async (req, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Access-Control-Allow-Origin', '*');

  const url = new URL(req.url, `http://${req.headers.host}`);
  const pathname = url.pathname;

  if (pathname === '/' || pathname === '/health') {
    res.writeHead(200);
    return res.end(JSON.stringify({ status: 'ok', message: 'Availability API is running' }));
  }

  // Manual cooldown control: /cooldown?minutes=10
  if (pathname === '/cooldown') {
    const minutes = parseInt(url.searchParams.get('minutes') || '10', 10);
    rcRateLimitedUntil = Date.now() + minutes * 60 * 1000;
    const until = new Date(rcRateLimitedUntil).toISOString();
    console.log(`[RATE LIMIT] Manual cooldown activated for ${minutes} minutes (until ${until})`);
    res.writeHead(200);
    return res.end(JSON.stringify({ status: 'cooldown_active', minutes, until }));
  }

  // Cooldown status: /cooldown/status
  if (pathname === '/cooldown/status') {
    const now = Date.now();
    const active = now < rcRateLimitedUntil;
    const remainingMs = active ? rcRateLimitedUntil - now : 0;
    res.writeHead(200);
    return res.end(JSON.stringify({
      active,
      remaining_seconds: Math.round(remainingMs / 1000),
      until: active ? new Date(rcRateLimitedUntil).toISOString() : null
    }));
  }

  // Legacy: state-based availability /availability?state=FL
  if (pathname === '/availability') {
    const state = url.searchParams.get('state');
    if (!state) {
      res.writeHead(400);
      return res.end(JSON.stringify({ available: false, error: 'Missing state parameter. Use ?state=TX' }));
    }
    const stateUpper = state.toUpperCase().trim();
    const office = url.searchParams.get('office') ? url.searchParams.get('office').trim() : null;
    const minAgentsParam = url.searchParams.get('min_agents');
    const minAgents = minAgentsParam ? parseInt(minAgentsParam, 10) : null;
    try {
      const result = await checkAvailabilityWithMinAgents(stateUpper, office, minAgents);
      res.writeHead(200);
      return res.end(JSON.stringify(result));
    } catch (err) {
      console.error('Error:', err.message);
      const status = err.message && err.message.includes('CMN-301') ? 200 : 500;
      res.writeHead(status);
      return res.end(JSON.stringify({ available: false, error: err.message }));
    }
  }

  // Legacy: agent by ID /agent?id=0000as
  if (pathname === '/agent') {
    const id = url.searchParams.get('id');
    if (!id) {
      res.writeHead(400);
      return res.end(JSON.stringify({ available: false, error: 'Missing id parameter' }));
    }
    const queueName = AGENT_MAP[id.toLowerCase().trim()];
    if (!queueName) {
      res.writeHead(404);
      return res.end(JSON.stringify({ available: false, error: 'Unknown agent id' }));
    }
    try {
      const result = await checkQueueAvailability(queueName);
      res.writeHead(200);
      return res.end(JSON.stringify(result));
    } catch (err) {
      console.error('Error:', err.message);
      const status = err.message && err.message.includes('CMN-301') ? 200 : 500;
      res.writeHead(status);
      return res.end(JSON.stringify({ available: false, error: err.message }));
    }
  }

  // Queue by name: /queue?name=Tampa+VIP
  if (pathname === '/queue') {
    const name = url.searchParams.get('name');
    if (!name) {
      res.writeHead(400);
      return res.end(JSON.stringify({ available: false, error: 'Missing name parameter. Use ?name=QueueName' }));
    }
    try {
      const result = await checkQueueAvailability(name.trim());
      res.writeHead(200);
      return res.end(JSON.stringify(result));
    } catch (err) {
      console.error('Error:', err.message);
      const status = err.message && err.message.includes('CMN-301') ? 200 : 500;
      res.writeHead(status);
      return res.end(JSON.stringify({ available: false, error: err.message }));
    }
  }

  // Tampa queue shortcuts
  if (TAMPA_QUEUE_SHORTCUTS[pathname]) {
    try {
      const result = await checkQueueAvailability(TAMPA_QUEUE_SHORTCUTS[pathname]);
      res.writeHead(200);
      return res.end(JSON.stringify(result));
    } catch (err) {
      console.error('Error:', err.message);
      const status = err.message && err.message.includes('CMN-301') ? 200 : 500;
      res.writeHead(status);
      return res.end(JSON.stringify({ available: false, error: err.message }));
    }
  }

  // List all queues
  if (pathname === '/queues') {
    try {
      const token = await getAccessToken();
      const queuesData = await getQueuesCached(token);
      const queues = queuesData.records || [];
      res.writeHead(200);
      return res.end(JSON.stringify({
        total: queues.length,
        queues: queues.map(q => ({ id: q.id, name: q.name }))
      }));
    } catch (err) {
      console.error('Error:', err.message);
      res.writeHead(500);
      return res.end(JSON.stringify({ error: err.message }));
    }
  }

  // Debug: all agents presence
  if (pathname === '/agents/debug') {
    try {
      const token = await getAccessToken();
      const extData = await getExtensionsCached(token);
      const extensions = (extData.records || []).map(e => e.extensionNumber);
      const results = await Promise.all(extensions.map(async (ext) => {
        try {
          const json = await new Promise((resolve, reject) => {
            const options = {
              hostname: 'platform.ringcentral.com',
              path: `/restapi/v1.0/account/~/extension?extensionNumber=${ext}`,
              method: 'GET',
              headers: { 'Authorization': `Bearer ${token}` }
            };
            const req = https.request(options, (res) => {
              let data = '';
              res.on('data', chunk => data += chunk);
              res.on('end', () => { try { resolve(JSON.parse(data)); } catch(e) { resolve(null); } });
            });
            req.on('error', reject);
            req.end();
          });
          const records = json && json.records || [];
          if (!records.length) return { extension: ext, error: 'not found' };
          const extId = records[0].id;
          const extName = records[0].name;
          const presence = await getPresenceCached(token, extId);
          return {
            extension: ext,
            name: extName,
            presenceStatus: presence ? presence.presenceStatus : null,
            dndStatus: presence ? presence.dndStatus : null,
            telephonyStatus: presence ? presence.telephonyStatus : null,
            userStatus: presence ? presence.userStatus : null,
            raw: presence
          };
        } catch(e) {
          return { extension: ext, error: e.message };
        }
      }));
      res.writeHead(200);
      return res.end(JSON.stringify({ agents: results }));
    } catch (err) {
      res.writeHead(500);
      return res.end(JSON.stringify({ error: err.message }));
    }
  }

  // RC Webhook receiver
  if (pathname === '/webhook/presence') {
    const validationToken = req.headers['validation-token'];
    if (validationToken) {
      console.log(`[WEBHOOK] Validation request received`);
      res.writeHead(200, { 'Validation-Token': validationToken });
      return res.end();
    }
    if (req.method === 'POST') {
      let body = '';
      req.on('data', chunk => body += chunk);
      req.on('end', () => {
        console.log(`[WEBHOOK] Incoming payload (${body.length} bytes):`, body.slice(0, 300));
        handleWebhookPresence(body);
        res.writeHead(200);
        res.end();
      });
      return;
    }
  }

  res.writeHead(404);
  res.end(JSON.stringify({ error: 'Not found. Available: /availability?state=TX, /agent?id=xxx, /queue?name=QueueName, /queues, /agents/debug' }));
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, async () => {
  console.log(`Availability API running on port ${PORT}`);
  console.log(`WEBHOOK_URL: ${WEBHOOK_URL || 'NOT SET'}`);
  console.log('Skipping warmup - cache will populate on demand');
  try {
    const token = await getAccessToken();
    await createWebhookSubscription(token);
  } catch(err) {
    console.error('Failed to create webhook subscription:', err.message);
  }
});
