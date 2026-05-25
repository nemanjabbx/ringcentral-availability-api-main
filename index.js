const http = require('http');
const https = require('https');

const RC_CLIENT_ID = process.env.RC_CLIENT_ID;
const RC_CLIENT_SECRET = process.env.RC_CLIENT_SECRET;
const RC_JWT = process.env.RC_JWT;

let tokenCache = null;
let tokenExpiry = 0;

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


const AGENT_MAP = {
  '0000as': 'MI - April Simpson',
  '0000by': 'MI - Bebeto Yewah',
  '0000dt': 'MI - Dylan Trout',
  '0000lt': 'MI - Lee Trawick',
};

async function getAccessToken() {
  const now = Date.now();
  if (tokenCache && now < tokenExpiry) {
    return tokenCache;
  }
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
        try { resolve(JSON.parse(data)); }
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
        try { resolve(JSON.parse(data)); }
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
        try { resolve(JSON.parse(data)); }
        catch(e) { resolve(null); }
      });
    });
    req.on('error', () => resolve(null));
    req.end();
  });
}

async function checkAvailability(stateUpper) {
  const stateName = STATE_NAME_MAP[stateUpper] || stateUpper;
  const token = await getAccessToken();
  const queuesData = await getQueues(token);
  const queues = queuesData.records || [];

  const matchedQueue = queues.find(q =>
    q.name.toLowerCase() === stateName.toLowerCase()
  );

  if (!matchedQueue) {
    return {
      available: false,
      agents: 0,
      state: stateUpper,
      state_name: stateName,
      reason: `No queue found for: ${stateName}`
    };
  }

  const membersData = await getQueueMembers(token, matchedQueue.id);
  const members = membersData.records || [];

  const presenceResults = await Promise.all(
    members.map(m => getPresence(token, m.id).catch(() => null))
  );

  const availableAgents = presenceResults.filter(p => {
    if (!p) return false;
    return (
      p.presenceStatus === 'Available' &&
      p.dndStatus === 'TakeAllCalls' &&
      p.telephonyStatus === 'NoCall'
    );
  });

  return {
    available: availableAgents.length > 0,
    agents: availableAgents.length,
    state: stateUpper,
    queue: matchedQueue.name,
    total_members: members.length
  };
}

async function checkAgentAvailability(queueName) {
  const token = await getAccessToken();
  const queuesData = await getQueues(token);
  const queues = queuesData.records || [];

  const matchedQueue = queues.find(q =>
    q.name.toLowerCase() === queueName.toLowerCase()
  );

  if (!matchedQueue) {
    return {
      available: false,
      agents: 0,
      reason: `No queue found`
    };
  }

  const membersData = await getQueueMembers(token, matchedQueue.id);
  const members = membersData.records || [];

  const presenceResults = await Promise.all(
    members.map(m => getPresence(token, m.id).catch(() => null))
  );

  const availableAgents = presenceResults.filter(p => {
    if (!p) return false;
    return (
      p.presenceStatus === 'Available' &&
      p.dndStatus === 'TakeAllCalls' &&
      p.telephonyStatus === 'NoCall'
    );
  });

  return {
    available: availableAgents.length > 0,
    agents: availableAgents.length,
    total_members: members.length
  };
}

const server = http.createServer(async (req, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Access-Control-Allow-Origin', '*');

  const url = new URL(req.url, `http://${req.headers.host}`);
  const pathname = url.pathname;

  if (pathname === '/' || pathname === '/health') {
    res.writeHead(200);
    return res.end(JSON.stringify({ status: 'ok', message: 'Availability API is running' }));
  }

  // State-based availability
  if (pathname === '/availability') {
    const state = url.searchParams.get('state');
    if (!state) {
      res.writeHead(400);
      return res.end(JSON.stringify({ available: false, error: 'Missing state parameter. Use ?state=TX' }));
    }
    const stateUpper = state.toUpperCase().trim();
    try {
      const result = await checkAvailability(stateUpper);
      res.writeHead(200);
      return res.end(JSON.stringify(result));
    } catch (err) {
      console.error('Error:', err.message);
      res.writeHead(500);
      return res.end(JSON.stringify({ available: false, error: err.message }));
    }
  }

  // Agent-specific availability
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
      const result = await checkAgentAvailability(queueName);
      res.writeHead(200);
      return res.end(JSON.stringify(result));
    } catch (err) {
      console.error('Error:', err.message);
      res.writeHead(500);
      return res.end(JSON.stringify({ available: false, error: err.message }));
    }
  }

  res.writeHead(404);
  res.end(JSON.stringify({ error: 'Not found. Use /availability?state=TX or /agent?id=x7k2m' }));
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Availability API running on port ${PORT}`));
