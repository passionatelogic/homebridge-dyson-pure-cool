const { HomebridgePluginUiServer, RequestError } = require('@homebridge/plugin-ui-utils');
const https = require('https');
const crypto = require('crypto');

// bonjour-service is optional; if unavailable we simply skip IP auto-discovery.
let Bonjour = null;
try {
  Bonjour = require('bonjour-service').Bonjour;
} catch (e) {
  Bonjour = null;
}

const USER_AGENT = 'android client';

function apiHost(region) {
  return region === 'cn' ? 'appapi.cp.dyson.cn' : 'appapi.cp.dyson.com';
}

/**
 * Minimal promise wrapper around the Dyson cloud API. Mirrors the requests the
 * plugin's original credentials-generator website makes (same endpoints,
 * User-Agent and relaxed TLS), just surfaced over the plugin-ui IPC channel.
 */
function dysonRequest({ region, path, method = 'GET', json, auth }) {
  return new Promise((resolve, reject) => {
    const headers = { 'User-Agent': USER_AGENT, Accept: 'application/json' };
    let bodyStr;
    if (json !== undefined) {
      bodyStr = JSON.stringify(json);
      headers['Content-Type'] = 'application/json';
      headers['Content-Length'] = Buffer.byteLength(bodyStr);
    }
    if (auth) {
      headers['Authorization'] = auth;
    }
    const req = https.request(
      { host: apiHost(region), path, method, headers, rejectUnauthorized: false },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const raw = Buffer.concat(chunks).toString('utf8');
          let body = null;
          try {
            body = raw ? JSON.parse(raw) : null;
          } catch (e) {
            body = raw;
          }
          resolve({ statusCode: res.statusCode, body });
        });
      },
    );
    req.on('error', reject);
    if (bodyStr) {
      req.write(bodyStr);
    }
    req.end();
  });
}

// Decrypts the local MQTT credential that the Dyson API returns.
// (AES-256-CBC, key = [1..32], zero IV — same scheme the plugin already uses.)
function decryptLocalPassword(localBrokerCredentials) {
  const key = Uint8Array.from(Array(32), (_, index) => index + 1);
  const iv = new Uint8Array(16);
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  const decrypted =
    decipher.update(localBrokerCredentials, 'base64', 'utf8') + decipher.final('utf8');
  return JSON.parse(decrypted).apPasswordHash;
}

// Turns a raw /v3/manifest device entry into the { serialNumber, name,
// productType, credentials } shape the platform config expects. The platform
// reads the base64 blob and pulls the mqtt password out of it, so we inject the
// decrypted password before encoding — exactly like the original generator.
function toConfigDevice(deviceBody) {
  const cc = deviceBody.connectedConfiguration;
  if (!cc || !cc.mqtt || !cc.mqtt.localBrokerCredentials) {
    return null;
  }
  deviceBody.connectedConfiguration.mqtt.password = decryptLocalPassword(
    cc.mqtt.localBrokerCredentials,
  );
  return {
    serialNumber: deviceBody.serialNumber,
    name: deviceBody.name || deviceBody.serialNumber,
    productType: cc.mqtt.mqttRootTopicLevel || deviceBody.type,
    credentials: Buffer.from(JSON.stringify(deviceBody)).toString('base64'),
  };
}

class DysonUiServer extends HomebridgePluginUiServer {
  constructor() {
    super();

    this.onRequest('/userstatus', this.userStatus.bind(this));
    this.onRequest('/challenge', this.challenge.bind(this));
    this.onRequest('/verify', this.verify.bind(this));
    this.onRequest('/discover-ips', this.discoverIps.bind(this));

    this.ready();
  }

  // Step 1a: check whether the account exists and whether it uses 2FA.
  async userStatus({ country, email }) {
    if (!country || !email) {
      throw new RequestError('Country code and email are required.', { status: 400 });
    }
    const { statusCode, body } = await dysonRequest({
      path: `/v3/userregistration/email/userstatus?country=${encodeURIComponent(country)}`,
      method: 'POST',
      json: { Email: email },
    });
    if (statusCode === 429) {
      throw new RequestError('Too many requests to Dyson. Wait a few minutes and try again.', { status: 429 });
    }
    if (statusCode !== 200 || !body || !body.authenticationMethod) {
      throw new RequestError('Could not look up that Dyson account. Check the country code and email.', { status: statusCode || 500 });
    }
    return { authenticationMethod: body.authenticationMethod, accountStatus: body.accountStatus };
  }

  // Step 1b (2FA accounts): request a challenge; Dyson emails the OTP code.
  async challenge({ country, email }) {
    const { statusCode, body } = await dysonRequest({
      path: `/v3/userregistration/email/auth?country=${encodeURIComponent(country)}`,
      method: 'POST',
      json: { Email: email },
    });
    if (statusCode === 429) {
      throw new RequestError('Too many requests to Dyson. Wait a few minutes and try again.', { status: 429 });
    }
    if (statusCode !== 200 || !body || !body.challengeId) {
      throw new RequestError('Could not start the verification. Check the email and try again.', { status: statusCode || 500 });
    }
    return { challengeId: body.challengeId };
  }

  // Step 2: sign in (2FA or legacy), then fetch + decrypt the device manifest.
  async verify({ country, email, password, challengeId, otpCode, authenticationMethod }) {
    if (!password) {
      throw new RequestError('Password is required.', { status: 400 });
    }

    let auth;
    if (authenticationMethod === 'EMAIL_PWD_2FA') {
      if (!challengeId || !otpCode) {
        throw new RequestError('The emailed verification code is required.', { status: 400 });
      }
      const { statusCode, body } = await dysonRequest({
        path: `/v3/userregistration/email/verify?country=${encodeURIComponent(country)}`,
        method: 'POST',
        json: { Email: email, Password: password, challengeId, otpCode },
      });
      if (statusCode === 401) {
        throw new RequestError('Sign-in failed — check your password and verification code.', { status: 401 });
      }
      if (statusCode !== 200 || !body || !body.token || !body.tokenType) {
        throw new RequestError('Sign-in failed. Check your password and the emailed code, then try again.', { status: statusCode || 500 });
      }
      auth = `${body.tokenType} ${body.token}`;
    } else {
      const { statusCode, body } = await dysonRequest({
        path: `/v1/userregistration/authenticate?country=${encodeURIComponent(country)}`,
        method: 'POST',
        json: { Email: email, Password: password },
      });
      if (statusCode !== 200 || !body || !body.Account || !body.Password) {
        throw new RequestError('Sign-in failed — check your password.', { status: statusCode || 500 });
      }
      auth = 'Basic ' + Buffer.from(`${body.Account}:${body.Password}`).toString('base64');
    }

    const { statusCode, body } = await dysonRequest({
      path: '/v3/manifest',
      method: 'GET',
      auth,
    });
    if (statusCode !== 200 || !Array.isArray(body)) {
      throw new RequestError('Signed in, but could not load your devices from Dyson.', { status: statusCode || 500 });
    }

    const devices = [];
    const skipped = [];
    for (const deviceBody of body) {
      const configDevice = toConfigDevice(deviceBody);
      if (configDevice) {
        devices.push(configDevice);
      } else {
        skipped.push(deviceBody.name || deviceBody.serialNumber || 'unknown device');
      }
    }
    return { devices, skipped };
  }

  // Best-effort: browse the LAN for Dyson MQTT services and map serial -> IP.
  async discoverIps({ serials }) {
    if (!Bonjour) {
      return { ips: {}, available: false };
    }
    const wanted = Array.isArray(serials) ? serials : [];
    return await new Promise((resolve) => {
      const ips = {};
      let bonjour;
      try {
        bonjour = new Bonjour();
      } catch (e) {
        resolve({ ips: {}, available: false });
        return;
      }
      const browser = bonjour.find({ type: 'dyson_mqtt' }, (service) => {
        const ip = (service.addresses || []).find((a) => /^\d{1,3}(\.\d{1,3}){3}$/.test(a));
        if (!ip) {
          return;
        }
        const haystack = [service.name, service.host, JSON.stringify(service.txt || {})]
          .join(' ')
          .toLowerCase();
        for (const serial of wanted) {
          if (serial && haystack.includes(String(serial).toLowerCase())) {
            ips[serial] = ip;
          }
        }
      });
      setTimeout(() => {
        try { browser.stop(); } catch (e) { /* noop */ }
        try { bonjour.destroy(); } catch (e) { /* noop */ }
        resolve({ ips, available: true });
      }, 5000);
    });
  }
}

(() => new DysonUiServer())();
