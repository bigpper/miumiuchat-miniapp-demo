const PROTOCOL = 'boxim-miniapp'
const BROKER_PROTOCOL = 'boxim-miniapp-broker'
const VERSION = '1.0'
const ENVELOPE_FIELDS = Object.freeze([
  'protocol', 'version', 'id', 'kind', 'method', 'nonce', 'payload', 'error'
])
const PRELOAD_FIELDS = Object.freeze(['protocol', 'version', 'kind', 'brokerUrl'])
const BROKER_BOUND_FIELDS = Object.freeze(['protocol', 'version', 'kind'])
const HOST_INIT_FIELDS = Object.freeze([
  'appId', 'sdkVersion', 'protocolVersion', 'grantedCapabilities', 'terminal',
  'locale', 'theme', 'safeArea'
])
const LAUNCH_FIELDS = Object.freeze(['appId', 'versionId', 'launchCode', 'expiresAt'])

function isPlainObject(value) {
  if (value === null || typeof value !== 'object') return false
  const prototype = Object.getPrototypeOf(value)
  return prototype === Object.prototype || prototype === null
}

function hasExactKeys(value, fields) {
  if (!isPlainObject(value)) return false
  const actual = Reflect.ownKeys(value)
  return actual.length === fields.length
    && actual.every(key => typeof key === 'string' && fields.includes(key))
}

function isJsonValue(value, ancestors = new WeakSet()) {
  if (value === null || ['string', 'boolean'].includes(typeof value)) return true
  if (typeof value === 'number') return Number.isFinite(value)
  if (!Array.isArray(value) && !isPlainObject(value)) return false
  if (ancestors.has(value)) return false
  ancestors.add(value)
  const valid = (Array.isArray(value) ? value : Object.values(value))
    .every(child => isJsonValue(child, ancestors))
  ancestors.delete(value)
  return valid
}

function base64url(bytes) {
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

function randomBase64url(cryptoObject, length) {
  const bytes = new Uint8Array(length)
  cryptoObject.getRandomValues(bytes)
  return base64url(bytes)
}

function secureUlid(cryptoObject) {
  const alphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'
  const bytes = new Uint8Array(16)
  let time = Date.now()
  for (let index = 5; index >= 0; index -= 1) {
    bytes[index] = time % 256
    time = Math.floor(time / 256)
  }
  cryptoObject.getRandomValues(bytes.subarray(6))
  let bits = '00'
  for (const byte of bytes) bits += byte.toString(2).padStart(8, '0')
  let id = ''
  for (let offset = 0; offset < 130; offset += 5) {
    id += alphabet[parseInt(bits.slice(offset, offset + 5), 2)]
  }
  return id
}

function isCanonicalUlid(value) {
  return typeof value === 'string' && /^[0-9A-HJKMNP-TV-Z]{26}$/.test(value)
}

function decodedBase64urlBytes(value) {
  if (typeof value !== 'string' || value.length === 0 || value.includes('=')
    || !/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) return -1
  return Math.floor(value.length * 6 / 8)
}

function canonicalBrokerUrl(value) {
  try {
    const parsed = new URL(value)
    if (parsed.protocol !== 'https:' || parsed.username !== '' || parsed.password !== ''
      || parsed.search !== '' || parsed.hash !== '' || parsed.href !== value) return null
    return parsed
  } catch {
    return null
  }
}

function validPreload(value) {
  return hasExactKeys(value, PRELOAD_FIELDS)
    && value.protocol === BROKER_PROTOCOL
    && value.version === VERSION
    && value.kind === 'preload'
    && canonicalBrokerUrl(value.brokerUrl) !== null
}

function validBound(value) {
  return hasExactKeys(value, BROKER_BOUND_FIELDS)
    && value.protocol === BROKER_PROTOCOL
    && value.version === VERSION
    && value.kind === 'bound'
}

function validEnvelope(value) {
  return hasExactKeys(value, ENVELOPE_FIELDS)
    && isJsonValue(value)
    && value.protocol === PROTOCOL
    && value.version === VERSION
    && isCanonicalUlid(value.id)
    && ['request', 'response', 'event'].includes(value.kind)
    && typeof value.method === 'string' && value.method.length > 0
    && typeof value.nonce === 'string' && decodedBase64urlBytes(value.nonce) >= 16
    && isPlainObject(value.payload)
    && (value.error === null || isPlainObject(value.error))
}

function validHostInit(value, appId, nonce) {
  const payload = value.payload
  return value.kind === 'response'
    && value.method === 'host.init'
    && value.nonce === nonce
    && value.error === null
    && hasExactKeys(payload, HOST_INIT_FIELDS)
    && payload.appId === appId
    && typeof payload.sdkVersion === 'string'
    && payload.protocolVersion === VERSION
    && Array.isArray(payload.grantedCapabilities)
    && payload.grantedCapabilities.every(capability => typeof capability === 'string')
    && typeof payload.terminal === 'string' && payload.terminal.length > 0
    && typeof payload.locale === 'string'
    && isPlainObject(payload.theme)
    && isPlainObject(payload.safeArea)
}

function validLaunch(value, appId, nonce, now) {
  const payload = value.payload
  const expiresAt = typeof payload.expiresAt === 'string' ? Date.parse(payload.expiresAt) : NaN
  return value.kind === 'event'
    && value.method === 'auth.launchCode'
    && value.nonce === nonce
    && value.error === null
    && hasExactKeys(payload, LAUNCH_FIELDS)
    && payload.appId === appId
    && isCanonicalUlid(payload.versionId)
    && decodedBase64urlBytes(payload.launchCode) === 32
    && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(payload.expiresAt)
    && Number.isFinite(expiresAt) && new Date(expiresAt).toISOString() === payload.expiresAt
    && expiresAt > now()
}

export function createMiniAppSdk({
  windowObject = window,
  documentObject = document,
  cryptoObject = crypto,
  appId,
  createId = () => secureUlid(cryptoObject),
  createNonce = () => randomBase64url(cryptoObject, 24),
  createVerifier = () => randomBase64url(cryptoObject, 32),
  onStatus = () => {},
  onLaunchCode = () => {},
  now = Date.now
} = {}) {
  const rawPreload = windowObject.name || ''
  windowObject.name = ''

  let brokerFrame = null
  let brokerOrigin = null
  let pageNonce = null
  let pkceVerifier = null
  let terminal = null
  let phase = 'BLOCKED'
  let readyStarted = false
  let launchConsumed = false
  let destroyed = false

  function publish(nextPhase, nextTerminal = terminal) {
    phase = nextPhase
    terminal = typeof nextTerminal === 'string' ? nextTerminal : null
    onStatus(Object.freeze({phase, terminal}))
  }

  function status() {
    return Object.freeze({phase, terminal})
  }

  function cleanup() {
    if (destroyed) return false
    destroyed = true
    windowObject.removeEventListener('message', onMessage)
    windowObject.removeEventListener('pagehide', cleanup)
    if (brokerFrame) {
      try { brokerFrame.src = 'about:blank' } catch {}
      if (typeof brokerFrame.remove === 'function') brokerFrame.remove()
      else if (brokerFrame.parentNode) brokerFrame.parentNode.removeChild(brokerFrame)
    }
    brokerFrame = null
    brokerOrigin = null
    pageNonce = null
    pkceVerifier = null
    publish('CLOSED', null)
    return true
  }

  async function sendReady() {
    if (destroyed || readyStarted || !brokerFrame || !brokerOrigin) return
    readyStarted = true
    try {
      pageNonce = createNonce()
      pkceVerifier = createVerifier()
      if (decodedBase64urlBytes(pageNonce) < 16
        || typeof pkceVerifier !== 'string'
        || !/^[A-Za-z0-9\-._~]{43,128}$/.test(pkceVerifier)) throw new TypeError('invalid local key material')
      const digest = await cryptoObject.subtle.digest('SHA-256', new TextEncoder().encode(pkceVerifier))
      if (destroyed || !brokerFrame || !brokerFrame.contentWindow) return
      const challenge = base64url(new Uint8Array(digest))
      if (decodedBase64urlBytes(challenge) !== 32) throw new TypeError('invalid challenge')
      brokerFrame.contentWindow.postMessage({
        protocol: PROTOCOL,
        version: VERSION,
        id: createId(),
        kind: 'request',
        method: 'miniapp.ready',
        nonce: pageNonce,
        payload: {
          appId,
          sdkVersion: '1.0.0',
          protocolVersion: VERSION,
          pageNonce,
          pkceChallenge: challenge,
          pkceMethod: 'S256',
          requestedCapabilities: ['auth.launch', 'host.backButton', 'host.close']
        },
        error: null
      }, brokerOrigin)
      publish('READY_SENT')
    } catch {
      if (!destroyed) publish('BLOCKED', null)
    }
  }

  function onMessage(event) {
    if (destroyed || !brokerFrame || event.source !== brokerFrame.contentWindow
      || event.origin !== brokerOrigin || (event.ports && event.ports.length > 0)) return
    const data = event.data
    if (validBound(data)) {
      sendReady()
      return
    }
    if (!validEnvelope(data) || pageNonce === null) return
    if (phase === 'READY_SENT' && validHostInit(data, appId, pageNonce)) {
      publish('HOST_READY', data.payload.terminal)
      return
    }
    if (phase === 'HOST_READY' && !launchConsumed && validLaunch(data, appId, pageNonce, now)) {
      launchConsumed = true
      let launchCode = data.payload.launchCode
      try { onLaunchCode(launchCode) } catch {} finally { launchCode = null }
      publish('RUNNING')
    }
  }

  let parsed
  try { parsed = JSON.parse(rawPreload) } catch { parsed = null }
  if (!appId || !validPreload(parsed)) {
    publish('BLOCKED', null)
    return Object.freeze({status, destroy: cleanup})
  }

  const brokerUrl = canonicalBrokerUrl(parsed.brokerUrl)
  brokerOrigin = brokerUrl.origin
  brokerFrame = documentObject.createElement('iframe')
  brokerFrame.src = brokerUrl.href
  brokerFrame.title = 'MiniApp secure bridge'
  brokerFrame.hidden = true
  brokerFrame.setAttribute('aria-hidden', 'true')
  windowObject.addEventListener('message', onMessage)
  windowObject.addEventListener('pagehide', cleanup, {once: true})
  documentObject.body.appendChild(brokerFrame)
  publish('CONNECTING', null)
  return Object.freeze({status, destroy: cleanup})
}
