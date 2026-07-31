const PROTOCOL = 'boxim-miniapp'
const BROKER_PROTOCOL = 'boxim-miniapp-broker'
const VERSION = '1.0'
const ENVELOPE_FIELDS = Object.freeze([
  'protocol', 'version', 'id', 'kind', 'method', 'nonce', 'payload', 'error'
])
const PRELOAD_FIELDS = Object.freeze(['protocol', 'version', 'kind', 'brokerUrl'])
const BROKER_BOUND_FIELDS = Object.freeze(['protocol', 'version', 'kind'])
const DIRECT_BOUND_FIELDS = Object.freeze([
  'protocol', 'version', 'kind', 'bindingId'
])
const HOST_INIT_FIELDS = Object.freeze([
  'appId', 'sdkVersion', 'protocolVersion', 'grantedCapabilities', 'terminal',
  'locale', 'theme', 'safeArea'
])
const LAUNCH_FIELDS = Object.freeze(['appId', 'versionId', 'launchCode', 'expiresAt'])
const THEME_FIELDS = Object.freeze(['mode', 'backgroundColor', 'textColor', 'accentColor'])
const SAFE_AREA_FIELDS = Object.freeze(['top', 'right', 'bottom', 'left'])
const REQUESTED_CAPABILITIES = Object.freeze(['auth.launch', 'host.backButton', 'host.close'])
const LOCAL_DIRECT_BROKER_URLS = Object.freeze([
  'http://localhost:8080/miniapp-host-broker.html',
  'http://localhost:5173/static/miniapp-host-broker.html'
])
const MAX_ENVELOPE_BYTES = 16 * 1024

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
    const allowedProtocol = parsed.protocol === 'https:'
      || (parsed.protocol === 'http:' && parsed.hostname === 'localhost')
    if (!allowedProtocol || parsed.username !== '' || parsed.password !== ''
      || parsed.search !== '' || parsed.hash !== '' || parsed.href !== value) return null
    return parsed
  } catch {
    return null
  }
}

function validPreload(value, trustedBrokerUrls) {
  return hasExactKeys(value, PRELOAD_FIELDS)
    && value.protocol === BROKER_PROTOCOL
    && value.version === VERSION
    && value.kind === 'preload'
    && trustedBrokerUrls.has(value.brokerUrl)
}

function validBound(value) {
  return hasExactKeys(value, BROKER_BOUND_FIELDS)
    && value.protocol === BROKER_PROTOCOL
    && value.version === VERSION
    && value.kind === 'bound'
}

function validDirectBound(value, bindingId) {
  return hasExactKeys(value, DIRECT_BOUND_FIELDS)
    && value.protocol === BROKER_PROTOCOL
    && value.version === VERSION
    && value.kind === 'direct-bound'
    && value.bindingId === bindingId
}

function validEnvelope(value) {
  let serialized
  try { serialized = JSON.stringify(value) } catch { return false }
  return hasExactKeys(value, ENVELOPE_FIELDS)
    && isJsonValue(value)
    && new TextEncoder().encode(serialized).byteLength <= MAX_ENVELOPE_BYTES
    && value.protocol === PROTOCOL
    && value.version === VERSION
    && isCanonicalUlid(value.id)
    && ['request', 'response', 'event'].includes(value.kind)
    && typeof value.method === 'string' && value.method.length > 0
    && typeof value.nonce === 'string' && decodedBase64urlBytes(value.nonce) >= 16
    && isPlainObject(value.payload)
    && (value.error === null || isPlainObject(value.error))
}

function validTheme(value) {
  return hasExactKeys(value, THEME_FIELDS)
    && ['light', 'dark'].includes(value.mode)
    && ['backgroundColor', 'textColor', 'accentColor'].every(key =>
      typeof value[key] === 'string' && value[key].length > 0
    )
}

function validSafeArea(value) {
  return hasExactKeys(value, SAFE_AREA_FIELDS)
    && SAFE_AREA_FIELDS.every(key => Number.isFinite(value[key]) && value[key] >= 0)
}

function isDenseCapabilityArray(value) {
  return Array.isArray(value)
    && Object.keys(value).length === value.length
    && value.every((capability, index) =>
      Object.prototype.hasOwnProperty.call(value, index)
        && typeof capability === 'string'
        && REQUESTED_CAPABILITIES.includes(capability)
    )
}

function validHostInit(value, appId, nonce, readyRequestId) {
  const payload = value.payload
  return value.kind === 'response'
    && value.method === 'host.init'
    && value.nonce === nonce
    && value.id === readyRequestId
    && value.error === null
    && hasExactKeys(payload, HOST_INIT_FIELDS)
    && payload.appId === appId
    && payload.sdkVersion === '1.0.0'
    && payload.protocolVersion === VERSION
    && isDenseCapabilityArray(payload.grantedCapabilities)
    && new Set(payload.grantedCapabilities).size === payload.grantedCapabilities.length
    && payload.terminal === 'WEB'
    && typeof payload.locale === 'string' && payload.locale.length > 0
    && validTheme(payload.theme)
    && validSafeArea(payload.safeArea)
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
  trustedBrokerUrls,
  preloadedName,
  createId = () => secureUlid(cryptoObject),
  createNonce = () => randomBase64url(cryptoObject, 24),
  createVerifier = () => randomBase64url(cryptoObject, 32),
  onStatus = () => {},
  onLaunchCode = () => {},
  now = Date.now
} = {}) {
  const rawPreload = typeof preloadedName === 'string' ? preloadedName : windowObject.name || ''
  windowObject.name = ''

  const trustedBrokerUrlSet = new Set(
    Array.isArray(trustedBrokerUrls)
      ? trustedBrokerUrls.filter(url => canonicalBrokerUrl(url) !== null)
      : []
  )

  let brokerFrame = null
  let brokerOrigin = null
  let transportWindow = null
  let directBindingId = null
  let directBridge = false
  let pageNonce = null
  let pkceVerifier = null
  let readyRequestId = null
  let terminal = null
  let phase = 'BLOCKED'
  let readyStarted = false
  let launchConsumed = false
  let destroyed = false
  let hostCapabilities = []

  function publish(nextPhase, nextTerminal = terminal) {
    phase = nextPhase
    terminal = typeof nextTerminal === 'string' ? nextTerminal : null
    try { onStatus(Object.freeze({phase, terminal})) } catch {}
  }

  function status() {
    return Object.freeze({phase, terminal})
  }

  function teardown(finalPhase) {
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
    transportWindow = null
    directBindingId = null
    directBridge = false
    pageNonce = null
    pkceVerifier = null
    readyRequestId = null
    readyStarted = false
    launchConsumed = false
    hostCapabilities = []
    publish(finalPhase, null)
    return true
  }

  function cleanup() {
    return teardown('CLOSED')
  }

  function failClosed() {
    return teardown('BLOCKED')
  }

  function diagnostics() {
    return Object.freeze({
      destroyed,
      privateStateCleared: brokerFrame === null
        && brokerOrigin === null
        && transportWindow === null
        && directBindingId === null
        && pageNonce === null
        && pkceVerifier === null
        && readyRequestId === null
    })
  }

  async function sendReady() {
    if (destroyed || readyStarted || !transportWindow || !brokerOrigin) return
    readyStarted = true
    try {
      pageNonce = createNonce()
      pkceVerifier = createVerifier()
      if (decodedBase64urlBytes(pageNonce) < 16
        || typeof pkceVerifier !== 'string'
        || !/^[A-Za-z0-9\-._~]{43,128}$/.test(pkceVerifier)) throw new TypeError('invalid local key material')
      const digest = await cryptoObject.subtle.digest('SHA-256', new TextEncoder().encode(pkceVerifier))
      if (destroyed || !transportWindow) return
      const challenge = base64url(new Uint8Array(digest))
      if (decodedBase64urlBytes(challenge) !== 32) throw new TypeError('invalid challenge')
      readyRequestId = createId()
      if (!isCanonicalUlid(readyRequestId)) throw new TypeError('invalid request id')
      transportWindow.postMessage({
        protocol: PROTOCOL,
        version: VERSION,
        id: readyRequestId,
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
          requestedCapabilities: [...REQUESTED_CAPABILITIES]
        },
        error: null
      }, brokerOrigin)
      publish('READY_SENT')
    } catch {
      if (!destroyed) failClosed()
    }
  }

  function onMessage(event) {
    if (destroyed || !transportWindow || event.source !== transportWindow
      || event.origin !== brokerOrigin || (event.ports && event.ports.length > 0)) return
    const data = event.data
    if ((!directBridge && validBound(data))
      || (directBridge && validDirectBound(data, directBindingId))) {
      sendReady()
      return
    }
    if (!validEnvelope(data) || pageNonce === null) return
    if (phase === 'READY_SENT' && validHostInit(data, appId, pageNonce, readyRequestId)) {
      hostCapabilities = [...data.payload.grantedCapabilities]
      publish('HOST_READY', data.payload.terminal)
      return
    }
    if (phase === 'HOST_READY' && !launchConsumed && validLaunch(data, appId, pageNonce, now)) {
      if (!hostCapabilities.includes('auth.launch')) return
      launchConsumed = true
      let launchCode = data.payload.launchCode
      try { onLaunchCode(launchCode) } catch {} finally { launchCode = null }
      publish('RUNNING')
    }
  }

  let parsed
  try { parsed = JSON.parse(rawPreload) } catch { parsed = null }
  if (!appId || trustedBrokerUrlSet.size === 0 || !validPreload(parsed, trustedBrokerUrlSet)) {
    publish('BLOCKED', null)
    destroyed = true
    return Object.freeze({status, destroy: cleanup, diagnostics})
  }

  const brokerUrl = canonicalBrokerUrl(parsed.brokerUrl)
  brokerOrigin = brokerUrl.origin
  directBridge = LOCAL_DIRECT_BROKER_URLS.includes(brokerUrl.href)
    && windowObject.location?.protocol === 'https:'
    && windowObject.parent
    && windowObject.parent !== windowObject
  if (directBridge) {
    try {
      directBindingId = secureUlid(cryptoObject)
    } catch {
      brokerOrigin = null
      directBridge = false
      destroyed = true
      publish('BLOCKED', null)
      return Object.freeze({status, destroy: cleanup, diagnostics})
    }
    transportWindow = windowObject.parent
    windowObject.addEventListener('message', onMessage)
    windowObject.addEventListener('pagehide', cleanup, {once: true})
    publish('CONNECTING', null)
    try {
      transportWindow.postMessage({
        protocol: BROKER_PROTOCOL,
        version: VERSION,
        kind: 'direct-hello',
        bindingId: directBindingId
      }, brokerOrigin)
    } catch {
      failClosed()
    }
    return Object.freeze({status, destroy: cleanup, diagnostics})
  }
  brokerFrame = documentObject.createElement('iframe')
  brokerFrame.src = brokerUrl.href
  brokerFrame.title = 'MiniApp secure bridge'
  brokerFrame.hidden = true
  brokerFrame.setAttribute('aria-hidden', 'true')
  windowObject.addEventListener('message', onMessage)
  windowObject.addEventListener('pagehide', cleanup, {once: true})
  documentObject.body.appendChild(brokerFrame)
  transportWindow = brokerFrame.contentWindow
  publish('CONNECTING', null)
  return Object.freeze({status, destroy: cleanup, diagnostics})
}
