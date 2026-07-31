import assert from 'node:assert/strict'
import {readFile} from 'node:fs/promises'
import test from 'node:test'
import vm from 'node:vm'

import {createMiniAppSdk} from './miniapp-sdk.js'

const APP_ID = '01KYN5H8CWSR2PJ6Q8WE46P12V'
const HOST_ORIGIN = 'https://im.example.com'
const BROKER_URL = `${HOST_ORIGIN}/miniapp-host-broker.html`
const LOCAL_BROKER_URL = 'http://localhost:8080/miniapp-host-broker.html'
const UNIAPP_H5_BROKER_URL = 'http://localhost:5173/h5/static/miniapp-host-broker.html'
const NOW_MS = Date.parse('2026-07-30T00:00:00.000Z')
const MAX_ENVELOPE_BYTES = 16 * 1024
const NONCE = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
const VERIFIER = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~'
const ID = '01KYN5H8CWSR2PJ6Q8WE46P12W'

function preload(overrides = {}) {
  return JSON.stringify({
    protocol: 'boxim-miniapp-broker',
    version: '1.0',
    kind: 'preload',
    brokerUrl: BROKER_URL,
    ...overrides
  })
}

function envelope(overrides = {}) {
  return {
    protocol: 'boxim-miniapp',
    version: '1.0',
    id: ID,
    kind: 'response',
    method: 'host.init',
    nonce: NONCE,
    payload: {
      appId: APP_ID,
      sdkVersion: '1.0.0',
      protocolVersion: '1.0',
      grantedCapabilities: ['auth.launch'],
      terminal: 'WEB',
      locale: 'zh-CN',
      theme: {mode: 'light', backgroundColor: '#fff', textColor: '#000', accentColor: '#07c160'},
      safeArea: {top: 0, right: 0, bottom: 0, left: 0}
    },
    error: null,
    ...overrides
  }
}

function envelopeAtByteLength(length) {
  const payload = {...envelope().payload, locale: ''}
  const overhead = new TextEncoder().encode(JSON.stringify(envelope({payload}))).byteLength
  assert.ok(overhead < length)
  return envelope({payload: {...payload, locale: 'x'.repeat(length - overhead)}})
}

function createHarness({
  name = preload(),
  preloadedName,
  trustedBrokerUrls = [BROKER_URL],
  launchCodeHandler = () => {},
  digestResult = async () => Uint8Array.from({length: 32}, (_, index) => index).buffer,
  randomFailure = false,
  runtimeTraps = false
} = {}) {
  const listeners = new Map()
  const iframeListeners = new Map()
  const domWrites = []
  const appended = []
  const iframe = {
    contentWindow: {
      sent: [],
      postMessage(message, targetOrigin) { this.sent.push({message, targetOrigin}) }
    },
    removeCalled: false,
    setAttribute(name, value) { domWrites.push(String(value)) },
    addEventListener(type, listener) { iframeListeners.set(type, listener) },
    removeEventListener(type, listener) { if (iframeListeners.get(type) === listener) iframeListeners.delete(type) },
    remove() { this.removeCalled = true }
  }
  Object.defineProperties(iframe, {
    src: {
      get() { return this._src },
      set(value) { this._src = value; domWrites.push(String(value)) }
    },
    title: {
      get() { return this._title },
      set(value) { this._title = value; domWrites.push(String(value)) }
    },
    hidden: {
      get() { return this._hidden },
      set(value) { this._hidden = value; domWrites.push(String(value)) }
    }
  })
  const document = {
    documentElement: {dataset: {}},
    body: {appendChild(value) { assert.equal(value, iframe); appended.push(value) }},
    createElement(type) { assert.equal(type, 'iframe'); return iframe }
  }
  const parentWindow = {
    sent: [],
    postMessage(message, targetOrigin) {
      this.sent.push({message, targetOrigin})
    }
  }
  const window = {
    name,
    location: {protocol: 'https:'},
    parent: parentWindow,
    addEventListener(type, listener) { listeners.set(type, listener) },
    removeEventListener(type, listener) { if (listeners.get(type) === listener) listeners.delete(type) }
  }
  window.self = window
  if (runtimeTraps) {
    const forbidden = name => ({get() { throw new Error(`${name} touched`) }})
    Object.defineProperties(window, {
      localStorage: forbidden('localStorage'),
      sessionStorage: forbidden('sessionStorage'),
      indexedDB: forbidden('indexedDB'),
      history: forbidden('history'),
      location: forbidden('location'),
      console: forbidden('console')
    })
    Object.defineProperty(document, 'cookie', forbidden('cookie'))
    Object.defineProperties(document.body, {
      innerHTML: forbidden('body.innerHTML'),
      textContent: forbidden('body.textContent')
    })
    Object.defineProperties(iframe, {
      innerHTML: forbidden('iframe.innerHTML'),
      textContent: forbidden('iframe.textContent')
    })
  }
  const crypto = {
    getRandomValues(bytes) {
      if (randomFailure) throw new Error('random source failed')
      bytes.fill(1)
      return bytes
    },
    subtle: {async digest(name, bytes) {
      assert.equal(name, 'SHA-256')
      assert.equal(new TextDecoder().decode(bytes), VERIFIER)
      return digestResult()
    }}
  }
  const statuses = []
  const sdk = createMiniAppSdk({
    windowObject: window,
    documentObject: document,
    cryptoObject: crypto,
    appId: APP_ID,
    trustedBrokerUrls,
    preloadedName,
    createId: () => ID,
    createNonce: () => NONCE,
    createVerifier: () => VERIFIER,
    onStatus: status => statuses.push(status),
    onLaunchCode: launchCodeHandler,
    now: () => NOW_MS
  })
  return {
    sdk,
    window,
    parentWindow,
    document,
    iframe,
    appended,
    listeners,
    iframeListeners,
    statuses,
    domWrites
  }
}

function bound(harness) {
  harness.listeners.get('message')({
    source: harness.iframe.contentWindow,
    origin: HOST_ORIGIN,
    ports: [],
    data: {protocol: 'boxim-miniapp-broker', version: '1.0', kind: 'bound'}
  })
}

function directBound(harness, origin = 'http://localhost:8080') {
  const hello = harness.parentWindow.sent[0]?.message
  harness.listeners.get('message')({
    source: harness.parentWindow,
    origin,
    ports: [],
    data: {
      protocol: 'boxim-miniapp-broker',
      version: '1.0',
      kind: 'direct-bound',
      bindingId: hello?.bindingId || ID
    }
  })
}

async function settle() {
  await Promise.resolve()
  await Promise.resolve()
}

async function runInlineBootstrap({rejectImport = false} = {}) {
  const html = await readFile(new URL('./index.html', import.meta.url), 'utf8')
  const inlineScript = html.match(/<script>\s*([\s\S]*?)<\/script>\s*<\/body>/)?.[1]
  assert.ok(inlineScript)
  const preloadValue = preload({brokerUrl: LOCAL_BROKER_URL})
  const status = {textContent: ''}
  const detail = {textContent: ''}
  const document = {
    documentElement: {dataset: {}},
    getElementById(id) { return id === 'bridge-status' ? status : detail }
  }
  const window = {name: preloadValue}
  const options = []
  let importCalls = 0
  const context = vm.createContext({window, document})
  const importedModule = new vm.SyntheticModule(['createMiniAppSdk'], function () {
    this.setExport('createMiniAppSdk', value => options.push(value))
  }, {context})
  await importedModule.link(() => {})
  await importedModule.evaluate()
  const script = new vm.Script(inlineScript, {
    importModuleDynamically: async specifier => {
      importCalls += 1
      assert.equal(window.name, '')
      assert.equal(specifier, './miniapp-sdk.js')
      if (rejectImport) throw new Error('module load failed')
      return importedModule
    }
  })
  script.runInContext(context)
  await settle()
  return {window, document, status, detail, options, importCalls, preloadValue}
}

test('clears window.name synchronously before any asynchronous PKCE work', () => {
  const harness = createHarness()
  assert.equal(harness.window.name, '')
  assert.equal(harness.iframe.contentWindow.sent.length, 0)
  assert.equal(harness.sdk.status().phase, 'CONNECTING')
})

test('uses an already captured preload while still clearing window.name synchronously', () => {
  const harness = createHarness({name: 'not a preload', preloadedName: preload()})
  assert.equal(harness.window.name, '')
  assert.equal(harness.sdk.status().phase, 'CONNECTING')
  assert.equal(harness.iframe.contentWindow.sent.length, 0)
})

test('accepts only an exactly allowlisted localhost broker and rejects all other broker URLs', () => {
  const accepted = createHarness({
    name: preload({brokerUrl: LOCAL_BROKER_URL}),
    trustedBrokerUrls: [LOCAL_BROKER_URL]
  })
  assert.equal(accepted.sdk.status().phase, 'CONNECTING')
  const future = 'https://host.example/miniapp-host-broker.html'
  assert.equal(createHarness({
    name: preload({brokerUrl: future}),
    trustedBrokerUrls: [future]
  }).sdk.status().phase, 'CONNECTING')
  for (const name of [
    preload({extra: true}),
    preload({brokerUrl: `${LOCAL_BROKER_URL}?x=1`}),
    preload({brokerUrl: 'http://evil.example/miniapp-host-broker.html'}),
    preload({brokerUrl: 'https://evil.example/miniapp-host-broker.html'}),
    preload({brokerUrl: 'https://im.example.com/other-broker.html'})
  ]) {
    const harness = createHarness({name})
    assert.equal(harness.sdk.status().phase, 'BLOCKED')
    assert.equal(harness.listeners.size, 0)
  }
})

test('uses a parent-bound bridge for the exact HTTPS-to-localhost mixed-content case', async () => {
  const harness = createHarness({
    name: preload({brokerUrl: LOCAL_BROKER_URL}),
    trustedBrokerUrls: [LOCAL_BROKER_URL]
  })
  assert.equal(harness.appended.length, 0)
  const directHello = harness.parentWindow.sent[0]
  assert.equal(directHello.targetOrigin, 'http://localhost:8080')
  assert.equal(directHello.message.protocol, 'boxim-miniapp-broker')
  assert.equal(directHello.message.version, '1.0')
  assert.equal(directHello.message.kind, 'direct-hello')
  assert.match(directHello.message.bindingId, /^[0-9A-HJKMNP-TV-Z]{26}$/)

  const listener = harness.listeners.get('message')
  for (const event of [
    {
      source: {},
      origin: 'http://localhost:8080',
      ports: [],
      data: {
        protocol: 'boxim-miniapp-broker',
        version: '1.0',
        kind: 'direct-bound',
        bindingId: directHello.message.bindingId
      }
    },
    {
      source: harness.parentWindow,
      origin: 'https://evil.example',
      ports: [],
      data: {
        protocol: 'boxim-miniapp-broker',
        version: '1.0',
        kind: 'direct-bound',
        bindingId: directHello.message.bindingId
      }
    },
    {
      source: harness.parentWindow,
      origin: 'http://localhost:8080',
      ports: [{}],
      data: {
        protocol: 'boxim-miniapp-broker',
        version: '1.0',
        kind: 'direct-bound',
        bindingId: directHello.message.bindingId
      }
    },
    {
      source: harness.parentWindow,
      origin: 'http://localhost:8080',
      ports: [],
      data: {
        protocol: 'boxim-miniapp-broker',
        version: '1.0',
        kind: 'direct-bound',
        bindingId: ID
      }
    }
  ]) listener(event)
  await settle()
  assert.equal(harness.parentWindow.sent.length, 1)

  directBound(harness)
  await settle()
  assert.equal(harness.parentWindow.sent.length, 2)
  assert.equal(harness.parentWindow.sent[1].message.method, 'miniapp.ready')
  assert.equal(harness.parentWindow.sent[1].targetOrigin, 'http://localhost:8080')
  listener({
    source: harness.parentWindow,
    origin: 'http://localhost:8080',
    ports: [],
    data: envelope()
  })
  assert.deepEqual(harness.sdk.status(), {phase: 'HOST_READY', terminal: 'WEB'})
  harness.sdk.destroy()
  assert.deepEqual(harness.sdk.diagnostics(), {
    destroyed: true,
    privateStateCleared: true
  })
})

test('uses the exact UniApp H5 broker source and origin for the parent-bound handshake', async () => {
  const harness = createHarness({
    name: preload({brokerUrl: UNIAPP_H5_BROKER_URL}),
    trustedBrokerUrls: [LOCAL_BROKER_URL, UNIAPP_H5_BROKER_URL]
  })
  assert.equal(harness.appended.length, 0)
  const directHello = harness.parentWindow.sent[0]
  assert.equal(directHello.targetOrigin, 'http://localhost:5173')
  assert.equal(directHello.message.kind, 'direct-hello')

  const listener = harness.listeners.get('message')
  listener({
    source: {},
    origin: 'http://localhost:5173',
    ports: [],
    data: {
      protocol: 'boxim-miniapp-broker',
      version: '1.0',
      kind: 'direct-bound',
      bindingId: directHello.message.bindingId
    }
  })
  await settle()
  assert.equal(harness.parentWindow.sent.length, 1)

  directBound(harness, 'http://localhost:5173')
  await settle()
  assert.equal(harness.parentWindow.sent.length, 2)
  assert.equal(harness.parentWindow.sent[1].message.method, 'miniapp.ready')
  assert.equal(harness.parentWindow.sent[1].targetOrigin, 'http://localhost:5173')

  listener({
    source: harness.parentWindow,
    origin: 'http://localhost:5173',
    ports: [],
    data: envelope()
  })
  assert.deepEqual(harness.sdk.status(), {phase: 'HOST_READY', terminal: 'WEB'})
})

test('rejects unlisted UniApp H5 broker paths, queries, and ports', () => {
  for (const brokerUrl of [
    'http://localhost:5173/miniapp-host-broker.html',
    'http://localhost:5173/static/miniapp-host-broker.html',
    `${UNIAPP_H5_BROKER_URL}?debug=1`,
    'http://localhost:5174/h5/static/miniapp-host-broker.html',
    'http://localhost:5173/h5/static/miniapp-host-broker.html/extra'
  ]) {
    const harness = createHarness({
      name: preload({brokerUrl}),
      trustedBrokerUrls: [LOCAL_BROKER_URL, UNIAPP_H5_BROKER_URL]
    })
    assert.deepEqual(harness.sdk.status(), {phase: 'BLOCKED', terminal: null})
    assert.equal(harness.listeners.size, 0)
    assert.equal(harness.parentWindow.sent.length, 0)
    assert.equal(harness.appended.length, 0)
  }
})

test('keeps HTTPS brokers on the isolated nested broker transport', () => {
  const harness = createHarness()
  assert.equal(harness.appended.length, 1)
  assert.equal(harness.parentWindow.sent.length, 0)
  assert.equal(harness.iframe.src, BROKER_URL)
})

test('fails closed before listener registration when direct binding entropy fails', () => {
  const harness = createHarness({
    name: preload({brokerUrl: LOCAL_BROKER_URL}),
    trustedBrokerUrls: [LOCAL_BROKER_URL],
    randomFailure: true
  })
  assert.deepEqual(harness.sdk.status(), {phase: 'BLOCKED', terminal: null})
  assert.equal(harness.listeners.size, 0)
  assert.equal(harness.parentWindow.sent.length, 0)
  assert.deepEqual(harness.sdk.diagnostics(), {
    destroyed: true,
    privateStateCleared: true
  })
})

test('sends one READY with an actual S256 PKCE challenge only after exact broker bound', async () => {
  const harness = createHarness()
  bound(harness)
  await settle()
  bound(harness)
  await settle()
  assert.equal(harness.iframe.contentWindow.sent.length, 1)
  const ready = harness.iframe.contentWindow.sent[0]
  assert.equal(ready.targetOrigin, HOST_ORIGIN)
  assert.equal(ready.message.method, 'miniapp.ready')
  assert.equal(ready.message.payload.pkceMethod, 'S256')
  assert.equal(ready.message.payload.pkceChallenge, 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8')
})

test('rejects forged source, origin, ports, and non-closed broker or host envelopes', async () => {
  const harness = createHarness()
  const listener = harness.listeners.get('message')
  for (const event of [
    {source: {}, origin: HOST_ORIGIN, ports: [], data: {protocol: 'boxim-miniapp-broker', version: '1.0', kind: 'bound'}},
    {source: harness.iframe.contentWindow, origin: 'https://evil.example', ports: [], data: {protocol: 'boxim-miniapp-broker', version: '1.0', kind: 'bound'}},
    {source: harness.iframe.contentWindow, origin: HOST_ORIGIN, ports: [{}], data: {protocol: 'boxim-miniapp-broker', version: '1.0', kind: 'bound'}},
    {source: harness.iframe.contentWindow, origin: HOST_ORIGIN, ports: [], data: {protocol: 'boxim-miniapp-broker', version: '1.0', kind: 'bound', extra: true}}
  ]) listener(event)
  await settle()
  assert.equal(harness.iframe.contentWindow.sent.length, 0)
  bound(harness)
  await settle()
  listener({source: harness.iframe.contentWindow, origin: HOST_ORIGIN, ports: [], data: envelope({extra: true})})
  assert.equal(harness.sdk.status().phase, 'READY_SENT')
})

test('accepts only a contract-exact host.init for the correlated READY request id', async () => {
  const harness = createHarness()
  bound(harness)
  await settle()
  const listener = harness.listeners.get('message')
  listener({source: harness.iframe.contentWindow, origin: HOST_ORIGIN, ports: [], data: envelope({nonce: 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB'})})
  assert.equal(harness.sdk.status().phase, 'READY_SENT')
  listener({source: harness.iframe.contentWindow, origin: HOST_ORIGIN, ports: [], data: envelope({id: '01KYN5H8CWSR2PJ6Q8WE46P12Y'})})
  assert.equal(harness.sdk.status().phase, 'READY_SENT')
  listener({source: harness.iframe.contentWindow, origin: HOST_ORIGIN, ports: [], data: envelope({payload: {...envelope().payload, terminal: 'web'}})})
  assert.equal(harness.sdk.status().phase, 'READY_SENT')
  for (const payload of [
    {...envelope().payload, grantedCapabilities: ['auth.launch', 'auth.launch']},
    {...envelope().payload, grantedCapabilities: ['unknown']},
    {...envelope().payload, locale: ''},
    {...envelope().payload, theme: {...envelope().payload.theme, extra: true}},
    {...envelope().payload, safeArea: {...envelope().payload.safeArea, top: -1}},
    {...envelope().payload, grantedCapabilities: new Array(1)},
    {...envelope().payload, locale: 'x'.repeat(17_000)}
  ]) {
    listener({source: harness.iframe.contentWindow, origin: HOST_ORIGIN, ports: [], data: envelope({payload})})
    assert.equal(harness.sdk.status().phase, 'READY_SENT')
  }
  listener({source: harness.iframe.contentWindow, origin: HOST_ORIGIN, ports: [], data: envelope()})
  assert.deepEqual(harness.sdk.status(), {phase: 'HOST_READY', terminal: 'WEB'})
  assert.equal(JSON.stringify(harness.sdk.status()).includes(NONCE), false)
})

test('accepts a 16,384-byte envelope and rejects a 16,385-byte envelope', async () => {
  const accepted = createHarness()
  bound(accepted)
  await settle()
  accepted.listeners.get('message')({
    source: accepted.iframe.contentWindow,
    origin: HOST_ORIGIN,
    ports: [],
    data: envelopeAtByteLength(MAX_ENVELOPE_BYTES)
  })
  assert.deepEqual(accepted.sdk.status(), {phase: 'HOST_READY', terminal: 'WEB'})

  const rejected = createHarness()
  bound(rejected)
  await settle()
  rejected.listeners.get('message')({
    source: rejected.iframe.contentWindow,
    origin: HOST_ORIGIN,
    ports: [],
    data: envelopeAtByteLength(MAX_ENVELOPE_BYTES + 1)
  })
  assert.deepEqual(rejected.sdk.status(), {phase: 'READY_SENT', terminal: null})
})

test('invokes the launch callback exactly once with a transport-local code after auth.launch is granted', async () => {
  let calls = 0
  let seen
  const harness = createHarness({launchCodeHandler(code) { calls += 1; seen = code }})
  bound(harness)
  await settle()
  harness.listeners.get('message')({
    source: harness.iframe.contentWindow,
    origin: HOST_ORIGIN,
    ports: [],
    data: envelope()
  })
  const launch = envelope({
    kind: 'event',
    method: 'auth.launchCode',
    payload: {
      appId: APP_ID,
      versionId: '01KYN5H8CWSR2PJ6Q8WE46P12X',
      launchCode: 'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC',
      expiresAt: new Date(NOW_MS + 60_000).toISOString()
    }
  })
  const event = {source: harness.iframe.contentWindow, origin: HOST_ORIGIN, ports: [], data: launch}
  harness.listeners.get('message')(event)
  harness.listeners.get('message')(event)
  assert.equal(calls, 1)
  assert.equal(seen, launch.payload.launchCode)
  assert.deepEqual(harness.sdk.status(), {phase: 'RUNNING', terminal: 'WEB'})
  assert.equal(JSON.stringify(harness.sdk.status()).includes(launch.payload.launchCode), false)
})

test('does not launch when host.init omits auth.launch', async () => {
  let calls = 0
  const harness = createHarness({launchCodeHandler() { calls += 1 }})
  bound(harness)
  await settle()
  harness.listeners.get('message')({
    source: harness.iframe.contentWindow,
    origin: HOST_ORIGIN,
    ports: [],
    data: envelope({payload: {...envelope().payload, grantedCapabilities: ['host.close']}})
  })
  const launch = envelope({
    kind: 'event',
    method: 'auth.launchCode',
    payload: {
      appId: APP_ID,
      versionId: '01KYN5H8CWSR2PJ6Q8WE46P12X',
      launchCode: 'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC',
      expiresAt: new Date(NOW_MS + 60_000).toISOString()
    }
  })
  harness.listeners.get('message')({source: harness.iframe.contentWindow, origin: HOST_ORIGIN, ports: [], data: launch})
  assert.equal(calls, 0)
  assert.deepEqual(harness.sdk.status(), {phase: 'HOST_READY', terminal: 'WEB'})
})

test('pagehide cleanup removes the broker and listener and clears private protocol state', async () => {
  const harness = createHarness()
  bound(harness)
  await Promise.resolve()
  harness.listeners.get('pagehide')()
  assert.equal(harness.iframe.removeCalled, true)
  assert.equal(harness.listeners.has('message'), false)
  assert.deepEqual(harness.sdk.status(), {phase: 'CLOSED', terminal: null})
  assert.deepEqual(harness.sdk.diagnostics(), {destroyed: true, privateStateCleared: true})
})

test('fails closed and clears broker, listeners, nonce, and verifier when PKCE generation fails', async () => {
  const harness = createHarness({digestResult: async () => { throw new Error('digest failed') }})
  bound(harness)
  await settle()
  assert.equal(harness.iframe.removeCalled, true)
  assert.equal(harness.listeners.has('message'), false)
  assert.deepEqual(harness.sdk.status(), {phase: 'BLOCKED', terminal: null})
  assert.deepEqual(harness.sdk.diagnostics(), {destroyed: true, privateStateCleared: true})
})

test('does not touch browser persistence, navigation, console, cookie, or DOM sinks with protocol material', () => {
  const harness = createHarness({runtimeTraps: true})
  assert.deepEqual(harness.sdk.status(), {phase: 'CONNECTING', terminal: null})
  assert.equal(harness.document.documentElement.dataset.bridgeReady, undefined)
  assert.equal(harness.statuses.every(status =>
    Object.keys(status).every(key => ['phase', 'terminal'].includes(key))
  ), true)
})

test('keeps every browser sink clean through the full trusted lifecycle', async () => {
  let launchCalls = 0
  const harness = createHarness({
    runtimeTraps: true,
    launchCodeHandler() { launchCalls += 1 }
  })
  bound(harness)
  await settle()
  harness.listeners.get('message')({
    source: harness.iframe.contentWindow,
    origin: HOST_ORIGIN,
    ports: [],
    data: envelope()
  })
  const launch = envelope({
    kind: 'event',
    method: 'auth.launchCode',
    payload: {
      appId: APP_ID,
      versionId: '01KYN5H8CWSR2PJ6Q8WE46P12X',
      launchCode: 'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC',
      expiresAt: new Date(NOW_MS + 60_000).toISOString()
    }
  })
  harness.listeners.get('message')({
    source: harness.iframe.contentWindow,
    origin: HOST_ORIGIN,
    ports: [],
    data: launch
  })
  assert.equal(launchCalls, 1)
  assert.deepEqual(harness.sdk.status(), {phase: 'RUNNING', terminal: 'WEB'})
  assert.equal(harness.statuses.every(status =>
    Object.keys(status).every(key => ['phase', 'terminal'].includes(key))
  ), true)
  assert.equal(JSON.stringify([harness.sdk.status(), harness.sdk.diagnostics()]).includes(NONCE), false)
  assert.equal(JSON.stringify([harness.sdk.status(), harness.sdk.diagnostics()]).includes(VERIFIER), false)
  assert.equal(JSON.stringify([harness.sdk.status(), harness.sdk.diagnostics()]).includes(launch.payload.launchCode), false)
  assert.equal(JSON.stringify(harness.domWrites).includes(NONCE), false)
  assert.equal(JSON.stringify(harness.domWrites).includes(VERIFIER), false)
  assert.equal(JSON.stringify(harness.domWrites).includes(launch.payload.launchCode), false)
  harness.sdk.destroy()
  assert.deepEqual(harness.sdk.diagnostics(), {destroyed: true, privateStateCleared: true})
})

test('executes the real inline bootstrap with a synchronously cleared captured preload', async () => {
  const result = await runInlineBootstrap()
  assert.equal(result.window.name, '')
  assert.equal(result.importCalls, 1)
  assert.equal(result.options.length, 1)
  assert.equal(result.options[0].preloadedName, result.preloadValue)
  assert.equal(result.options[0].appId, APP_ID)
  assert.deepEqual(Array.from(result.options[0].trustedBrokerUrls), [
    LOCAL_BROKER_URL,
    UNIAPP_H5_BROKER_URL
  ])
  assert.equal(result.status.textContent.includes(result.preloadValue), false)
  assert.equal(result.detail.textContent.includes(result.preloadValue), false)
  assert.equal(JSON.stringify(result.document.documentElement.dataset).includes(result.preloadValue), false)
})

test('renders only BLOCKED copy when the real inline bootstrap import fails', async () => {
  const result = await runInlineBootstrap({rejectImport: true})
  assert.equal(result.window.name, '')
  assert.equal(result.importCalls, 1)
  assert.equal(result.options.length, 0)
  assert.equal(result.status.textContent, '请从聊天系统打开')
  assert.equal(result.detail.textContent, '此演示页只能作为 MiniApp 在聊天系统中运行。')
  assert.equal(result.status.textContent.includes(result.preloadValue), false)
  assert.equal(result.detail.textContent.includes(result.preloadValue), false)
})
