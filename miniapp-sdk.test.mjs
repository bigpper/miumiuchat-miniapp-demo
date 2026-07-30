import assert from 'node:assert/strict'
import test from 'node:test'

import {createMiniAppSdk} from './miniapp-sdk.js'

const APP_ID = '01KYN5H8CWSR2PJ6Q8WE46P12V'
const HOST_ORIGIN = 'https://im.example.com'
const BROKER_URL = `${HOST_ORIGIN}/miniapp-host-broker.html`
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
      terminal: 'web',
      locale: 'zh-CN',
      theme: {mode: 'light', backgroundColor: '#fff', textColor: '#000', accentColor: '#07c160'},
      safeArea: {top: 0, right: 0, bottom: 0, left: 0}
    },
    error: null,
    ...overrides
  }
}

function createHarness({name = preload(), launchCodeHandler = () => {}} = {}) {
  const listeners = new Map()
  const iframeListeners = new Map()
  const iframe = {
    contentWindow: {
      sent: [],
      postMessage(message, targetOrigin) { this.sent.push({message, targetOrigin}) }
    },
    removeCalled: false,
    setAttribute() {},
    addEventListener(type, listener) { iframeListeners.set(type, listener) },
    removeEventListener(type, listener) { if (iframeListeners.get(type) === listener) iframeListeners.delete(type) },
    remove() { this.removeCalled = true }
  }
  const document = {
    documentElement: {dataset: {}},
    body: {appendChild(value) { assert.equal(value, iframe) }},
    createElement(type) { assert.equal(type, 'iframe'); return iframe }
  }
  const window = {
    name,
    location: {origin: 'https://mini.example.com'},
    addEventListener(type, listener) { listeners.set(type, listener) },
    removeEventListener(type, listener) { if (listeners.get(type) === listener) listeners.delete(type) }
  }
  const crypto = {
    getRandomValues(bytes) { bytes.fill(1); return bytes },
    subtle: {async digest(name, bytes) {
      assert.equal(name, 'SHA-256')
      assert.equal(new TextDecoder().decode(bytes), VERIFIER)
      return Uint8Array.from({length: 32}, (_, index) => index).buffer
    }}
  }
  const statuses = []
  const sdk = createMiniAppSdk({
    windowObject: window,
    documentObject: document,
    cryptoObject: crypto,
    appId: APP_ID,
    createId: () => ID,
    createNonce: () => NONCE,
    createVerifier: () => VERIFIER,
    onStatus: status => statuses.push(status),
    onLaunchCode: launchCodeHandler
  })
  return {sdk, window, document, iframe, listeners, iframeListeners, statuses}
}

function bound(harness) {
  harness.listeners.get('message')({
    source: harness.iframe.contentWindow,
    origin: HOST_ORIGIN,
    ports: [],
    data: {protocol: 'boxim-miniapp-broker', version: '1.0', kind: 'bound'}
  })
}

test('clears window.name synchronously before any asynchronous PKCE work', () => {
  const harness = createHarness()
  assert.equal(harness.window.name, '')
  assert.equal(harness.iframe.contentWindow.sent.length, 0)
  assert.equal(harness.sdk.status().phase, 'CONNECTING')
})

test('rejects preload with extra fields or a noncanonical broker before creating an iframe', () => {
  for (const name of [preload({extra: true}), preload({brokerUrl: `${BROKER_URL}?x=1`})]) {
    const harness = createHarness({name})
    assert.equal(harness.sdk.status().phase, 'BLOCKED')
    assert.equal(harness.listeners.size, 0)
  }
})

test('sends one READY with an actual S256 PKCE challenge only after exact broker bound', async () => {
  const harness = createHarness()
  bound(harness)
  await Promise.resolve()
  bound(harness)
  await Promise.resolve()
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
  await Promise.resolve()
  assert.equal(harness.iframe.contentWindow.sent.length, 0)
  bound(harness)
  await Promise.resolve()
  listener({source: harness.iframe.contentWindow, origin: HOST_ORIGIN, ports: [], data: envelope({extra: true})})
  assert.equal(harness.sdk.status().phase, 'READY_SENT')
})

test('accepts only an exact host.init for the READY nonce and exposes no sensitive state', async () => {
  const harness = createHarness()
  bound(harness)
  await Promise.resolve()
  const listener = harness.listeners.get('message')
  listener({source: harness.iframe.contentWindow, origin: HOST_ORIGIN, ports: [], data: envelope({nonce: 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB'})})
  assert.equal(harness.sdk.status().phase, 'READY_SENT')
  listener({source: harness.iframe.contentWindow, origin: HOST_ORIGIN, ports: [], data: envelope()})
  assert.deepEqual(harness.sdk.status(), {phase: 'HOST_READY', terminal: 'web'})
  assert.equal(JSON.stringify(harness.sdk.status()).includes(NONCE), false)
})

test('invokes the launch callback exactly once with a transport-local code', async () => {
  let calls = 0
  let seen
  const harness = createHarness({launchCodeHandler(code) { calls += 1; seen = code }})
  bound(harness)
  await Promise.resolve()
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
      expiresAt: '2030-01-01T00:00:00.000Z'
    }
  })
  const event = {source: harness.iframe.contentWindow, origin: HOST_ORIGIN, ports: [], data: launch}
  harness.listeners.get('message')(event)
  harness.listeners.get('message')(event)
  assert.equal(calls, 1)
  assert.equal(seen, launch.payload.launchCode)
  assert.deepEqual(harness.sdk.status(), {phase: 'RUNNING', terminal: 'web'})
  assert.equal(JSON.stringify(harness.sdk.status()).includes(launch.payload.launchCode), false)
})

test('pagehide cleanup removes the broker and listener and clears private protocol state', async () => {
  const harness = createHarness()
  bound(harness)
  await Promise.resolve()
  harness.listeners.get('pagehide')()
  assert.equal(harness.iframe.removeCalled, true)
  assert.equal(harness.listeners.has('message'), false)
  assert.deepEqual(harness.sdk.status(), {phase: 'CLOSED', terminal: null})
})
