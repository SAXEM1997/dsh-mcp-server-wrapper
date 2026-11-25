#!/usr/bin/env node
/**
 * The policy that decides whether one settings request may proceed.
 *
 * The case that matters is the ordinary one: a browser asks for the settings page
 * from the page it is already on. Browsers send `Sec-Fetch-Site` on every request
 * but omit `Origin` on a same-origin GET, so a policy that only admits requests
 * carrying an `Origin` refuses the page it was written for — while `curl`, which
 * sends neither header, sails through.
 *
 * Run: node test/config-trust-test.mjs
 */

import assert from 'node:assert/strict'

import { createConfigTrust } from '../lib/config-trust.js'

let passed = 0
const failures = []
async function check(name, run) {
  try {
    await run()
    passed += 1
    console.log(`ok - ${name}`)
  } catch (error) {
    failures.push({ name, error })
    console.log(`FAIL - ${name}\n  ${error && error.message ? error.message : String(error)}`)
  }
}

const HOST = '127.0.0.1:23023'
const trust = (options = {}) => createConfigTrust({ getConnection: () => undefined, ...options })

function request(headers = {}) {
  return { headers: { host: HOST, ...headers } }
}

await check('a request with no browser headers at all is admitted', async () => {
  assert.equal(trust()(request()), true)
})

await check('a same-origin navigation carries no Origin and must be admitted', async () => {
  // The defect: `Sec-Fetch-Site` made this a "browser request", and the only
  // success path then required an `Origin` header — which the browser does not
  // send for a same-origin GET. The settings page got a 403 and reported it as
  // "served to the local machine only".
  assert.equal(trust()(request({ 'sec-fetch-site': 'same-origin' })), true)
})

await check('a same-site request without Origin is refused', async () => {
  // `same-site` is another origin on the same site — a page on a different port
  // of this host. It is not this listener's own document, so the absence of an
  // `Origin` must not be read as permission.
  assert.equal(trust()(request({ 'sec-fetch-site': 'same-site' })), false)
})

await check('a same-site request is refused even when the Host connection would admit it', async () => {
  // The rule must not depend on whether `connection` happens to be resolvable at
  // the moment the request arrives. A live connection answers for its own
  // browsers and is more permissive about a missing `Origin`, so deferring to it
  // made the same-site case flip between boots: 403 when the service was absent,
  // 200 when it was present. A page on another port of this host is still not
  // this listener's own document.
  const accepting = trust({ getConnection: () => ({ requestRejection: () => undefined }) })
  assert.equal(accepting(request({ 'sec-fetch-site': 'same-site' })), false,
    'an accepting connection must not admit a same-site request with no Origin')
  const sameOrigin = trust({ getConnection: () => ({ requestRejection: () => undefined }) })
  assert.equal(sameOrigin(request({ 'sec-fetch-site': 'same-origin' })), true,
    'the same-origin GET the settings page makes is still admitted')
})

await check('a typed navigation is admitted', async () => {
  // `none` is the user opening the URL directly, with no cross-site initiator.
  assert.equal(trust()(request({ 'sec-fetch-site': 'none' })), true)
})

await check('a cross-site request is refused', async () => {
  assert.equal(trust()(request({ 'sec-fetch-site': 'cross-site' })), false)
  assert.equal(trust()(request({ origin: `http://${HOST}`, 'sec-fetch-site': 'cross-site' })), false)
})

await check('a same-origin request with a matching Origin is admitted', async () => {
  assert.equal(trust()(request({ origin: `http://${HOST}`, 'sec-fetch-site': 'same-origin' })), true)
})

await check('an Origin on another authority is refused', async () => {
  assert.equal(trust()(request({ origin: 'http://evil.example', 'sec-fetch-site': 'same-origin' })), false)
  assert.equal(trust()(request({ origin: 'https://192.168.50.216:23022' })), false)
})

await check('a request without a Host is refused', async () => {
  const bare = { headers: { 'sec-fetch-site': 'same-origin' } }
  assert.equal(trust()(bare), false)
})

await check('the Host connection still decides when it is available', async () => {
  const rejecting = trust({ getConnection: () => ({ requestRejection: () => 401 }) })
  assert.equal(rejecting(request({ 'sec-fetch-site': 'same-origin' })), false, 'a rejected connection is refused')
  const accepting = trust({ getConnection: () => ({ requestRejection: () => undefined }) })
  assert.equal(accepting(request({ 'sec-fetch-site': 'same-origin' })), true, 'an accepted connection is admitted')
})

await check('a failing connection check falls through to the header fence', async () => {
  const broken = trust({ getConnection: () => ({ requestRejection: () => { throw new Error('boom') } }) })
  assert.equal(broken(request({ origin: `http://${HOST}` })), true, 'the throw must not admit or refuse by itself')
  assert.equal(broken(request({ origin: 'http://evil.example' })), false)
})

if (failures.length > 0) {
  console.error(`\n${failures.length} config-trust checks failed`)
  process.exit(1)
}
console.log(`\n${passed} config-trust checks passed`)
