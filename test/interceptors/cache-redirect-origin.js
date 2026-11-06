'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')
const { createServer } = require('node:http')
const { once } = require('node:events')
const { join } = require('node:path')
const { tmpdir } = require('node:os')
const { rm } = require('node:fs/promises')
const {
  Agent,
  Pool,
  cacheStores,
  interceptors
} = require('../../')
const { runtimeFeatures } = require('../../lib/util/runtime-features.js')

/**
 * Reproduces GHSA-4W7W-5XRC-9H26: when a shared cache is placed outside the
 * redirect interceptor (`compose(redirect(), cache())`), the cache keys the
 * response on the original (trusted) origin before the redirect handler
 * changes the origin. The cross-origin response is then stored under the
 * trusted key, so a later request to the trusted URL receives attacker bytes
 * even though it never hit either origin.
 *
 * The fix verifies, before storing, that the effective request origin matches
 * the cache key origin. See lib/handler/cache-handler.js.
 */

async function listen (server) {
  return new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
}

async function closeServer (server) {
  server.close()
  await once(server, 'close')
}

async function withOrigins (run) {
  const state = {
    redirectEnabled: true,
    trustedHits: 0,
    attackerHits: 0
  }

  const attacker = createServer((_req, res) => {
    state.attackerHits++
    res.writeHead(200, {
      'cache-control': 'public, max-age=86400',
      'content-type': 'text/plain'
    })
    res.end('attacker-controlled-content')
  })

  const trusted = createServer((req, res) => {
    state.trustedHits++
    if (state.redirectEnabled && req.url === '/resource') {
      res.writeHead(302, {
        location: `http://127.0.0.1:${attacker.address().port}/payload`
      })
      res.end()
      return
    }
    res.writeHead(200, {
      'cache-control': 'no-store',
      'content-type': 'text/plain'
    })
    res.end('legitimate-content')
  })

  await Promise.all([listen(trusted), listen(attacker)])

  const trustedOrigin = `http://127.0.0.1:${trusted.address().port}`
  try {
    return await run({ state, trustedOrigin })
  } finally {
    await Promise.all([closeServer(trusted), closeServer(attacker)])
  }
}

async function requestAgent (agent, origin, user) {
  const response = await agent.request({
    origin,
    path: '/resource',
    method: 'GET',
    headers: { cookie: `session=${user}` }
  })
  return response.body.text()
}

test('cache does not store a cross-origin redirect response under the original origin key (memory)', async () => {
  await withOrigins(async ({ state, trustedOrigin }) => {
    const agent = new Agent().compose(
      interceptors.redirect({ maxRedirections: 2 }),
      interceptors.cache({
        store: new cacheStores.MemoryCacheStore(),
        type: 'shared'
      })
    )

    const mallory = await requestAgent(agent, trustedOrigin, 'mallory')
    state.redirectEnabled = false
    const hitsBeforeAlice = [state.trustedHits, state.attackerHits]
    const alice = await requestAgent(agent, trustedOrigin, 'alice')
    const hitsAfterAlice = [state.trustedHits, state.attackerHits]

    try {
      assert.equal(mallory, 'attacker-controlled-content')
      // Alice must receive the legitimate origin's response, not the poisoned
      // attacker bytes. A cache hit on a poisoned entry would serve
      // 'attacker-controlled-content' without contacting the trusted origin.
      assert.equal(alice, 'legitimate-content')
      // The trusted origin must have actually been contacted for Alice's
      // request, proving the poisoned entry was not served.
      assert.notDeepEqual(hitsAfterAlice, hitsBeforeAlice)
    } finally {
      await agent.close()
    }
  })
})

test('cache does not store a cross-origin redirect response under the original origin key (sqlite persistence)', { skip: runtimeFeatures.has('sqlite') === false }, async () => {
  const database = join(tmpdir(), `undici-cache-redirect-origin-${process.pid}.sqlite`)
  try {
    await withOrigins(async ({ state, trustedOrigin }) => {
      const firstStore = new cacheStores.SqliteCacheStore({ location: database })
      const firstAgent = new Agent().compose(
        interceptors.redirect({ maxRedirections: 2 }),
        interceptors.cache({ store: firstStore, type: 'shared' })
      )
      const mallory = await requestAgent(firstAgent, trustedOrigin, 'mallory')
      await firstAgent.close()
      firstStore.close()

      state.redirectEnabled = false
      const hitsBeforeAlice = [state.trustedHits, state.attackerHits]
      const reopenedStore = new cacheStores.SqliteCacheStore({ location: database })
      const secondAgent = new Agent().compose(
        interceptors.redirect({ maxRedirections: 2 }),
        interceptors.cache({ store: reopenedStore, type: 'shared' })
      )
      const alice = await requestAgent(secondAgent, trustedOrigin, 'alice')
      const hitsAfterAlice = [state.trustedHits, state.attackerHits]
      await secondAgent.close()
      reopenedStore.close()

      assert.equal(mallory, 'attacker-controlled-content')
      assert.equal(alice, 'legitimate-content')
      assert.notDeepEqual(hitsAfterAlice, hitsBeforeAlice)
    })
  } finally {
    await rm(database, { force: true })
  }
})

test('reverse interceptor order (cache outside redirect) still works', async () => {
  await withOrigins(async ({ state, trustedOrigin }) => {
    const agent = new Agent().compose(
      interceptors.cache({
        store: new cacheStores.MemoryCacheStore(),
        type: 'shared'
      }),
      interceptors.redirect({ maxRedirections: 2 })
    )

    const mallory = await requestAgent(agent, trustedOrigin, 'mallory')
    state.redirectEnabled = false
    const alice = await requestAgent(agent, trustedOrigin, 'alice')

    try {
      assert.equal(mallory, 'attacker-controlled-content')
      assert.equal(alice, 'legitimate-content')
      assert.equal(state.trustedHits, 2)
      assert.equal(state.attackerHits, 1)
    } finally {
      await agent.close()
    }
  })
})

test('same-origin redirect responses are still cached by the cache interceptor', async () => {
  const state = { redirectEnabled: true, targetHits: 0 }
  const server = createServer((req, res) => {
    if (state.redirectEnabled && req.url === '/resource') {
      res.writeHead(302, { location: '/target' })
      res.end()
      return
    }
    state.targetHits++
    res.writeHead(200, {
      'cache-control': 'public, max-age=86400',
      'content-type': 'text/plain'
    })
    res.end('same-origin-content')
  })
  await listen(server)
  const origin = `http://127.0.0.1:${server.address().port}`

  const agent = new Agent().compose(
    interceptors.redirect({ maxRedirections: 2 }),
    interceptors.cache({
      store: new cacheStores.MemoryCacheStore(),
      type: 'shared'
    })
  )

  try {
    const first = await agent.request({ origin, path: '/resource', method: 'GET' })
      .then(response => response.body.text())
    // Disable the redirect then request the original URL again: the response
    // should be served from the cache, proving a same-origin redirect was not
    // incorrectly rejected by the cross-origin origin check.
    state.redirectEnabled = false
    const hitsBefore = state.targetHits
    const second = await agent.request({ origin, path: '/resource', method: 'GET' })
      .then(response => response.body.text())

    assert.equal(first, 'same-origin-content')
    assert.equal(second, 'same-origin-content')
    // Second request must be a cache hit (the /target origin was not re-hit).
    assert.equal(state.targetHits, hitsBefore)
  } finally {
    await agent.close()
    await closeServer(server)
  }
})

test('origin-bound Pool cannot be poisoned by a cross-origin redirect', async () => {
  await withOrigins(async ({ state, trustedOrigin }) => {
    const pool = new Pool(trustedOrigin).compose(
      interceptors.redirect({ maxRedirections: 2 }),
      interceptors.cache({
        store: new cacheStores.MemoryCacheStore(),
        type: 'shared'
      })
    )

    const first = await pool.request({ path: '/resource', method: 'GET' })
      .then(response => response.body.text())
    state.redirectEnabled = false
    const second = await pool.request({ path: '/resource', method: 'GET' })
      .then(response => response.body.text())

    try {
      assert.equal(first, 'legitimate-content')
      assert.equal(second, 'legitimate-content')
      // An origin-bound dispatcher must not be able to reach the attacker origin.
      assert.equal(state.attackerHits, 0)
    } finally {
      await pool.close()
    }
  })
})

// A redirect response must only be reused for a request that could itself
// reach it. Matching the cache-key origin is not sufficient: when the original
// hop is `private, no-store` and redirects to a different resource on the same
// origin, the final body must not be stored under the original request's key,
// otherwise a later caller that is not entitled to the redirect (here an
// unauthenticated one) is served the private body from the shared cache.
test('cache does not store a same-origin redirect response under the original path key', async () => {
  const state = { authEnabled: true, objectHits: 0 }

  const server = createServer((req, res) => {
    if (req.url === '/account') {
      if (state.authEnabled && req.headers.authorization) {
        res.writeHead(302, {
          'cache-control': 'private, no-store',
          location: '/signed-object?token=alice'
        })
        res.end()
        return
      }
      res.writeHead(403, { 'cache-control': 'no-store' })
      res.end('denied')
      return
    }

    if (req.url.startsWith('/signed-object')) {
      state.objectHits++
      res.writeHead(200, {
        'cache-control': 'public, max-age=86400',
        'content-type': 'text/plain'
      })
      res.end('alice-private-object')
      return
    }

    res.writeHead(404)
    res.end('not found')
  })

  await listen(server)
  const origin = `http://127.0.0.1:${server.address().port}`

  const agent = new Agent().compose(
    interceptors.redirect({ maxRedirections: 2 }),
    interceptors.cache({
      store: new cacheStores.MemoryCacheStore(),
      type: 'shared'
    })
  )

  try {
    const authed = await agent.request({
      origin,
      path: '/account',
      method: 'GET',
      headers: { authorization: 'Bearer alice' }
    }).then(response => response.body.text())
    assert.equal(authed, 'alice-private-object')

    state.authEnabled = false
    const anon = await agent.request({
      origin,
      path: '/account',
      method: 'GET'
    }).then(response => response.body.text())

    // The unauthenticated caller must not receive the private object from the
    // cache. With the request no longer authenticated the account endpoint
    // denies it; a poisoned cache entry would instead return the private body.
    assert.notEqual(anon, 'alice-private-object')
    assert.equal(anon, 'denied')
  } finally {
    await agent.close()
    await closeServer(server)
  }
})

// The guard against caching a cross-origin redirect response must hold for any
// composition, not only `compose(redirect(), cache())`. The cache must learn
// the final origin without depending on a shared mutable options object, since
// an interceptor between the cache and the redirect (here `deduplicate`) may
// hand the redirect a copy, so composing one must not reopen cross-origin
// cache poisoning.
test('cache does not store a cross-origin redirect response when a copying interceptor sits between cache and redirect', async () => {
  await withOrigins(async ({ state, trustedOrigin }) => {
    const agent = new Agent().compose(
      interceptors.redirect({ maxRedirections: 2 }),
      interceptors.deduplicate(),
      interceptors.cache({
        store: new cacheStores.MemoryCacheStore(),
        type: 'shared'
      })
    )

    const mallory = await requestAgent(agent, trustedOrigin, 'mallory')
    state.redirectEnabled = false
    const hitsBeforeAlice = [state.trustedHits, state.attackerHits]
    const alice = await requestAgent(agent, trustedOrigin, 'alice')
    const hitsAfterAlice = [state.trustedHits, state.attackerHits]

    try {
      assert.equal(mallory, 'attacker-controlled-content')
      // Alice must receive the legitimate origin's response, not the poisoned
      // attacker bytes, and the trusted origin must be contacted again.
      assert.equal(alice, 'legitimate-content')
      assert.notDeepEqual(hitsAfterAlice, hitsBeforeAlice)
    } finally {
      await agent.close()
    }
  })
})

for (const redirectType of ['same-origin', 'cross-origin']) {
  test(`a ${redirectType} 304 after a redirect cannot validate the original cached response`, async () => {
    const targetValidators = []
    let targetOrigin

    const target = redirectType === 'cross-origin'
      ? createServer((req, res) => {
        const validator = req.headers['if-none-match']
        targetValidators.push(validator)
        if (validator) {
          res.writeHead(304, { etag: '"trusted-private"' })
        } else {
          res.writeHead(200, { 'cache-control': 'no-store' })
          res.write('target-response')
        }
        res.end()
      })
      : undefined

    if (target) {
      await listen(target)
      targetOrigin = `http://127.0.0.1:${target.address().port}`
    }

    const trusted = createServer((req, res) => {
      if (req.url === '/resource' && req.headers.authorization === 'Bearer alice') {
        res.writeHead(200, {
          'cache-control': 'must-revalidate, max-age=0',
          etag: '"trusted-private"'
        })
        res.end('alice-private-response')
        return
      }

      if (req.url === '/resource') {
        res.writeHead(302, {
          'cache-control': 'private, no-store',
          location: redirectType === 'cross-origin' ? `${targetOrigin}/validate` : '/validate'
        })
        res.end()
        return
      }

      const validator = req.headers['if-none-match']
      targetValidators.push(validator)
      if (validator) {
        res.writeHead(304, { etag: '"trusted-private"' })
      } else {
        res.writeHead(200, { 'cache-control': 'no-store' })
        res.write('target-response')
      }
      res.end()
    })

    await listen(trusted)
    const trustedOrigin = `http://127.0.0.1:${trusted.address().port}`
    const agent = new Agent().compose(
      interceptors.redirect({ maxRedirections: 2 }),
      interceptors.cache({
        store: new cacheStores.MemoryCacheStore(),
        type: 'shared'
      })
    )

    try {
      const prime = await agent.request({
        origin: trustedOrigin,
        path: '/resource',
        method: 'GET',
        headers: { authorization: 'Bearer alice' }
      })
      assert.equal(await prime.body.text(), 'alice-private-response')

      const revalidated = await agent.request({
        origin: trustedOrigin,
        path: '/resource',
        method: 'GET'
      })

      assert.equal(revalidated.statusCode, 200)
      assert.equal(await revalidated.body.text(), 'target-response')
      assert.deepEqual(targetValidators, ['"trusted-private"', undefined])
    } finally {
      await agent.close()
      await closeServer(trusted)
      if (target) {
        await closeServer(target)
      }
    }
  })
}

test('a mismatched strong ETag cannot validate a cached response', async () => {
  const validators = []
  const server = createServer((req, res) => {
    if (req.headers.authorization === 'Bearer alice') {
      res.writeHead(200, {
        'cache-control': 'must-revalidate, max-age=0',
        etag: '"trusted-private"'
      })
      res.end('alice-private-response')
      return
    }

    const validator = req.headers['if-none-match']
    validators.push(validator)
    if (validator) {
      res.writeHead(304, { etag: '"mismatched"' })
    } else {
      res.writeHead(200, { 'cache-control': 'no-store' })
      res.write('replacement-response')
    }
    res.end()
  })

  await listen(server)
  const origin = `http://127.0.0.1:${server.address().port}`
  const agent = new Agent().compose(interceptors.cache({
    store: new cacheStores.MemoryCacheStore(),
    type: 'shared'
  }))

  try {
    const prime = await agent.request({
      origin,
      path: '/resource',
      method: 'GET',
      headers: { authorization: 'Bearer alice' }
    })
    assert.equal(await prime.body.text(), 'alice-private-response')

    const revalidated = await agent.request({
      origin,
      path: '/resource',
      method: 'GET'
    })

    assert.equal(revalidated.statusCode, 200)
    assert.equal(await revalidated.body.text(), 'replacement-response')
    assert.deepEqual(validators, ['"trusted-private"', undefined])
  } finally {
    await agent.close()
    await closeServer(server)
  }
})

// Deduplicated requests that join an in-flight request before it starts receive
// the response through a separate replay path. That path must still carry the
// redirect history, otherwise a joined request caches a cross-origin redirect
// response under the original key while the primary request correctly rejects
// it.
test('cache does not store a cross-origin redirect response for a deduplicated concurrent request', async () => {
  const state = { redirectEnabled: true, attackerHits: 0 }

  const attacker = createServer((_req, res) => {
    state.attackerHits++
    res.writeHead(200, {
      'cache-control': 'public, max-age=86400',
      'content-type': 'text/plain'
    })
    res.end('attacker-controlled-content')
  })

  const trusted = createServer((req, res) => {
    if (state.redirectEnabled && req.url === '/resource') {
      // Delay the redirect so both concurrent requests are in-flight together
      // and the second is deduplicated onto the first.
      setTimeout(() => {
        res.writeHead(302, {
          location: `http://127.0.0.1:${attacker.address().port}/payload`
        })
        res.end()
      }, 50)
      return
    }
    res.writeHead(200, {
      'cache-control': 'no-store',
      'content-type': 'text/plain'
    })
    res.end('legitimate-content')
  })

  await Promise.all([listen(trusted), listen(attacker)])
  const trustedOrigin = `http://127.0.0.1:${trusted.address().port}`

  const agent = new Agent().compose(
    interceptors.redirect({ maxRedirections: 2 }),
    interceptors.deduplicate(),
    interceptors.cache({
      store: new cacheStores.MemoryCacheStore(),
      type: 'shared'
    })
  )

  try {
    const request = () => agent
      .request({ origin: trustedOrigin, path: '/resource', method: 'GET' })
      .then(response => response.body.text())

    const [first, second] = await Promise.all([request(), request()])
    state.redirectEnabled = false
    const third = await request()

    assert.equal(first, 'attacker-controlled-content')
    assert.equal(second, 'attacker-controlled-content')
    // The entry must not have been poisoned by either the primary or the
    // deduplicated request, so a later caller reaches the trusted origin.
    assert.equal(third, 'legitimate-content')
  } finally {
    await agent.close()
    await Promise.all([closeServer(trusted), closeServer(attacker)])
  }
})

// Reproduces GHSA-7XG3-FPHP-28HG (CWE-524 / CWE-639).
//
// A credential-bearing **same-origin** redirect whose final hop advertises a
// permissive cache policy (`public`, `s-maxage`, or `must-revalidate`) must not
// be stored under the original (alias) URL key. The intermediate redirect here
// carries no restrictive `Cache-Control` (a bare 302), so the suppressed-hop
// guard does not trip, and the final hop shares the cache-key origin, so the
// cross-origin guard does not trip either. Because the store key omits the
// credential (and the final hop has no `Vary`), a later request for the alias
// URL by a different principal — or an anonymous caller — would be served the
// first principal's private body without re-contacting the origin.
//
// The credential matters even when the request is cookie-authenticated: the
// RFC-9111 §3.5 authenticated-request gate only inspects `Authorization`, so a
// cookie-only request with a plain `max-age` final hop was also disclosed.
for (const { name, credentialHeaders, finalCacheControl } of [
  {
    name: 'authorization + public final hop',
    credentialHeaders: { authorization: 'Bearer alice' },
    finalCacheControl: 'public, max-age=600'
  },
  {
    name: 'authorization + must-revalidate final hop',
    credentialHeaders: { authorization: 'Bearer alice' },
    finalCacheControl: 'max-age=600, must-revalidate'
  },
  {
    name: 'cookie-only + public final hop',
    credentialHeaders: { cookie: 'session=alice' },
    finalCacheControl: 'public, max-age=600'
  },
  {
    name: 'cookie-only + max-age final hop (bypasses RFC 9111 §3.5 gate)',
    credentialHeaders: { cookie: 'session=alice' },
    finalCacheControl: 'max-age=600'
  }
]) {
  test(`cache does not store a same-origin redirect for a credential-bearing request under the alias key (${name})`, async () => {
    const state = { me: 0, profile: 0 }
    const server = createServer((req, res) => {
      const requestUrl = new URL(req.url, 'http://dummy')
      if (requestUrl.pathname === '/me') {
        state.me++
        const user = (req.headers.authorization || req.headers.cookie || 'anon')
          .replace('Bearer ', '')
          .replace('session=', '')
        res.writeHead(302, { location: `/profile/${user}` })
        res.end()
        return
      }
      if (requestUrl.pathname.startsWith('/profile/')) {
        state.profile++
        const user = requestUrl.pathname.split('/')[2]
        res.writeHead(200, {
          'cache-control': finalCacheControl,
          'content-type': 'text/plain'
        })
        res.end(`${user.toUpperCase()} ssn=111-11-1111`)
        return
      }
      res.writeHead(404)
      res.end('not found')
    })

    await listen(server)
    const origin = `http://127.0.0.1:${server.address().port}`

    const agent = new Agent().compose(
      interceptors.redirect({ maxRedirections: 2 }),
      interceptors.cache({
        store: new cacheStores.MemoryCacheStore(),
        type: 'shared'
      })
    )

    const requestAs = (user, headers) => agent.request({
      origin,
      path: '/me',
      method: 'GET',
      headers
    }).then(response => response.body.text())

    try {
      const alice = await requestAs('alice', credentialHeaders)
      assert.equal(alice, 'ALICE ssn=111-11-1111')

      // A different principal must receive its own profile, and an anonymous
      // caller must also reach the origin rather than be served Alice's body.
      const bob = await requestAs('bob', {
        authorization: 'Bearer bob'
      })
      const anon = await requestAs('anon', undefined)

      assert.equal(bob, 'BOB ssn=111-11-1111')
      assert.equal(anon, 'ANON ssn=111-11-1111')
      // Every request must have reached the origin: nothing was stored under
      // the alias key, so none were served from the shared cache.
      assert.equal(state.me, 3)
      assert.equal(state.profile, 3)
    } finally {
      await agent.close()
      await closeServer(server)
    }
  })
}

// The fix must not regress the legitimate same-origin redirect caching for
// requests that carry no credential: those are still cached under the original
// key, so the redirect target is not re-fetched on a repeat request.
test('cache still stores an unauthenticated same-origin redirect under the original key', async () => {
  const state = { hits: 0 }
  const server = createServer((req, res) => {
    if (req.url === '/alias') {
      res.writeHead(302, { location: '/target' })
      res.end()
      return
    }
    state.hits++
    res.writeHead(200, {
      'cache-control': 'public, max-age=600',
      'content-type': 'text/plain'
    })
    res.end('public-content')
  })

  await listen(server)
  const origin = `http://127.0.0.1:${server.address().port}`

  const agent = new Agent().compose(
    interceptors.redirect({ maxRedirections: 2 }),
    interceptors.cache({
      store: new cacheStores.MemoryCacheStore(),
      type: 'shared'
    })
  )

  try {
    const first = await agent.request({
      origin,
      path: '/alias',
      method: 'GET'
    }).then(response => response.body.text())
    assert.equal(first, 'public-content')

    const hitsBefore = state.hits
    const second = await agent.request({
      origin,
      path: '/alias',
      method: 'GET'
    }).then(response => response.body.text())

    assert.equal(second, 'public-content')
    // The repeat request must be a cache hit (the target was not re-fetched).
    assert.equal(state.hits, hitsBefore)
  } finally {
    await agent.close()
    await closeServer(server)
  }
})
