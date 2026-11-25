/**
 * Whether one settings request may proceed.
 *
 * Two fences guard `/mcp-config` and `/mcp-scope`: the caller must be on this
 * machine, and — because a foreign page could otherwise drive the settings with
 * a CORS-simple request — a browser-shaped request must also come from this
 * listener's own origin.
 *
 * The subtle part is what "browser-shaped" means. Browsers send `Sec-Fetch-Site`
 * on every request, but they omit `Origin` on a **same-origin GET**. A policy
 * that keys on `Origin` alone therefore refuses the page it exists to serve,
 * while a command-line client — which sends neither header — is let straight
 * through. The two rules below say what was meant: a cross-site request is
 * always refused, and an absent `Origin` means "same origin", which is exactly
 * how the Harness's own API fence (`isTrustedApiRequest`) reads it.
 *
 * @module dsh-mcp-server/config-trust
 */

/**
 * Build the trust function for the two settings routes.
 *
 * @param options.getConnection - returns the Harness `connection` service, or
 *   `undefined` when this Host has none. Called per request so a service that
 *   appears later is honoured.
 * @param options.logger - debug sink.
 * @returns `(req) => boolean`.
 */
export function createConfigTrust({ getConnection, logger = () => {} } = {}) {
  return function configTrust(req) {
    const headers = req?.headers ?? {}
    const origin = headers.origin
    const site = headers['sec-fetch-site']
    const browserRequest = typeof origin === 'string' || typeof site === 'string'
    if (!browserRequest) return true

    // No page may drive these routes from another site, whatever else it sends.
    if (site === 'cross-site') return false

    // A `same-site` page is another origin on this site — a different port of this
    // host, say. It is never this listener's own document, and a browser omits
    // `Origin` on some of its requests, so the absence of one cannot be read as
    // permission. Decide this before consulting `connection`: that service is only
    // sometimes resolvable, and it answers for its own browsers more permissively,
    // which made this case flip between boots.
    if (site === 'same-site' && typeof origin !== 'string') return false

    // The Harness knows its own browsers: a live owner Peer is a stronger answer
    // than anything this module can derive from headers.
    const connection = typeof getConnection === 'function' ? getConnection() : undefined
    if (connection !== undefined) {
      try {
        return connection.requestRejection({ headers }) === undefined
      } catch (error) {
        logger('debug', 'configuration admission failed', { error: error instanceof Error ? error.message : String(error) })
      }
    }

    const host = headers.host
    if (typeof host !== 'string' || host === '') return false
    // A browser omits `Origin` on its own same-origin GET; only a cross-site
    // request is required to carry one, and that case already returned above.
    // So fall back to the label the browser puts on every request: `same-origin`
    // is this listener's own document and `none` is a typed navigation, while
    // `same-site` is a *different* origin on the same site — the one case that
    // would otherwise slip through without an `Origin` to compare.
    if (typeof origin !== 'string') return site === 'same-origin' || site === 'none'
    try {
      return new URL(origin).host === host
    } catch {
      return false
    }
  }
}
