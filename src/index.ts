/**
 * @vafast/webhook - Webhook dispatch middleware for Vafast framework
 *
 * Automatically trigger webhooks based on route configuration.
 * Uses vafast RouteRegistry to query event configurations.
 */
import type { Middleware } from 'vafast'
import { getRoute } from 'vafast'
import * as crypto from 'crypto'

// ============================================
// Types
// ============================================

/**
 * Webhook configuration in route definition
 */
export interface WebhookConfig {
  /** Custom event key (default: auto-generated from path) */
  eventKey?: string
  /** Fields to include in payload (whitelist) */
  include?: string[]
  /** Fields to exclude from payload (blacklist) */
  exclude?: string[]
  /** Condition function to determine if webhook should trigger */
  condition?: (data: Record<string, unknown>) => boolean
  /** Custom transform function for payload */
  transform?: (data: Record<string, unknown>, req: Request) => Record<string, unknown>
}

/**
 * Webhook event configuration (resolved from route)
 */
export interface WebhookEventConfig {
  eventKey: string
  name: string
  description: string
  category: string
  method: string
  path: string
  config: WebhookConfig
}

/**
 * Webhook subscription document (from database)
 */
export interface WebhookSubscription {
  id: string
  appId: string
  eventKey: string
  endpointUrl: string
  secret?: string
  status: 'enabled' | 'disabled'
}

/**
 * Webhook log document
 */
export interface WebhookLog {
  appId: string
  webhookId: string
  eventKey: string
  endpointUrl: string
  payload: Record<string, unknown>
  status: 'success' | 'failed'
  statusCode: number | null
  error: string | null
  duration: number
  createdAt: Date
}

/**
 * Storage adapter interface
 */
export interface WebhookStorage {
  /** Find enabled subscriptions for an event */
  findSubscriptions(appId: string, eventKey: string): Promise<WebhookSubscription[]>
  /** Save webhook log */
  saveLog(log: WebhookLog): Promise<void>
}

/**
 * Logger interface
 */
export interface WebhookLogger {
  debug(message: string, meta?: Record<string, unknown>): void
  info(message: string, meta?: Record<string, unknown>): void
  warn(message: string, meta?: Record<string, unknown>): void
  error(message: string, meta?: Record<string, unknown>): void
}

/**
 * Webhook middleware configuration
 */
export interface WebhookMiddlewareConfig {
  /** Storage adapter for subscriptions and logs */
  storage: WebhookStorage
  /** Logger (optional, defaults to console) */
  logger?: WebhookLogger
  /** API path prefix to strip (e.g., '/restfulApi') */
  pathPrefix?: string
  /** Header name for app ID (default: 'app-id') */
  appIdHeader?: string
  /** Timeout for webhook requests in ms (default: 30000) */
  timeout?: number
  /** Fields to always exclude from payload */
  sensitiveFields?: string[]
  /** Success response code to check (default: 20001) */
  successCode?: number
}

// ============================================
// Default values
// ============================================

const DEFAULT_SENSITIVE_FIELDS = [
  'password',
  'token',
  'jwtToken',
  'refreshToken',
  'secret',
  'accessToken',
  'apiKey',
]

const DEFAULT_LOGGER: WebhookLogger = {
  debug: (msg, meta) => console.debug(`[Webhook] ${msg}`, meta || ''),
  info: (msg, meta) => console.info(`[Webhook] ${msg}`, meta || ''),
  warn: (msg, meta) => console.warn(`[Webhook] ${msg}`, meta || ''),
  error: (msg, meta) => console.error(`[Webhook] ${msg}`, meta || ''),
}

// ============================================
// Utility functions
// ============================================

/**
 * Get client IP from request
 */
function getClientIp(req: Request): string {
  return (
    req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    req.headers.get('x-real-ip') ||
    'unknown'
  )
}

/**
 * Generate HMAC-SHA256 signature
 */
function generateSignature(payload: string, secret: string): string {
  return crypto.createHmac('sha256', secret).update(payload).digest('hex')
}

/**
 * Generate event key from path
 */
function generateEventKey(path: string): string {
  const segments = path.split('/').filter(Boolean)
  if (segments.length === 0) return 'unknown'
  if (segments.length === 1) return segments[0]
  return `${segments[0]}.${segments.slice(1).join('.')}`
}

/**
 * Extract category from path
 */
function extractCategory(path: string): string {
  const segments = path.split('/').filter(Boolean)
  return segments[0] || 'unknown'
}

/**
 * Generate default name from path
 */
function generateName(path: string): string {
  const segments = path.split('/').filter(Boolean)
  return segments.join(' / ') || 'Unknown'
}

/**
 * Get webhook event config from route
 */
function getWebhookEventConfig(
  method: string,
  path: string
): WebhookEventConfig | undefined {
  const route = getRoute<{ webhook?: WebhookConfig }>(method, path)
  if (!route?.webhook) return undefined

  const webhookConfig = route.webhook
  const fullPath = route.fullPath

  return {
    eventKey: webhookConfig.eventKey || generateEventKey(fullPath),
    name: (route as { name?: string }).name || generateName(fullPath),
    description: (route as { description?: string }).description || '',
    category: extractCategory(fullPath),
    method: route.method,
    path: fullPath,
    config: webhookConfig,
  }
}

/**
 * Process payload fields
 */
function processFields(
  data: Record<string, unknown>,
  config: WebhookConfig,
  req: Request,
  sensitiveFields: string[]
): Record<string, unknown> {
  let result: Record<string, unknown> = { ...data }

  // 1. Always filter sensitive fields
  for (const field of sensitiveFields) {
    delete result[field]
  }

  // 2. Handle include (whitelist)
  if (config.include && config.include.length > 0) {
    const newResult: Record<string, unknown> = {}
    for (const field of config.include) {
      if (field in result) {
        newResult[field] = result[field]
      }
    }
    result = newResult
  }

  // 3. Handle exclude (blacklist)
  if (config.exclude && config.exclude.length > 0) {
    for (const field of config.exclude) {
      delete result[field]
    }
  }

  // 4. Custom transform
  if (config.transform) {
    result = config.transform(result, req)
  }

  // 5. Add common fields
  return {
    ...result,
    clientIp: getClientIp(req),
    userAgent: req.headers.get('user-agent') || 'unknown',
    timestamp: new Date().toISOString(),
  }
}

/**
 * Check trigger condition
 */
function checkCondition(
  data: Record<string, unknown>,
  config: WebhookConfig
): boolean {
  if (config.condition) {
    return config.condition(data)
  }
  return true
}

// ============================================
// Core functions
// ============================================

/**
 * Send webhook and log result
 */
async function sendWebhook(
  subscription: WebhookSubscription,
  appId: string,
  eventKey: string,
  data: Record<string, unknown>,
  storage: WebhookStorage,
  logger: WebhookLogger,
  timeout: number
): Promise<void> {
  const startTime = Date.now()
  const payload = {
    appId,
    eventType: eventKey.split('.')[0],
    eventKey,
    timestamp: new Date().toISOString(),
    data,
  }

  const bodyString = JSON.stringify(payload)
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'X-Webhook-Event': eventKey,
    'X-Webhook-Timestamp': payload.timestamp,
  }

  // Add signature if secret is configured
  if (subscription.secret) {
    headers['X-Webhook-Signature'] = generateSignature(bodyString, subscription.secret)
  }

  let status: 'success' | 'failed' = 'success'
  let statusCode: number | null = null
  let errorMsg: string | null = null

  try {
    const response = await fetch(subscription.endpointUrl, {
      method: 'POST',
      headers,
      body: bodyString,
      signal: AbortSignal.timeout(timeout),
    })

    statusCode = response.status
    if (!response.ok) {
      status = 'failed'
      errorMsg = `HTTP ${response.status}`
    }
  } catch (err) {
    status = 'failed'
    errorMsg = err instanceof Error ? err.message : String(err)
  }

  const duration = Date.now() - startTime

  // Log result
  try {
    await storage.saveLog({
      appId,
      webhookId: subscription.id,
      eventKey,
      endpointUrl: subscription.endpointUrl,
      payload,
      status,
      statusCode,
      error: errorMsg,
      duration,
      createdAt: new Date(),
    })
  } catch (logErr) {
    logger.error('Failed to save webhook log', { error: logErr })
  }

  if (status === 'failed') {
    logger.warn('Webhook delivery failed', {
      eventKey,
      endpointUrl: subscription.endpointUrl,
      error: errorMsg,
      duration,
    })
  } else {
    logger.debug('Webhook delivered successfully', {
      eventKey,
      endpointUrl: subscription.endpointUrl,
      statusCode,
      duration,
    })
  }
}

/**
 * Dispatch webhook event to all subscribers
 */
async function dispatchEvent(
  appId: string,
  eventKey: string,
  data: Record<string, unknown>,
  storage: WebhookStorage,
  logger: WebhookLogger,
  timeout: number
): Promise<void> {
  try {
    const subscriptions = await storage.findSubscriptions(appId, eventKey)

    if (subscriptions.length === 0) return

    logger.info('Dispatching webhook event', {
      appId,
      eventKey,
      count: subscriptions.length,
    })

    // Send to all subscribers in parallel
    await Promise.all(
      subscriptions.map((sub) =>
        sendWebhook(sub, appId, eventKey, data, storage, logger, timeout)
      )
    )
  } catch (err) {
    logger.error('Webhook dispatch failed', { error: err })
  }
}

// ============================================
// Middleware
// ============================================

/**
 * Create webhook dispatch middleware
 *
 * @example
 * ```typescript
 * import { webhook } from '@vafast/webhook'
 *
 * const webhookMiddleware = webhook({
 *   storage: myStorageAdapter,
 *   pathPrefix: '/restfulApi',
 * })
 *
 * server.use(webhookMiddleware)
 * ```
 */
export function webhook(config: WebhookMiddlewareConfig): Middleware {
  const {
    storage,
    logger = DEFAULT_LOGGER,
    pathPrefix = '',
    appIdHeader = 'app-id',
    timeout = 30000,
    sensitiveFields = DEFAULT_SENSITIVE_FIELDS,
    successCode = 20001,
  } = config

  return async (req: Request, next: () => Promise<Response>) => {
    const response = await next()

    // Only process successful JSON responses
    if (!response.ok) return response

    const contentType = response.headers.get('content-type')
    if (!contentType?.includes('application/json')) return response

    const appId = req.headers.get(appIdHeader)
    if (!appId) return response

    // Get request path (strip prefix)
    const url = new URL(req.url)
    const pathname = pathPrefix
      ? url.pathname.replace(new RegExp(`^${pathPrefix}`), '')
      : url.pathname

    // Get event config from route registry
    const eventConfig = getWebhookEventConfig(req.method, pathname)
    if (!eventConfig) return response

    try {
      // Clone response to read body
      const clonedResponse = response.clone()
      const responseData = (await clonedResponse.json()) as {
        success?: boolean
        code?: number
        data?: Record<string, unknown>
      }

      // Only process business-successful responses
      if (!responseData.success || responseData.code !== successCode) return response

      const rawData = responseData.data || {}

      // Check trigger condition
      if (!checkCondition(rawData, eventConfig.config)) return response

      // Process payload
      const payload = processFields(rawData, eventConfig.config, req, sensitiveFields)

      // Dispatch asynchronously (don't block response)
      setImmediate(() => {
        dispatchEvent(appId, eventConfig.eventKey, payload, storage, logger, timeout).catch(
          (err) => {
            logger.error('Async dispatch failed', { error: err })
          }
        )
      })
    } catch {
      // Parse error doesn't affect response
    }

    return response
  }
}

/**
 * Manually dispatch webhook (for redirect scenarios like OAuth)
 *
 * @example
 * ```typescript
 * import { dispatchWebhook } from '@vafast/webhook'
 *
 * // In OAuth callback handler
 * dispatchWebhook(storage, logger, {
 *   appId,
 *   eventKey: 'auth.oauth',
 *   data: { userId, provider },
 *   req,
 * })
 * ```
 */
export function dispatchWebhook(
  storage: WebhookStorage,
  logger: WebhookLogger,
  options: {
    appId: string
    eventKey: string
    data: Record<string, unknown>
    req: Request
    timeout?: number
  }
): void {
  const { appId, eventKey, data, req, timeout = 30000 } = options

  const payload = {
    ...data,
    clientIp: getClientIp(req),
    userAgent: req.headers.get('user-agent') || 'unknown',
    timestamp: new Date().toISOString(),
  }

  setImmediate(() => {
    dispatchEvent(appId, eventKey, payload, storage, logger, timeout).catch((err) => {
      logger.error('Manual dispatch failed', { error: err })
    })
  })
}

// ============================================
// Exports
// ============================================

export default webhook

// Re-export utility functions
export {
  getWebhookEventConfig,
  generateEventKey,
  extractCategory,
  generateName,
  generateSignature,
  getClientIp,
  DEFAULT_SENSITIVE_FIELDS,
}

