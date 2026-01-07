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
  appId?: string  // Optional for single-tenant apps
  eventKey: string
  endpointUrl: string
  secret?: string
  status: 'enabled' | 'disabled'
}

/**
 * Webhook log document
 */
export interface WebhookLog {
  appId?: string  // Optional for single-tenant apps
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
  /** 
   * Find enabled subscriptions for an event
   * @param appId - App ID (may be undefined for single-tenant apps)
   * @param eventKey - Event key (e.g., 'auth.signIn')
   */
  findSubscriptions(appId: string | undefined, eventKey: string): Promise<WebhookSubscription[]>
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
 * Response data structure (for isSuccess check)
 */
export interface ResponseData {
  success?: boolean
  code?: number
  data?: Record<string, unknown>
  [key: string]: unknown
}

/**
 * Retry configuration
 */
export interface RetryConfig {
  /** Number of retry attempts (default: 0, no retry) */
  count?: number
  /** Delay between retries in ms (default: 1000) */
  delay?: number
  /** Exponential backoff multiplier (default: 2) */
  backoff?: number
  /** Max delay in ms (default: 30000) */
  maxDelay?: number
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
  /** 
   * Function to extract app ID from request (for multi-tenant apps)
   * Return undefined/null for single-tenant apps
   * @default undefined (single-tenant mode, no appId required)
   */
  getAppId?: (req: Request) => string | null | undefined
  /** 
   * Function to check if response is successful (should trigger webhook)
   * @default (data) => data.success === true && data.code === 20001
   */
  isSuccess?: (data: ResponseData) => boolean
  /**
   * Function to extract payload data from response
   * @default (data) => data.data || {}
   */
  getData?: (data: ResponseData) => Record<string, unknown>
  /** Timeout for webhook requests in ms (default: 30000) */
  timeout?: number
  /** Fields to always exclude from payload */
  sensitiveFields?: string[]
  /** Retry configuration for failed webhooks */
  retry?: RetryConfig
  /** Max concurrent webhook requests (default: 10) */
  concurrency?: number
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
 * Sleep utility
 */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

/**
 * Semaphore for concurrency control
 */
class Semaphore {
  private permits: number
  private waiting: (() => void)[] = []

  constructor(permits: number) {
    this.permits = permits
  }

  async acquire(): Promise<void> {
    if (this.permits > 0) {
      this.permits--
      return
    }
    await new Promise<void>((resolve) => this.waiting.push(resolve))
  }

  release(): void {
    const next = this.waiting.shift()
    if (next) {
      next()
    } else {
      this.permits++
    }
  }
}

/**
 * Send a single HTTP request to webhook endpoint
 */
async function sendRequest(
  url: string,
  bodyString: string,
  headers: Record<string, string>,
  timeout: number
): Promise<{ ok: boolean; statusCode: number | null; error: string | null }> {
  try {
    const response = await fetch(url, {
      method: 'POST',
      headers,
      body: bodyString,
      signal: AbortSignal.timeout(timeout),
    })
    return {
      ok: response.ok,
      statusCode: response.status,
      error: response.ok ? null : `HTTP ${response.status}`,
    }
  } catch (err) {
    return {
      ok: false,
      statusCode: null,
      error: err instanceof Error ? err.message : String(err),
    }
  }
}

/**
 * Send webhook with retry support
 */
async function sendWebhook(
  subscription: WebhookSubscription,
  appId: string | undefined,
  eventKey: string,
  data: Record<string, unknown>,
  storage: WebhookStorage,
  logger: WebhookLogger,
  timeout: number,
  retry?: RetryConfig
): Promise<void> {
  const startTime = Date.now()
  const timestamp = new Date().toISOString()
  const payload: Record<string, unknown> = {
    eventType: eventKey.split('.')[0],
    eventKey,
    timestamp,
    data,
  }
  if (appId) payload.appId = appId

  const bodyString = JSON.stringify(payload)
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'X-Webhook-Event': eventKey,
    'X-Webhook-Timestamp': timestamp,
  }

  if (subscription.secret) {
    headers['X-Webhook-Signature'] = generateSignature(bodyString, subscription.secret)
  }

  // Retry config
  const maxAttempts = (retry?.count ?? 0) + 1
  const baseDelay = retry?.delay ?? 1000
  const backoff = retry?.backoff ?? 2
  const maxDelay = retry?.maxDelay ?? 30000

  let status: 'success' | 'failed' = 'failed'
  let statusCode: number | null = null
  let errorMsg: string | null = null
  let attempts = 0

  // Try with retries
  for (let i = 0; i < maxAttempts; i++) {
    attempts = i + 1
    const result = await sendRequest(subscription.endpointUrl, bodyString, headers, timeout)

    if (result.ok) {
      status = 'success'
      statusCode = result.statusCode
      errorMsg = null
      break
    }

    statusCode = result.statusCode
    errorMsg = result.error

    // Don't wait after last attempt
    if (i < maxAttempts - 1) {
      const delay = Math.min(baseDelay * Math.pow(backoff, i), maxDelay)
      logger.debug('Webhook failed, retrying...', {
        attempt: attempts,
        maxAttempts,
        delay,
        error: errorMsg,
      })
      await sleep(delay)
    }
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
      attempts,
      duration,
    })
  } else {
    logger.debug('Webhook delivered successfully', {
      eventKey,
      endpointUrl: subscription.endpointUrl,
      statusCode,
      attempts,
      duration,
    })
  }
}

/**
 * Dispatch options
 */
interface DispatchOptions {
  storage: WebhookStorage
  logger: WebhookLogger
  timeout: number
  retry?: RetryConfig
  concurrency?: number
}

/**
 * Dispatch webhook event to all subscribers with concurrency control
 */
async function dispatchEvent(
  appId: string | undefined,
  eventKey: string,
  data: Record<string, unknown>,
  options: DispatchOptions
): Promise<void> {
  const { storage, logger, timeout, retry, concurrency = 10 } = options

  try {
    const subscriptions = await storage.findSubscriptions(appId, eventKey)

    if (subscriptions.length === 0) return

    logger.info('Dispatching webhook event', {
      appId,
      eventKey,
      count: subscriptions.length,
    })

    // Use semaphore for concurrency control
    const semaphore = new Semaphore(concurrency)
    
    await Promise.all(
      subscriptions.map(async (sub) => {
        await semaphore.acquire()
        try {
          await sendWebhook(sub, appId, eventKey, data, storage, logger, timeout, retry)
        } finally {
          semaphore.release()
        }
      })
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
    timeout = 30000,
    sensitiveFields = DEFAULT_SENSITIVE_FIELDS,
    retry,
    concurrency = 10,
    // Flexible options
    getAppId = config.getAppId, // undefined = single-tenant mode (no appId)
    isSuccess = config.isSuccess ?? ((data: ResponseData) => data.success === true && data.code === 20001),
    getData = (data: ResponseData) => (data.data || {}) as Record<string, unknown>,
  } = config

  // Pre-create dispatch options
  const dispatchOptions: DispatchOptions = { storage, logger, timeout, retry, concurrency }

  return async (req: Request, next: () => Promise<Response>) => {
    const response = await next()

    // Only process successful JSON responses
    if (!response.ok) return response

    const contentType = response.headers.get('content-type')
    if (!contentType?.includes('application/json')) return response

    // Get app ID (undefined for single-tenant apps)
    const appId = getAppId ? getAppId(req) ?? undefined : undefined

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
      const responseData = (await clonedResponse.json()) as ResponseData

      // Check if response is successful using custom function
      if (!isSuccess(responseData)) return response

      // Extract payload data using custom function
      const rawData = getData(responseData)

      // Check trigger condition
      if (!checkCondition(rawData, eventConfig.config)) return response

      // Process payload
      const payload = processFields(rawData, eventConfig.config, req, sensitiveFields)

      // Dispatch asynchronously (don't block response)
      setImmediate(() => {
        dispatchEvent(appId, eventConfig.eventKey, payload, dispatchOptions).catch((err) => {
          logger.error('Async dispatch failed', { error: err })
        })
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
    appId?: string  // Optional for single-tenant apps
    eventKey: string
    data: Record<string, unknown>
    req: Request
    timeout?: number
    retry?: RetryConfig
    concurrency?: number
  }
): void {
  const { appId, eventKey, data, req, timeout = 30000, retry, concurrency = 10 } = options

  const payload = {
    ...data,
    clientIp: getClientIp(req),
    userAgent: req.headers.get('user-agent') || 'unknown',
    timestamp: new Date().toISOString(),
  }

  const dispatchOptions: DispatchOptions = { storage, logger, timeout, retry, concurrency }

  setImmediate(() => {
    dispatchEvent(appId, eventKey, payload, dispatchOptions).catch((err) => {
      logger.error('Manual dispatch failed', { error: err })
    })
  })
}

// ============================================
// Simple Storage Adapter
// ============================================

/**
 * Webhook configuration item
 */
export interface WebhookConfigItem {
  /** Event key pattern (e.g., 'auth.signIn' or 'auth.*' for wildcard) */
  eventKey: string
  /** Webhook endpoint URL */
  url: string
  /** Any custom fields (secret, appId, name, headers, etc.) */
  [key: string]: unknown
}

/**
 * Extended storage with direct access to data
 */
export interface SimpleStorage extends WebhookStorage {
  /** Direct access to subscriptions array */
  subscriptions: WebhookSubscription[]
  /** Direct access to logs array */
  logs: WebhookLog[]
  /** Add a subscription dynamically */
  add: (config: WebhookConfigItem) => string
  /** Clear all logs */
  clearLogs: () => void
}

/**
 * Define webhooks with a simple configuration (no database needed)
 * 
 * @example
 * ```typescript
 * const storage = defineWebhooks([
 *   { eventKey: 'auth.signIn', url: 'https://api.example.com/webhook' },
 *   { eventKey: 'users.*', url: 'https://crm.example.com/hook', secret: 'xxx' },
 * ])
 * 
 * // Dynamic add
 * storage.add({ eventKey: 'order.created', url: 'https://...' })
 * 
 * // Check logs (for testing)
 * console.log(storage.logs)
 * 
 * server.use(webhook({ storage }))
 * ```
 */
export function defineWebhooks(initialConfigs: WebhookConfigItem[] = []): SimpleStorage {
  let idCounter = 0
  
  const subscriptions: WebhookSubscription[] = initialConfigs.map((c) => {
    const { eventKey, url, ...rest } = c
    return {
      ...rest, // Preserve custom fields
      id: `ws_${++idCounter}`,
      eventKey,
      endpointUrl: url,
      status: 'enabled' as const,
    }
  })
  
  const logs: WebhookLog[] = []

  return {
    subscriptions,
    logs,
    
    add(config) {
      const { eventKey, url, ...rest } = config
      const id = `ws_${++idCounter}`
      subscriptions.push({
        ...rest, // Preserve custom fields
        id,
        eventKey,
        endpointUrl: url,
        status: 'enabled',
      })
      return id
    },
    
    clearLogs() {
      logs.length = 0
    },

    async findSubscriptions(appId, eventKey) {
      return subscriptions.filter((s) => {
        if (s.status !== 'enabled') return false
        // Match event key (support wildcard)
        const matches = s.eventKey === eventKey || 
          (s.eventKey.endsWith('.*') && eventKey.startsWith(s.eventKey.slice(0, -2) + '.'))
        if (!matches) return false
        // Match appId (if specified)
        if (appId !== undefined && s.appId !== undefined && s.appId !== appId) return false
        return true
      })
    },
    
    async saveLog(log) {
      logs.push(log)
    },
  }
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

