import { Middleware } from 'vafast';

/**
 * @vafast/webhook - Webhook dispatch middleware for Vafast framework
 *
 * Automatically trigger webhooks based on route configuration.
 * Uses vafast RouteRegistry to query event configurations.
 */

/**
 * Webhook configuration in route definition
 */
interface WebhookConfig {
    /** Custom event key (default: auto-generated from path) */
    eventKey?: string;
    /** Fields to include in payload (whitelist) */
    include?: string[];
    /** Fields to exclude from payload (blacklist) */
    exclude?: string[];
    /** Condition function to determine if webhook should trigger */
    condition?: (data: Record<string, unknown>) => boolean;
    /** Custom transform function for payload */
    transform?: (data: Record<string, unknown>, req: Request) => Record<string, unknown>;
}
/**
 * Webhook event configuration (resolved from route)
 */
interface WebhookEventConfig {
    eventKey: string;
    name: string;
    description: string;
    category: string;
    method: string;
    path: string;
    config: WebhookConfig;
}
/**
 * Webhook subscription document (from database)
 */
interface WebhookSubscription {
    id: string;
    appId: string;
    eventKey: string;
    endpointUrl: string;
    secret?: string;
    status: 'enabled' | 'disabled';
}
/**
 * Webhook log document
 */
interface WebhookLog {
    appId: string;
    webhookId: string;
    eventKey: string;
    endpointUrl: string;
    payload: Record<string, unknown>;
    status: 'success' | 'failed';
    statusCode: number | null;
    error: string | null;
    duration: number;
    createdAt: Date;
}
/**
 * Storage adapter interface
 */
interface WebhookStorage {
    /** Find enabled subscriptions for an event */
    findSubscriptions(appId: string, eventKey: string): Promise<WebhookSubscription[]>;
    /** Save webhook log */
    saveLog(log: WebhookLog): Promise<void>;
}
/**
 * Logger interface
 */
interface WebhookLogger {
    debug(message: string, meta?: Record<string, unknown>): void;
    info(message: string, meta?: Record<string, unknown>): void;
    warn(message: string, meta?: Record<string, unknown>): void;
    error(message: string, meta?: Record<string, unknown>): void;
}
/**
 * Webhook middleware configuration
 */
interface WebhookMiddlewareConfig {
    /** Storage adapter for subscriptions and logs */
    storage: WebhookStorage;
    /** Logger (optional, defaults to console) */
    logger?: WebhookLogger;
    /** API path prefix to strip (e.g., '/restfulApi') */
    pathPrefix?: string;
    /** Header name for app ID (default: 'app-id') */
    appIdHeader?: string;
    /** Timeout for webhook requests in ms (default: 30000) */
    timeout?: number;
    /** Fields to always exclude from payload */
    sensitiveFields?: string[];
    /** Success response code to check (default: 20001) */
    successCode?: number;
}
declare const DEFAULT_SENSITIVE_FIELDS: string[];
/**
 * Get client IP from request
 */
declare function getClientIp(req: Request): string;
/**
 * Generate HMAC-SHA256 signature
 */
declare function generateSignature(payload: string, secret: string): string;
/**
 * Generate event key from path
 */
declare function generateEventKey(path: string): string;
/**
 * Extract category from path
 */
declare function extractCategory(path: string): string;
/**
 * Generate default name from path
 */
declare function generateName(path: string): string;
/**
 * Get webhook event config from route
 */
declare function getWebhookEventConfig(method: string, path: string): WebhookEventConfig | undefined;
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
declare function webhook(config: WebhookMiddlewareConfig): Middleware;
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
declare function dispatchWebhook(storage: WebhookStorage, logger: WebhookLogger, options: {
    appId: string;
    eventKey: string;
    data: Record<string, unknown>;
    req: Request;
    timeout?: number;
}): void;

export { DEFAULT_SENSITIVE_FIELDS, type WebhookConfig, type WebhookEventConfig, type WebhookLog, type WebhookLogger, type WebhookMiddlewareConfig, type WebhookStorage, type WebhookSubscription, webhook as default, dispatchWebhook, extractCategory, generateEventKey, generateName, generateSignature, getClientIp, getWebhookEventConfig, webhook };
