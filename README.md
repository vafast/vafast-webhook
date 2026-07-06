# @vafast/webhook

Webhook dispatch middleware for [Vafast](https://github.com/vafastjs/vafast) framework.

Automatically trigger webhooks based on route configuration. Zero boilerplate - just add `webhook` field to your routes!

## Features

- 🚀 **Declarative** - Configure webhooks directly in route definitions
- ⚡ **Async** - Non-blocking, dispatches after response is sent
- 🔒 **Secure** - HMAC-SHA256 signature support
- 🎯 **Flexible** - Include/exclude fields, custom transforms, conditions
- 📝 **Logged** - Full delivery tracking with customizable storage
- 🔄 **Retry** - Automatic retry with exponential backoff on failure
- 🚦 **Concurrency** - Control parallel webhook requests
- 🆔 **Event ID** - Unique event IDs for idempotency support

## Installation

```bash
npm install @vafast/webhook
# or
npm install @vafast/webhook
```

## Quick Start

### Option 1: Simple Config (No Database)

```typescript
import { Server } from 'vafast'
import { webhook, defineWebhooks } from '@vafast/webhook'

// Define webhooks in code
const storage = defineWebhooks([
  { eventKey: 'auth.signIn', url: 'https://api.example.com/webhook' },
  { eventKey: 'auth.signUp', url: 'https://api.example.com/webhook' },
  { eventKey: 'users.*', url: 'https://crm.example.com/hook', secret: 'my-secret' }, // Wildcard
])

// Dynamic add (optional)
storage.add({ eventKey: 'order.created', url: 'https://...' })

// Check logs (for testing)
console.log(storage.logs)

const server = new Server(routes)
server.use(webhook({ storage }))
```

### Option 2: Custom Storage (Database/Redis/etc.)

```typescript
import type { WebhookStorage } from '@vafast/webhook'

const storage: WebhookStorage = {
  async findSubscriptions(appId, eventKey) {
    // Use any data source: MySQL, Redis, API, etc.
    return db.query('SELECT * FROM webhooks WHERE event_key = ? AND status = "enabled"', [eventKey])
  },
  async saveLog(log) {
    await db.insert('webhook_logs', log)
  },
}

server.use(webhook({ 
  storage,
  getAppId: (req) => req.headers.get('app-id'), // Optional: for multi-tenant
}))
```

### 3. Configure routes

```typescript
const routes = [
  {
    method: 'POST',
    path: '/auth/signIn',
    handler: signInHandler,
    name: '用户登录',
    description: '用户登录接口',
    // Enable webhook with field filtering
    webhook: {
      exclude: ['jwtToken', 'refreshToken'],
    },
  },
  {
    method: 'POST',
    path: '/users/create',
    handler: createUserHandler,
    name: '创建用户',
    // Only include specific fields
    webhook: {
      include: ['userId', 'email', 'createdAt'],
    },
  },
]
```

## Configuration

### Middleware Options

```typescript
webhook({
  // Required: Storage adapter for subscriptions and logs
  storage: WebhookStorage,

  // Optional: Logger (default: console)
  logger: WebhookLogger,

  // Optional: API path prefix to strip when generating eventKey
  // e.g., '/restfulApi' → '/restfulApi/auth/signIn' becomes 'auth.signIn'
  pathPrefix: '/restfulApi',

  // Optional: Custom function to extract app ID from request
  // Default: (req) => req.headers.get('app-id')
  getAppId: (req) => {
    // From header
    return req.headers.get('x-app-id')
    // Or from JWT
    // return decodeJwt(req.headers.get('authorization')).appId
    // Or fixed value (single-tenant)
    // return 'my-app'
  },

  // Optional: Custom function to check if response is successful
  // Default: isWebhookResponseSuccess — supports both wrapped ({ success, code: 20001 })
  // and direct business-object responses (e.g. { id, title, ... })
  isSuccess: (data) => data.code === 200,

  // Optional: Custom function to extract payload data from response
  // Default: getWebhookResponseData — uses data.data for wrapped responses,
  // or the whole object for direct business-object responses
  getData: (data) => data.result || {},

  // Optional: Timeout for webhook requests in ms (default: 30000)
  timeout: 30000,

  // Optional: Fields to always exclude (default: password, token, etc.)
  sensitiveFields: ['password', 'token', 'secret'],

  // Optional: Retry configuration for failed webhooks
  retry: {
    count: 3,      // Number of retry attempts (default: 0)
    delay: 1000,   // Initial delay in ms (default: 1000)
    backoff: 2,    // Exponential backoff multiplier (default: 2)
    maxDelay: 30000, // Max delay in ms (default: 30000)
  },

  // Optional: Max concurrent webhook requests (default: 10)
  concurrency: 10,
})
```

### Route Webhook Options

```typescript
{
  webhook: {
    // Custom event key (default: auto-generated from path)
    // e.g., '/auth/signIn' -> 'auth.signIn'
    eventKey: 'user.login',

    // Fields to include in payload (whitelist)
    include: ['userId', 'email'],

    // Fields to exclude from payload (blacklist)
    exclude: ['password', 'token'],

    // Condition function - only trigger if returns true
    condition: (data) => data.role === 'admin',

    // Custom transform function
    transform: (data, req) => ({
      ...data,
      source: 'web',
    }),
  }
}
```

## Webhook Payload

```json
{
  "eventId": "evt_m4xr7z_1a2b3c4d5e6f7890",
  "appId": "app_123",
  "eventType": "auth",
  "eventKey": "auth.signIn",
  "timestamp": "2024-01-07T12:00:00.000Z",
  "data": {
    "userId": "user_456",
    "email": "user@example.com",
    "clientIp": "192.168.1.1",
    "userAgent": "Mozilla/5.0...",
    "timestamp": "2024-01-07T12:00:00.000Z"
  }
}
```

> **Event ID** (`eventId`): Each webhook delivery has a unique event ID. Use this for idempotency - if your endpoint receives the same `eventId` twice, you can safely skip processing.

## Webhook Headers

| Header | Description |
|--------|-------------|
| `Content-Type` | `application/json` |
| `X-Webhook-Event` | Event key (e.g., `auth.signIn`) |
| `X-Webhook-Event-Id` | Unique event ID for idempotency (e.g., `evt_m4xr7z_1a2b3c4d5e6f7890`) |
| `X-Webhook-Timestamp` | ISO timestamp |
| `X-Webhook-Signature` | HMAC-SHA256 signature (if secret configured) |

## Manual Dispatch

For redirect scenarios (e.g., OAuth callbacks), use `dispatchWebhook`:

```typescript
import { dispatchWebhook } from '@vafast/webhook'

// In OAuth callback handler
const oauthCallback = async (req) => {
  const { userId, email, provider } = await verifyOAuth(req)

  // Manually trigger webhook (redirect responses can't be auto-processed)
  dispatchWebhook(storage, logger, {
    appId,
    eventKey: 'auth.oauth',
    data: { userId, email, provider },
    req,
  })

  // Return redirect response
  return Response.redirect(`${frontendUrl}?token=${token}`)
}
```

## Query Events API

Query available webhook events from route configurations:

```typescript
import {
  getAllWebhookEvents,
  getWebhookCategories,
  getWebhookEventsByCategory,
} from '@vafast/webhook'

// Get all events (pass pathPrefix if your routes use a prefix)
const events = getAllWebhookEvents('/restfulApi')
// Returns:
// [
//   { eventKey: 'auth.signIn', name: '用户登录', category: 'auth', method: 'POST', path: '/restfulApi/auth/signIn' },
//   { eventKey: 'users.update', name: '更新用户', category: 'users', method: 'PUT', path: '/restfulApi/users/update' },
// ]

// Get all categories
const categories = getWebhookCategories('/restfulApi')
// Returns: ['auth', 'users']

// Get events by category
const authEvents = getWebhookEventsByCategory('auth', '/restfulApi')
// Returns only events with category === 'auth'
```

**Use case:** Build an admin UI for webhook configuration by exposing these as API endpoints:

```typescript
const routes = [
  {
    method: 'GET',
    path: '/webhooks/events',
    handler: () => success(getAllWebhookEvents('/restfulApi')),
  },
  {
    method: 'GET',
    path: '/webhooks/categories',
    handler: () => success(getWebhookCategories('/restfulApi')),
  },
  {
    method: 'GET',
    path: '/webhooks/events/:category',
    handler: ({ params }) => success(getWebhookEventsByCategory(params.category, '/restfulApi')),
  },
]
```

## HTTP Storage & Dispatcher (Microservices)

When webhook subscriptions and delivery live in a dedicated **webhook-server**, use `createHttpStorage` and `createHttpDispatcher`:

```typescript
import {
  webhook,
  createHttpStorage,
  createHttpDispatcher,
} from '@vafast/webhook'

const storage = createHttpStorage({
  baseUrl: 'http://localhost:9006',
  sourceService: 'ones',       // auth | ones | billing | ai
  apiKeyId: process.env.API_KEY_ID!,
  apiKeySecret: process.env.API_KEY_SECRET!,
})

const dispatcher = createHttpDispatcher({
  baseUrl: 'http://localhost:9006',
  apiKeyId: process.env.API_KEY_ID!,
  apiKeySecret: process.env.API_KEY_SECRET!,
  timeout: 10000,
})

server.use(webhook({
  storage,
  dispatcher,
  pathPrefix: '/restfulApi',
  sourceService: 'ones',
  getAppId: (req) => req.headers.get('app-id') || undefined,
  // isSuccess / getData use library defaults — no need to pass explicitly
}))
```

**`createHttpStorage`** calls webhook-server internal APIs:
- `POST /internal/findSubscriptions` — query enabled subscriptions by `appId` + `eventKey`
- `POST /internal/saveLog` — persist delivery logs

**`createHttpDispatcher`** calls:
- `POST /internal/dispatchEvent` — deliver to configured targets (HTTP / IM bots / email, per subscription)

`serializeDispatchSubscription()` forwards all non-null subscription fields to webhook-server; the library does not enumerate business delivery types.

### Response helpers (v0.1.3+)

| Export | Purpose |
|--------|---------|
| `isWebhookResponseSuccess` | Default `isSuccess` — wrapped `{ success, code: 20001 }` **or** direct handler payload |
| `getWebhookResponseData` | Default `getData` — `data.data` when wrapped, otherwise the full response object |

Override only when your API uses a non-standard envelope.

## Storage Adapters

### MongoDB Example

```typescript
import { Collection } from 'mongodb'

const createMongoStorage = (
  webhooks: Collection,
  logs: Collection
): WebhookStorage => ({
  async findSubscriptions(appId, eventKey) {
    const docs = await webhooks.find({ appId, eventKey, status: 'enabled' }).toArray()
    return docs.map((doc) => ({
      id: doc._id.toString(),
      appId: doc.appId,
      eventKey: doc.eventKey,
      endpointUrl: doc.endpointUrl,
      secret: doc.webhookSecret,
      status: doc.status,
    }))
  },
  async saveLog(log) {
    await logs.insertOne({
      ...log,
      createAt: new Date(),
      updateAt: new Date(),
    })
  },
})
```

### In-Memory Example (for testing)

```typescript
const createMemoryStorage = (): WebhookStorage => {
  const subscriptions: WebhookSubscription[] = []
  const logs: WebhookLog[] = []

  return {
    async findSubscriptions(appId, eventKey) {
      return subscriptions.filter(
        (s) => s.appId === appId && s.eventKey === eventKey && s.status === 'enabled'
      )
    },
    async saveLog(log) {
      logs.push(log)
    },
  }
}
```

## Retry & Concurrency

### Retry with Exponential Backoff

Failed webhooks can be automatically retried:

```typescript
server.use(webhook({
  storage,
  retry: {
    count: 3,        // Try up to 3 more times after initial failure
    delay: 1000,     // Start with 1 second delay
    backoff: 2,      // Double delay each retry: 1s → 2s → 4s
    maxDelay: 30000, // Cap at 30 seconds
  },
}))
```

**Retry timeline example:**
- Attempt 1: Immediate (fails)
- Attempt 2: Wait 1s, retry (fails)
- Attempt 3: Wait 2s, retry (fails)
- Attempt 4: Wait 4s, retry (succeeds or gives up)

### Concurrency Control

Control how many webhooks are sent in parallel:

```typescript
server.use(webhook({
  storage,
  concurrency: 5,  // Max 5 concurrent requests (default: 10)
}))
```

**Use cases:**
- Prevent overwhelming external services
- Respect rate limits on third-party APIs
- Reduce memory usage during high traffic

## Processing Flow

```
Request → Handler → Response
                       ↓
               webhookMiddleware
                       ↓
          getWebhookEventConfig() ← Query vafast RouteRegistry
                       ↓
              checkCondition() → Skip if false
                       ↓
              processFields() → Filter sensitive/specified fields
                       ↓
           setImmediate() → Async dispatch (non-blocking)
                       ↓
           dispatchEvent() → Semaphore(concurrency) → Send with retry
```

## Changelog

### v0.1.7

- `createHttpDispatcher`: pass through subscription fields via `serializeDispatchSubscription()` (e.g. `notifyEmails` for email delivery on webhook-server)
- Fix `WebhookDispatchSubscription` assignability with `WebhookSubscription` (no index signature on dispatch types)

## License

MIT

