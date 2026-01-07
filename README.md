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

## Installation

```bash
npm install @vafast/webhook
# or
bun add @vafast/webhook
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

  // Optional: API path prefix to strip (default: '')
  pathPrefix: '/api',

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
  // Default: (data) => data.success === true && data.code === 20001
  isSuccess: (data) => {
    // Standard REST API
    return data.code === 200
    // Or simple check
    // return data.ok === true
  },

  // Optional: Custom function to extract payload data from response
  // Default: (data) => data.data || {}
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

## Webhook Headers

| Header | Description |
|--------|-------------|
| `Content-Type` | `application/json` |
| `X-Webhook-Event` | Event key (e.g., `auth.signIn`) |
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

## License

MIT

