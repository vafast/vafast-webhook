# @vafast/webhook

Webhook dispatch middleware for [Vafast](https://github.com/vafastjs/vafast) framework.

Automatically trigger webhooks based on route configuration. Zero boilerplate - just add `webhook` field to your routes!

## Features

- 🚀 **Declarative** - Configure webhooks directly in route definitions
- ⚡ **Async** - Non-blocking, dispatches after response is sent
- 🔒 **Secure** - HMAC-SHA256 signature support
- 🎯 **Flexible** - Include/exclude fields, custom transforms, conditions
- 📝 **Logged** - Full delivery tracking with customizable storage

## Installation

```bash
npm install @vafast/webhook
# or
bun add @vafast/webhook
```

## Quick Start

### 1. Create a storage adapter

```typescript
import type { WebhookStorage, WebhookSubscription, WebhookLog } from '@vafast/webhook'

const storage: WebhookStorage = {
  async findSubscriptions(appId, eventKey) {
    // Query your database
    return db.collection('webhooks').find({ appId, eventKey, status: 'enabled' }).toArray()
  },
  async saveLog(log) {
    // Save to your database
    await db.collection('webhookLogs').insertOne(log)
  },
}
```

### 2. Add middleware to server

```typescript
import { Server } from 'vafast'
import { webhook } from '@vafast/webhook'

const server = new Server(routes)

server.use(
  webhook({
    storage,
    pathPrefix: '/api', // Strip API prefix from paths
  })
)
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

  // Optional: Header name for app ID (default: 'app-id')
  appIdHeader: 'app-id',

  // Optional: Timeout for webhook requests in ms (default: 30000)
  timeout: 30000,

  // Optional: Fields to always exclude (default: password, token, etc.)
  sensitiveFields: ['password', 'token', 'secret'],

  // Optional: Success response code to check (default: 20001)
  successCode: 20001,
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
           dispatchEvent() → Query subscriptions → Send to endpoints
```

## License

MIT

