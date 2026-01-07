/**
 * Example usage of @vafast/webhook
 */
import { Server, createHandler, json } from 'vafast'
import { webhook, type WebhookStorage, type WebhookSubscription, type WebhookLog } from '../src'

// ============================================
// 1. Create a simple in-memory storage adapter
// ============================================
const subscriptions: WebhookSubscription[] = [
  {
    id: '1',
    appId: 'demo-app',
    eventKey: 'auth.signIn',
    endpointUrl: 'https://webhook.site/your-id',
    status: 'enabled',
  },
]

const logs: WebhookLog[] = []

const storage: WebhookStorage = {
  async findSubscriptions(appId, eventKey) {
    return subscriptions.filter(
      (s) => s.appId === appId && s.eventKey === eventKey && s.status === 'enabled'
    )
  },
  async saveLog(log) {
    logs.push(log)
    console.log('[Log] Webhook sent:', log.eventKey, log.status)
  },
}

// ============================================
// 2. Define routes with webhook configuration
// ============================================
const routes = [
  {
    method: 'POST' as const,
    path: '/auth/signIn',
    handler: createHandler(
      {},
      () => {
        return json({
          success: true,
          code: 20001,
          data: {
            userId: 'user_123',
            email: 'demo@example.com',
            jwtToken: 'secret-token-should-be-filtered',
            role: 'admin',
          },
        })
      }
    ),
    name: '用户登录',
    description: '用户登录接口',
    // Webhook configuration
    webhook: {
      exclude: ['jwtToken'], // Exclude sensitive fields
    },
  },
  {
    method: 'POST' as const,
    path: '/users/create',
    handler: createHandler(
      {},
      () => {
        return json({
          success: true,
          code: 20001,
          data: {
            userId: 'user_456',
            email: 'new@example.com',
            createdAt: new Date().toISOString(),
          },
        })
      }
    ),
    name: '创建用户',
    webhook: {
      include: ['userId', 'email', 'createdAt'], // Only include these fields
    },
  },
  {
    method: 'GET' as const,
    path: '/health',
    handler: createHandler({}, () => json({ success: true, code: 20001, data: { status: 'ok' } })),
    name: '健康检查',
    // No webhook - won't trigger
  },
]

// ============================================
// 3. Create server and add middleware
// ============================================
const server = new Server(routes)

// Add webhook middleware
server.use(
  webhook({
    storage,
    pathPrefix: '', // No prefix in this example
    appIdHeader: 'app-id',
  })
)

// ============================================
// 4. Test
// ============================================
async function test() {
  console.log('Testing webhook middleware...\n')

  // Test 1: Sign in (should trigger webhook)
  console.log('=== Test 1: POST /auth/signIn ===')
  const signInReq = new Request('http://localhost/auth/signIn', {
    method: 'POST',
    headers: {
      'app-id': 'demo-app',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ email: 'demo@example.com', password: '123456' }),
  })

  const signInRes = await server.fetch(signInReq)
  console.log('Response:', await signInRes.json())
  console.log('')

  // Test 2: Create user (should trigger webhook)
  console.log('=== Test 2: POST /users/create ===')
  const createUserReq = new Request('http://localhost/users/create', {
    method: 'POST',
    headers: {
      'app-id': 'demo-app',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ email: 'new@example.com' }),
  })

  const createUserRes = await server.fetch(createUserReq)
  console.log('Response:', await createUserRes.json())
  console.log('')

  // Test 3: Health check (no webhook)
  console.log('=== Test 3: GET /health ===')
  const healthReq = new Request('http://localhost/health', {
    headers: { 'app-id': 'demo-app' },
  })

  const healthRes = await server.fetch(healthReq)
  console.log('Response:', await healthRes.json())
  console.log('')

  // Wait for async webhooks to complete
  await new Promise((resolve) => setTimeout(resolve, 100))

  console.log('=== Webhook Logs ===')
  console.log(logs)
}

test().catch(console.error)

