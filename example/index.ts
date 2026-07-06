/**
 * Example usage of @vafast/webhook
 */
import { Server, defineRoutes } from 'vafast'
import { webhook, type WebhookStorage, type WebhookSubscription, type WebhookLog } from '../src'

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
      s => s.appId === appId && s.eventKey === eventKey && s.status === 'enabled',
    )
  },
  async saveLog(log) {
    logs.push(log)
    console.log('[Log] Webhook sent:', log.eventKey, log.status)
  },
}

const routes = defineRoutes([
  {
    method: 'POST',
    path: '/auth/signIn',
    name: '用户登录',
    description: '用户登录接口',
    webhook: {
      exclude: ['jwtToken'],
    },
    handler: () => ({
      userId: 'user_123',
      email: 'demo@example.com',
      jwtToken: 'secret-token-should-be-filtered',
      role: 'admin',
    }),
  },
  {
    method: 'POST',
    path: '/users/create',
    name: '创建用户',
    webhook: {
      include: ['userId', 'email', 'createdAt'],
    },
    handler: () => ({
      userId: 'user_456',
      email: 'new@example.com',
      createdAt: new Date().toISOString(),
    }),
  },
  {
    method: 'GET',
    path: '/health',
    name: '健康检查',
    handler: () => ({ status: 'ok' }),
  },
])

const server = new Server(routes)

server.use(
  webhook({
    storage,
    pathPrefix: '',
    getAppId: req => req.headers.get('app-id') || undefined,
  }),
)

async function test() {
  console.log('Testing webhook middleware...\n')

  console.log('=== Test 1: POST /auth/signIn ===')
  const signInRes = await server.fetch(new Request('http://localhost/auth/signIn', {
    method: 'POST',
    headers: {
      'app-id': 'demo-app',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ email: 'demo@example.com', password: '123456' }),
  }))
  console.log('Response:', await signInRes.json())

  console.log('\n=== Test 2: POST /users/create ===')
  const createUserRes = await server.fetch(new Request('http://localhost/users/create', {
    method: 'POST',
    headers: {
      'app-id': 'demo-app',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ email: 'new@example.com' }),
  }))
  console.log('Response:', await createUserRes.json())

  console.log('\n=== Test 3: GET /health ===')
  const healthRes = await server.fetch(new Request('http://localhost/health', {
    headers: { 'app-id': 'demo-app' },
  }))
  console.log('Response:', await healthRes.json())

  await new Promise(resolve => setTimeout(resolve, 100))
  console.log('\n=== Webhook Logs ===')
  console.log(logs)
}

test().catch(console.error)
