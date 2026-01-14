import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import {
  generateEventKey,
  generateEventId,
  extractCategory,
  generateName,
  generateSignature,
  getClientIp,
  DEFAULT_SENSITIVE_FIELDS,
  defineWebhooks,
  dispatchWebhook,
  getAllWebhookEvents,
  getWebhookCategories,
  getWebhookEventsByCategory,
  type WebhookLogger,
} from '../src/index'

// Mock fetch for testing
const mockFetch = vi.fn()
vi.stubGlobal('fetch', mockFetch)

// Mock vafast filterRoutes for event query tests
vi.mock('vafast', () => ({
  getRoute: vi.fn(),
  filterRoutes: vi.fn(),
}))

// Mock logger
const mockLogger: WebhookLogger = {
  debug: vi.fn(),
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
}

describe('@vafast/webhook', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
  })
  describe('generateEventKey', () => {
    it('should generate event key from path', () => {
      expect(generateEventKey('/auth/signIn')).toBe('auth.signIn')
      expect(generateEventKey('/users/create')).toBe('users.create')
      expect(generateEventKey('/api/v1/orders')).toBe('api.v1.orders')
    })

    it('should handle single segment path', () => {
      expect(generateEventKey('/health')).toBe('health')
    })

    it('should handle empty path', () => {
      expect(generateEventKey('/')).toBe('unknown')
      expect(generateEventKey('')).toBe('unknown')
    })
  })

  describe('generateEventId', () => {
    it('should generate unique event IDs with evt_ prefix', () => {
      const id1 = generateEventId()
      const id2 = generateEventId()
      
      expect(id1).toMatch(/^evt_[a-z0-9]+_[a-f0-9]+$/)
      expect(id2).toMatch(/^evt_[a-z0-9]+_[a-f0-9]+$/)
      expect(id1).not.toBe(id2)
    })

    it('should produce consistent format', () => {
      const id = generateEventId()
      const parts = id.split('_')
      
      expect(parts.length).toBe(3)
      expect(parts[0]).toBe('evt')
      // timestamp part (base36)
      expect(parts[1].length).toBeGreaterThan(0)
      // random part (16 hex chars = 8 bytes)
      expect(parts[2].length).toBe(16)
    })
  })

  describe('extractCategory', () => {
    it('should extract first segment as category', () => {
      expect(extractCategory('/auth/signIn')).toBe('auth')
      expect(extractCategory('/users/create')).toBe('users')
      expect(extractCategory('/api/v1/orders')).toBe('api')
    })

    it('should return "unknown" for empty path', () => {
      expect(extractCategory('/')).toBe('unknown')
      expect(extractCategory('')).toBe('unknown')
    })
  })

  describe('generateName', () => {
    it('should generate name from path', () => {
      expect(generateName('/auth/signIn')).toBe('auth / signIn')
      expect(generateName('/users/create')).toBe('users / create')
    })

    it('should return "Unknown" for empty path', () => {
      expect(generateName('/')).toBe('Unknown')
      expect(generateName('')).toBe('Unknown')
    })
  })

  describe('generateSignature', () => {
    it('should generate HMAC-SHA256 signature', () => {
      const payload = JSON.stringify({ test: 'data' })
      const secret = 'my-secret'
      const signature = generateSignature(payload, secret)

      expect(signature).toBeTruthy()
      expect(signature.length).toBe(64) // SHA256 hex is 64 chars
    })

    it('should produce consistent signatures', () => {
      const payload = JSON.stringify({ test: 'data' })
      const secret = 'my-secret'

      const sig1 = generateSignature(payload, secret)
      const sig2 = generateSignature(payload, secret)

      expect(sig1).toBe(sig2)
    })

    it('should produce different signatures for different secrets', () => {
      const payload = JSON.stringify({ test: 'data' })

      const sig1 = generateSignature(payload, 'secret1')
      const sig2 = generateSignature(payload, 'secret2')

      expect(sig1).not.toBe(sig2)
    })
  })

  describe('getClientIp', () => {
    it('should extract IP from x-forwarded-for header', () => {
      const req = new Request('http://localhost', {
        headers: { 'x-forwarded-for': '192.168.1.1, 10.0.0.1' },
      })
      expect(getClientIp(req)).toBe('192.168.1.1')
    })

    it('should extract IP from x-real-ip header', () => {
      const req = new Request('http://localhost', {
        headers: { 'x-real-ip': '10.0.0.1' },
      })
      expect(getClientIp(req)).toBe('10.0.0.1')
    })

    it('should return "unknown" if no IP headers', () => {
      const req = new Request('http://localhost')
      expect(getClientIp(req)).toBe('unknown')
    })
  })

  describe('DEFAULT_SENSITIVE_FIELDS', () => {
    it('should include common sensitive fields', () => {
      expect(DEFAULT_SENSITIVE_FIELDS).toContain('password')
      expect(DEFAULT_SENSITIVE_FIELDS).toContain('token')
      expect(DEFAULT_SENSITIVE_FIELDS).toContain('jwtToken')
      expect(DEFAULT_SENSITIVE_FIELDS).toContain('refreshToken')
      expect(DEFAULT_SENSITIVE_FIELDS).toContain('secret')
      expect(DEFAULT_SENSITIVE_FIELDS).toContain('accessToken')
      expect(DEFAULT_SENSITIVE_FIELDS).toContain('apiKey')
    })
  })

  describe('defineWebhooks', () => {
    it('should create storage with initial configs', () => {
      const storage = defineWebhooks([
        { eventKey: 'auth.signIn', url: 'https://example.com/hook1' },
        { eventKey: 'auth.signUp', url: 'https://example.com/hook2' },
      ])

      expect(storage.subscriptions).toHaveLength(2)
      expect(storage.subscriptions[0].eventKey).toBe('auth.signIn')
      expect(storage.subscriptions[1].eventKey).toBe('auth.signUp')
    })

    it('should allow dynamic subscription adding', () => {
      const storage = defineWebhooks()
      expect(storage.subscriptions).toHaveLength(0)

      const id = storage.add({ eventKey: 'test.event', url: 'https://example.com/hook' })
      expect(id).toBeTruthy()
      expect(storage.subscriptions).toHaveLength(1)
    })

    it('should support wildcard matching', async () => {
      const storage = defineWebhooks([
        { eventKey: 'users.*', url: 'https://example.com/hook' },
      ])

      const matches = await storage.findSubscriptions(undefined, 'users.create')
      expect(matches).toHaveLength(1)

      const noMatches = await storage.findSubscriptions(undefined, 'auth.signIn')
      expect(noMatches).toHaveLength(0)
    })

    it('should preserve custom fields', () => {
      const storage = defineWebhooks([
        { 
          eventKey: 'auth.signIn', 
          url: 'https://example.com/hook',
          secret: 'my-secret',
          customField: 'custom-value',
        },
      ])

      expect(storage.subscriptions[0].secret).toBe('my-secret')
      expect(storage.subscriptions[0]['customField']).toBe('custom-value')
    })
  })

  describe('Retry mechanism', () => {
    it('should retry on failure with exponential backoff', async () => {
      vi.useRealTimers() // Use real timers for this test
      
      let attempts = 0
      mockFetch.mockImplementation(() => {
        attempts++
        if (attempts < 3) {
          return Promise.resolve({ ok: false, status: 500 })
        }
        return Promise.resolve({ ok: true, status: 200 })
      })

      const storage = defineWebhooks([
        { eventKey: 'test.event', url: 'https://example.com/hook' },
      ])

      const req = new Request('http://localhost/test')
      
      dispatchWebhook(storage, mockLogger, {
        eventKey: 'test.event',
        data: { test: 'data' },
        req,
        timeout: 5000,
        retry: { count: 3, delay: 10, backoff: 2, maxDelay: 1000 },
      })

      // Wait for async dispatch
      await new Promise((resolve) => setTimeout(resolve, 200))

      // Should have retried and eventually succeeded
      expect(attempts).toBeGreaterThanOrEqual(2)
    })

    it('should give up after max retries', async () => {
      vi.useRealTimers()
      
      mockFetch.mockResolvedValue({ ok: false, status: 500 })

      const storage = defineWebhooks([
        { eventKey: 'test.event', url: 'https://example.com/hook' },
      ])

      const req = new Request('http://localhost/test')
      
      dispatchWebhook(storage, mockLogger, {
        eventKey: 'test.event',
        data: { test: 'data' },
        req,
        timeout: 5000,
        retry: { count: 2, delay: 10, backoff: 1 },
      })

      // Wait for all retries
      await new Promise((resolve) => setTimeout(resolve, 200))

      // Should have been called 3 times (1 initial + 2 retries)
      expect(mockFetch).toHaveBeenCalledTimes(3)
      
      // Should log warning about failure
      expect(mockLogger.warn).toHaveBeenCalled()
    })

    it('should succeed on first attempt without retry', async () => {
      vi.useRealTimers()
      
      mockFetch.mockResolvedValue({ ok: true, status: 200 })

      const storage = defineWebhooks([
        { eventKey: 'test.event', url: 'https://example.com/hook' },
      ])

      const req = new Request('http://localhost/test')
      
      dispatchWebhook(storage, mockLogger, {
        eventKey: 'test.event',
        data: { test: 'data' },
        req,
        timeout: 5000,
        retry: { count: 3, delay: 10 },
      })

      await new Promise((resolve) => setTimeout(resolve, 100))

      // Should only be called once
      expect(mockFetch).toHaveBeenCalledTimes(1)
    })
  })

  describe('Concurrency control', () => {
    it('should limit concurrent requests', async () => {
      vi.useRealTimers()
      
      let concurrent = 0
      let maxConcurrent = 0
      
      mockFetch.mockImplementation(async () => {
        concurrent++
        maxConcurrent = Math.max(maxConcurrent, concurrent)
        await new Promise((resolve) => setTimeout(resolve, 50))
        concurrent--
        return { ok: true, status: 200 }
      })

      // Create 10 subscriptions
      const storage = defineWebhooks(
        Array.from({ length: 10 }, (_, i) => ({
          eventKey: 'test.event',
          url: `https://example.com/hook${i}`,
        }))
      )

      const req = new Request('http://localhost/test')
      
      dispatchWebhook(storage, mockLogger, {
        eventKey: 'test.event',
        data: { test: 'data' },
        req,
        timeout: 5000,
        concurrency: 3, // Only 3 concurrent
      })

      // Wait for all to complete
      await new Promise((resolve) => setTimeout(resolve, 500))

      // Max concurrent should be limited to 3
      expect(maxConcurrent).toBeLessThanOrEqual(3)
      // All 10 should have been called
      expect(mockFetch).toHaveBeenCalledTimes(10)
    })

    it('should use default concurrency of 10', async () => {
      vi.useRealTimers()
      
      let concurrent = 0
      let maxConcurrent = 0
      
      mockFetch.mockImplementation(async () => {
        concurrent++
        maxConcurrent = Math.max(maxConcurrent, concurrent)
        await new Promise((resolve) => setTimeout(resolve, 20))
        concurrent--
        return { ok: true, status: 200 }
      })

      // Create 15 subscriptions
      const storage = defineWebhooks(
        Array.from({ length: 15 }, (_, i) => ({
          eventKey: 'test.event',
          url: `https://example.com/hook${i}`,
        }))
      )

      const req = new Request('http://localhost/test')
      
      dispatchWebhook(storage, mockLogger, {
        eventKey: 'test.event',
        data: { test: 'data' },
        req,
        timeout: 5000,
        // No concurrency specified, defaults to 10
      })

      await new Promise((resolve) => setTimeout(resolve, 500))

      // Default concurrency is 10
      expect(maxConcurrent).toBeLessThanOrEqual(10)
      expect(mockFetch).toHaveBeenCalledTimes(15)
    })
  })

  describe('Retry + Concurrency combined', () => {
    it('should respect concurrency even with retries', async () => {
      vi.useRealTimers()
      
      let concurrent = 0
      let maxConcurrent = 0
      let callCount = 0
      
      mockFetch.mockImplementation(async () => {
        callCount++
        concurrent++
        maxConcurrent = Math.max(maxConcurrent, concurrent)
        await new Promise((resolve) => setTimeout(resolve, 20))
        concurrent--
        // First call fails, second succeeds
        return { ok: callCount > 5, status: callCount > 5 ? 200 : 500 }
      })

      const storage = defineWebhooks(
        Array.from({ length: 5 }, (_, i) => ({
          eventKey: 'test.event',
          url: `https://example.com/hook${i}`,
        }))
      )

      const req = new Request('http://localhost/test')
      
      dispatchWebhook(storage, mockLogger, {
        eventKey: 'test.event',
        data: { test: 'data' },
        req,
        timeout: 5000,
        retry: { count: 2, delay: 10 },
        concurrency: 2,
      })

      await new Promise((resolve) => setTimeout(resolve, 500))

      // Concurrency should still be respected
      expect(maxConcurrent).toBeLessThanOrEqual(2)
    })
  })

  describe('Event Query Functions', () => {
    const mockRoutes = [
      {
        method: 'POST',
        path: '/auth/signIn',
        fullPath: '/restfulApi/auth/signIn',
        name: '用户登录',
        description: '用户登录接口',
        webhook: { exclude: ['jwtToken'] },
      },
      {
        method: 'POST',
        path: '/auth/signUp',
        fullPath: '/restfulApi/auth/signUp',
        name: '用户注册',
        description: '用户注册接口',
        webhook: {},
      },
      {
        method: 'PUT',
        path: '/users/update',
        fullPath: '/restfulApi/users/update',
        name: '更新用户',
        description: '更新用户信息',
        webhook: { include: ['userId', 'email'] },
      },
      {
        method: 'DELETE',
        path: '/users/delete',
        fullPath: '/restfulApi/users/delete',
        name: '删除用户',
        webhook: { eventKey: 'users.remove' },
      },
    ]

    beforeEach(async () => {
      const vafast = await import('vafast')
      vi.mocked(vafast.filterRoutes).mockReturnValue(mockRoutes as any)
    })

    describe('getAllWebhookEvents', () => {
      it('should return all webhook events', () => {
        const events = getAllWebhookEvents()
        expect(events).toHaveLength(4)
      })

      it('should generate eventKey from path', () => {
        const events = getAllWebhookEvents()
        // 使用 route.path 生成 eventKey
        expect(events[0].eventKey).toBe('auth.signIn')
        expect(events[1].eventKey).toBe('auth.signUp')
      })

      it('should strip pathPrefix when generating eventKey', () => {
        const events = getAllWebhookEvents('/restfulApi')
        expect(events[0].eventKey).toBe('auth.signIn')
        expect(events[1].eventKey).toBe('auth.signUp')
        expect(events[2].eventKey).toBe('users.update')
      })

      it('should use custom eventKey if provided', () => {
        const events = getAllWebhookEvents('/restfulApi')
        // The 4th route has a custom eventKey
        expect(events[3].eventKey).toBe('users.remove')
      })

      it('should include route name and description', () => {
        const events = getAllWebhookEvents()
        expect(events[0].name).toBe('用户登录')
        expect(events[0].description).toBe('用户登录接口')
      })

      it('should extract category from path', () => {
        const events = getAllWebhookEvents('/restfulApi')
        expect(events[0].category).toBe('auth')
        expect(events[2].category).toBe('users')
      })
    })

    describe('getWebhookCategories', () => {
      it('should return unique categories with names', () => {
        const categories = getWebhookCategories('/restfulApi')
        expect(categories).toHaveLength(2)
        expect(categories.map(c => c.category)).toContain('auth')
        expect(categories.map(c => c.category)).toContain('users')
      })

      it('should sort categories alphabetically', () => {
        const categories = getWebhookCategories('/restfulApi')
        expect(categories.map(c => c.category)).toEqual(['auth', 'users'])
      })
    })

    describe('getWebhookEventsByCategory', () => {
      it('should return events for specific category', () => {
        const authEvents = getWebhookEventsByCategory('auth', '/restfulApi')
        expect(authEvents).toHaveLength(2)
        expect(authEvents.every(e => e.category === 'auth')).toBe(true)
      })

      it('should return events for users category', () => {
        const usersEvents = getWebhookEventsByCategory('users', '/restfulApi')
        expect(usersEvents).toHaveLength(2)
        expect(usersEvents.every(e => e.category === 'users')).toBe(true)
      })

      it('should return empty array for non-existent category', () => {
        const events = getWebhookEventsByCategory('orders', '/restfulApi')
        expect(events).toHaveLength(0)
      })
    })
  })
})

