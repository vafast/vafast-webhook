import { describe, it, expect, vi, beforeEach } from 'vitest'
import {
  generateEventKey,
  extractCategory,
  generateName,
  generateSignature,
  getClientIp,
  DEFAULT_SENSITIVE_FIELDS,
} from '../src/index'

describe('@vafast/webhook', () => {
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
})

