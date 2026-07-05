/**
 * HTTP Dispatcher：委托 webhook-server 统一投递业务事件
 */
export type WebhookDeliveryType = 'generic' | 'feishu' | 'dingtalk' | 'wecom' | 'slack'

export interface WebhookDispatchSubscription {
  id: string
  endpointUrl: string
  deliveryType?: WebhookDeliveryType
  secret?: string
  signSecret?: string
}

export interface WebhookDispatchInput {
  subscription: WebhookDispatchSubscription
  appId?: string
  eventKey: string
  eventId: string
  data: Record<string, unknown>
}

export interface WebhookDispatchResult {
  success: boolean
  statusCode: number | null
  error: string | null
  payload: Record<string, unknown>
}

export interface WebhookDispatcher {
  dispatch(input: WebhookDispatchInput): Promise<WebhookDispatchResult>
}

export interface HttpDispatcherOptions {
  baseUrl: string
  timeout?: number
  apiKeyId: string
  apiKeySecret: string
}

/**
 * 创建 HTTP Dispatcher，调用 webhook-server /internal/dispatchEvent 代发
 */
export function createHttpDispatcher(options: HttpDispatcherOptions): WebhookDispatcher {
  const {
    baseUrl,
    apiKeyId,
    apiKeySecret,
    timeout = 10000,
  } = options

  const headers = {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${apiKeyId}:${apiKeySecret}`,
  }

  return {
    async dispatch(input) {
      const { subscription, appId, eventKey, eventId, data } = input
      const deliveryType = subscription.deliveryType ?? 'generic'

      try {
        const response = await fetch(`${baseUrl}/internal/dispatchEvent`, {
          method: 'POST',
          headers,
          body: JSON.stringify({
            appId,
            eventKey,
            eventId,
            subscription: {
              id: subscription.id,
              endpointUrl: subscription.endpointUrl,
              deliveryType,
              secret: subscription.secret,
              signSecret: subscription.signSecret,
            },
            data,
          }),
          signal: AbortSignal.timeout(timeout),
        })

        if (!response.ok) {
          return {
            success: false,
            statusCode: response.status,
            error: `HTTP ${response.status}`,
            payload: data,
          }
        }

        const result = await response.json() as {
          success?: boolean
          data?: {
            success?: boolean
            statusCode?: number | null
            error?: string | null
            payload?: Record<string, unknown>
          }
        } & WebhookDispatchResult

        const payload = result.data?.payload ?? result.payload ?? data
        const dispatchResult = result.data ?? result

        return {
          success: dispatchResult.success === true,
          statusCode: dispatchResult.statusCode ?? null,
          error: dispatchResult.error ?? null,
          payload,
        }
      }
      catch (err) {
        return {
          success: false,
          statusCode: null,
          error: err instanceof Error ? err.message : String(err),
          payload: data,
        }
      }
    },
  }
}
