/**
 * HTTP Dispatcher：委托 webhook-server 统一投递业务事件
 */
export type WebhookDeliveryType = 'generic' | 'feishu' | 'dingtalk' | 'wecom' | 'slack'

/** 投递订阅：已知字段 + 运行时透传其余 webhook-server 字段 */
export interface WebhookDispatchSubscription {
  id: string
  endpointUrl?: string
  deliveryType?: string
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

/** 序列化订阅：透传 webhook-server 字段，跳过 null / 空数组 */
function serializeDispatchSubscription(subscription: WebhookDispatchSubscription) {
  const result: Record<string, unknown> = {
    id: subscription.id,
    endpointUrl: subscription.endpointUrl ?? '',
    deliveryType: subscription.deliveryType ?? 'generic',
  }

  for (const [key, value] of Object.entries(subscription)) {
    if (key === 'id' || key === 'endpointUrl' || key === 'deliveryType') {
      continue
    }
    if (value == null) {
      continue
    }
    if (Array.isArray(value) && value.length === 0) {
      continue
    }
    result[key] = value
  }

  return result
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

      try {
        const response = await fetch(`${baseUrl}/internal/dispatchEvent`, {
          method: 'POST',
          headers,
          body: JSON.stringify({
            appId,
            eventKey,
            eventId,
            subscription: serializeDispatchSubscription(subscription),
            data,
          }),
          signal: AbortSignal.timeout(timeout),
        })

        if (!response.ok) {
          let error = `HTTP ${response.status}`
          try {
            const errBody = await response.json() as { message?: string, error?: string }
            if (errBody.message)
              error = errBody.message
            else if (errBody.error)
              error = errBody.error
          }
          catch {
            // 非 JSON 响应，保留 HTTP 状态描述
          }

          return {
            success: false,
            statusCode: response.status,
            error,
            payload: data,
          }
        }

        const dispatchResult = await response.json() as WebhookDispatchResult

        return {
          success: dispatchResult.success === true,
          statusCode: dispatchResult.statusCode ?? null,
          error: dispatchResult.error ?? null,
          payload: dispatchResult.payload ?? data,
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
