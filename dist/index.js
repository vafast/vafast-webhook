// src/index.ts
import { getRoute } from "vafast";
import * as crypto from "crypto";
var DEFAULT_SENSITIVE_FIELDS = [
  "password",
  "token",
  "jwtToken",
  "refreshToken",
  "secret",
  "accessToken",
  "apiKey"
];
var DEFAULT_LOGGER = {
  debug: (msg, meta) => console.debug(`[Webhook] ${msg}`, meta || ""),
  info: (msg, meta) => console.info(`[Webhook] ${msg}`, meta || ""),
  warn: (msg, meta) => console.warn(`[Webhook] ${msg}`, meta || ""),
  error: (msg, meta) => console.error(`[Webhook] ${msg}`, meta || "")
};
function getClientIp(req) {
  return req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || req.headers.get("x-real-ip") || "unknown";
}
function generateSignature(payload, secret) {
  return crypto.createHmac("sha256", secret).update(payload).digest("hex");
}
function generateEventKey(path) {
  const segments = path.split("/").filter(Boolean);
  if (segments.length === 0) return "unknown";
  if (segments.length === 1) return segments[0];
  return `${segments[0]}.${segments.slice(1).join(".")}`;
}
function extractCategory(path) {
  const segments = path.split("/").filter(Boolean);
  return segments[0] || "unknown";
}
function generateName(path) {
  const segments = path.split("/").filter(Boolean);
  return segments.join(" / ") || "Unknown";
}
function getWebhookEventConfig(method, path) {
  const route = getRoute(method, path);
  if (!route?.webhook) return void 0;
  const webhookConfig = route.webhook;
  const fullPath = route.fullPath;
  return {
    eventKey: webhookConfig.eventKey || generateEventKey(fullPath),
    name: route.name || generateName(fullPath),
    description: route.description || "",
    category: extractCategory(fullPath),
    method: route.method,
    path: fullPath,
    config: webhookConfig
  };
}
function processFields(data, config, req, sensitiveFields) {
  let result = { ...data };
  for (const field of sensitiveFields) {
    delete result[field];
  }
  if (config.include && config.include.length > 0) {
    const newResult = {};
    for (const field of config.include) {
      if (field in result) {
        newResult[field] = result[field];
      }
    }
    result = newResult;
  }
  if (config.exclude && config.exclude.length > 0) {
    for (const field of config.exclude) {
      delete result[field];
    }
  }
  if (config.transform) {
    result = config.transform(result, req);
  }
  return {
    ...result,
    clientIp: getClientIp(req),
    userAgent: req.headers.get("user-agent") || "unknown",
    timestamp: (/* @__PURE__ */ new Date()).toISOString()
  };
}
function checkCondition(data, config) {
  if (config.condition) {
    return config.condition(data);
  }
  return true;
}
async function sendWebhook(subscription, appId, eventKey, data, storage, logger, timeout) {
  const startTime = Date.now();
  const payload = {
    appId,
    eventType: eventKey.split(".")[0],
    eventKey,
    timestamp: (/* @__PURE__ */ new Date()).toISOString(),
    data
  };
  const bodyString = JSON.stringify(payload);
  const headers = {
    "Content-Type": "application/json",
    "X-Webhook-Event": eventKey,
    "X-Webhook-Timestamp": payload.timestamp
  };
  if (subscription.secret) {
    headers["X-Webhook-Signature"] = generateSignature(bodyString, subscription.secret);
  }
  let status = "success";
  let statusCode = null;
  let errorMsg = null;
  try {
    const response = await fetch(subscription.endpointUrl, {
      method: "POST",
      headers,
      body: bodyString,
      signal: AbortSignal.timeout(timeout)
    });
    statusCode = response.status;
    if (!response.ok) {
      status = "failed";
      errorMsg = `HTTP ${response.status}`;
    }
  } catch (err) {
    status = "failed";
    errorMsg = err instanceof Error ? err.message : String(err);
  }
  const duration = Date.now() - startTime;
  try {
    await storage.saveLog({
      appId,
      webhookId: subscription.id,
      eventKey,
      endpointUrl: subscription.endpointUrl,
      payload,
      status,
      statusCode,
      error: errorMsg,
      duration,
      createdAt: /* @__PURE__ */ new Date()
    });
  } catch (logErr) {
    logger.error("Failed to save webhook log", { error: logErr });
  }
  if (status === "failed") {
    logger.warn("Webhook delivery failed", {
      eventKey,
      endpointUrl: subscription.endpointUrl,
      error: errorMsg,
      duration
    });
  } else {
    logger.debug("Webhook delivered successfully", {
      eventKey,
      endpointUrl: subscription.endpointUrl,
      statusCode,
      duration
    });
  }
}
async function dispatchEvent(appId, eventKey, data, storage, logger, timeout) {
  try {
    const subscriptions = await storage.findSubscriptions(appId, eventKey);
    if (subscriptions.length === 0) return;
    logger.info("Dispatching webhook event", {
      appId,
      eventKey,
      count: subscriptions.length
    });
    await Promise.all(
      subscriptions.map(
        (sub) => sendWebhook(sub, appId, eventKey, data, storage, logger, timeout)
      )
    );
  } catch (err) {
    logger.error("Webhook dispatch failed", { error: err });
  }
}
function webhook(config) {
  const {
    storage,
    logger = DEFAULT_LOGGER,
    pathPrefix = "",
    appIdHeader = "app-id",
    timeout = 3e4,
    sensitiveFields = DEFAULT_SENSITIVE_FIELDS,
    successCode = 20001
  } = config;
  return async (req, next) => {
    const response = await next();
    if (!response.ok) return response;
    const contentType = response.headers.get("content-type");
    if (!contentType?.includes("application/json")) return response;
    const appId = req.headers.get(appIdHeader);
    if (!appId) return response;
    const url = new URL(req.url);
    const pathname = pathPrefix ? url.pathname.replace(new RegExp(`^${pathPrefix}`), "") : url.pathname;
    const eventConfig = getWebhookEventConfig(req.method, pathname);
    if (!eventConfig) return response;
    try {
      const clonedResponse = response.clone();
      const responseData = await clonedResponse.json();
      if (!responseData.success || responseData.code !== successCode) return response;
      const rawData = responseData.data || {};
      if (!checkCondition(rawData, eventConfig.config)) return response;
      const payload = processFields(rawData, eventConfig.config, req, sensitiveFields);
      setImmediate(() => {
        dispatchEvent(appId, eventConfig.eventKey, payload, storage, logger, timeout).catch(
          (err) => {
            logger.error("Async dispatch failed", { error: err });
          }
        );
      });
    } catch {
    }
    return response;
  };
}
function dispatchWebhook(storage, logger, options) {
  const { appId, eventKey, data, req, timeout = 3e4 } = options;
  const payload = {
    ...data,
    clientIp: getClientIp(req),
    userAgent: req.headers.get("user-agent") || "unknown",
    timestamp: (/* @__PURE__ */ new Date()).toISOString()
  };
  setImmediate(() => {
    dispatchEvent(appId, eventKey, payload, storage, logger, timeout).catch((err) => {
      logger.error("Manual dispatch failed", { error: err });
    });
  });
}
var index_default = webhook;
export {
  DEFAULT_SENSITIVE_FIELDS,
  index_default as default,
  dispatchWebhook,
  extractCategory,
  generateEventKey,
  generateName,
  generateSignature,
  getClientIp,
  getWebhookEventConfig,
  webhook
};
//# sourceMappingURL=index.js.map