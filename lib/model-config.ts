/**
 * Centralized, secure AI model configuration for AegisFlow.
 * Protects against accidental key-as-model misconfigurations,
 * provides verified fallback models, and redacts sensitive credentials.
 */

export interface ModelConfig {
  provider: 'Featherless AI';
  primaryModel: string;
  fallbackTextModel: string;
  fallbackVisionModel: string;
  apiKeyConfigured: boolean;
  userAgent: string;
}

// Officially verified models on Featherless AI
export const VERIFIED_PRIMARY_MODEL = 'Qwen/Qwen3-VL-8B-Instruct';
export const VERIFIED_FALLBACK_TEXT_MODEL = 'Qwen/Qwen2.5-7B-Instruct';
export const VERIFIED_FALLBACK_VISION_MODEL = 'Qwen/Qwen3-VL-4B-Instruct';

const USER_AGENT = 'AegisFlow/1.0 (Cybersecurity Intelligence; +https://aegisflowx.vercel.app)';

/**
 * Validates whether a model identifier is well-formed (e.g. "org/model-name").
 * Rejects API keys (like "rc_..."), hex tokens, or strings without a slash.
 */
export function isValidModelIdentifier(modelCandidate?: string | null): boolean {
  if (!modelCandidate || typeof modelCandidate !== 'string') return false;
  const trimmed = modelCandidate.trim();
  // Reject keys starting with common token prefixes
  if (trimmed.startsWith('rc_') || trimmed.startsWith('sk-') || trimmed.startsWith('AIza')) {
    return false;
  }
  // Reject hex-only tokens (e.g. 32 or 64 char hashes)
  if (/^[a-f0-9]{32,}$/i.test(trimmed)) {
    return false;
  }
  // Model identifiers on Featherless/HuggingFace must be in "owner/model_name" format
  if (!trimmed.includes('/') || trimmed.split('/').length !== 2) {
    return false;
  }
  return true;
}

/**
 * Redacts any API key or secret token patterns from text.
 * Ensures credentials never leak in logs, user messages, or error responses.
 */
export function redactSecrets(text: string): string {
  if (!text || typeof text !== 'string') return '';
  let sanitized = text;

  // Redact current process key if available
  const currentKey = process.env.FEATHERLESS_API_KEY;
  if (currentKey && currentKey.length > 8 && currentKey !== 'YOUR_FEATHERLESS_API_KEY') {
    sanitized = sanitized.split(currentKey).join('[REDACTED_FEATHERLESS_KEY]');
  }

  // Redact generic token patterns
  sanitized = sanitized.replace(/rc_[a-f0-9]{30,}/gi, '[REDACTED_TOKEN]');
  sanitized = sanitized.replace(/Bearer\s+[A-Za-z0-9_\-\.]{15,}/gi, 'Bearer [REDACTED_TOKEN]');

  return sanitized;
}

/**
 * Authoritatively resolves the model to use for analysis.
 * Safely guards against production env var confusion where FEATHERLESS_MODEL
 * was set to the API key or an invalid identifier.
 */
export function resolveFeatherlessModel(isVisionRequired: boolean = false): {
  model: string;
  isCustom: boolean;
  warnings?: string[];
} {
  const envModel = process.env.FEATHERLESS_MODEL;
  const envKey = process.env.FEATHERLESS_API_KEY;
  const warnings: string[] = [];

  // Check if FEATHERLESS_MODEL was mistakenly set to the API key
  if (envModel && (envModel === envKey || envModel.startsWith('rc_') || !isValidModelIdentifier(envModel))) {
    warnings.push(
      'Invalid FEATHERLESS_MODEL detected (model identifier cannot be a key or non-repo string). Falling back to verified default.'
    );
    return {
      model: isVisionRequired ? VERIFIED_PRIMARY_MODEL : VERIFIED_PRIMARY_MODEL,
      isCustom: false,
      warnings,
    };
  }

  if (envModel && isValidModelIdentifier(envModel)) {
    return {
      model: envModel.trim(),
      isCustom: true,
    };
  }

  return {
    model: VERIFIED_PRIMARY_MODEL,
    isCustom: false,
  };
}

/**
 * Returns safe server-side model configuration without exposing secrets.
 */
export function getSafeModelConfig(): ModelConfig {
  const key = process.env.FEATHERLESS_API_KEY;
  const hasValidKey = Boolean(key && key !== 'YOUR_FEATHERLESS_API_KEY' && key.trim().length > 10);
  const { model } = resolveFeatherlessModel(false);

  return {
    provider: 'Featherless AI',
    primaryModel: model,
    fallbackTextModel: VERIFIED_FALLBACK_TEXT_MODEL,
    fallbackVisionModel: VERIFIED_FALLBACK_VISION_MODEL,
    apiKeyConfigured: hasValidKey,
    userAgent: USER_AGENT,
  };
}

/**
 * Standard fetch options with custom User-Agent and auth headers for Featherless AI.
 */
export function getFeatherlessHeaders(apiKey: string): Record<string, string> {
  return {
    'Content-Type': 'application/json',
    Authorization: `Bearer ${apiKey.trim()}`,
    'User-Agent': USER_AGENT,
  };
}
