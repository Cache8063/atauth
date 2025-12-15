/**
 * Error Handling Utilities
 *
 * Provides safe error responses that don't leak internal details.
 * Express 5 automatically forwards async errors to the error handler.
 */

/**
 * Standard error response format.
 */
export interface ErrorResponse {
  error: string;
  message: string;
}

/**
 * HTTP error with status code and machine-readable error code.
 * Thrown from route handlers and caught by the global error middleware.
 */
export class HttpError extends Error {
  constructor(
    public readonly statusCode: number,
    public readonly code: string,
    message: string
  ) {
    super(message);
    this.name = 'HttpError';
  }
}

/**
 * Convenience factory functions for common HTTP errors.
 */
export const httpError = {
  badRequest: (code: string, message: string) => new HttpError(400, code, message),
  unauthorized: (code: string, message: string) => new HttpError(401, code, message),
  forbidden: (code: string, message: string) => new HttpError(403, code, message),
  notFound: (code: string, message: string) => new HttpError(404, code, message),
  conflict: (code: string, message: string) => new HttpError(409, code, message),
};

/**
 * Sanitize an error for client response.
 * Logs the full error server-side but returns a safe message to clients.
 *
 * @param error - The caught error
 * @param context - Context for logging (e.g., "Token verify")
 * @returns Safe error message for client response
 */
export function sanitizeError(error: unknown, context: string): string {
  // Log full error details server-side for debugging
  console.error(`${context} error:`, error);

  // In development, return more details for debugging
  // In production, return a generic message
  if (process.env.NODE_ENV === 'development') {
    if (error instanceof Error) {
      // Even in dev, don't expose stack traces or sensitive paths
      return error.message.replace(/\/[^\s:]+/g, '[path]');
    }
  }

  // Generic message that doesn't leak implementation details
  return 'An internal error occurred. Please try again later.';
}

/**
 * Create a safe 500 error response.
 *
 * @param errorCode - Machine-readable error code
 * @param error - The caught error
 * @param context - Context for logging
 * @returns Error response object
 */
export function internalError(
  errorCode: string,
  error: unknown,
  context: string
): ErrorResponse {
  return {
    error: errorCode,
    message: sanitizeError(error, context),
  };
}
