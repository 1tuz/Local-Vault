import { ApiError } from "~/services/http.client";

export function nameErrorMessage(cause: unknown): string {
  if (cause instanceof ApiError) {
    if (cause.status === 409) return "This name is already taken.";
    if (cause.hasCode("PROJECT_NAME_INVALID")) {
      return "Use 1–128 characters. Control characters are not allowed.";
    }
    if (
      cause.hasCode("REQUEST_INVALID") ||
      cause.hasCode("ENVIRONMENT_NAME_INVALID")
    ) {
      return "Use 1–128 characters. Control characters are not allowed.";
    }
  }
  return "The operation failed. Try again.";
}
