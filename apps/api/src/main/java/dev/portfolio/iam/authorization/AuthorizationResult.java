package dev.portfolio.iam.authorization;

/** Only ALLOW grants access; all other outcomes fail closed. */
public enum AuthorizationResult {
  ALLOW, DENY, INVALID_REQUEST, INVALID_CONFIGURATION, TIMEOUT, UNAVAILABLE,
  INVALID_RESPONSE, DATABASE_FAILURE;

  public boolean isAllowed() { return this == ALLOW; }
}
