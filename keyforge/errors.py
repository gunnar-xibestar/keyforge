class KeyForgeError(Exception):
    exit_code = 1
class NotFound(KeyForgeError):
    exit_code = 3
class VerifyFailed(KeyForgeError):
    exit_code = 4
class PolicyViolation(KeyForgeError):
    exit_code = 5
class Aborted(KeyForgeError):
    exit_code = 6
class ValidationError(KeyForgeError):
    exit_code = 2
class AuthError(KeyForgeError):
    """Authentication failed or the Auth0 token was rejected."""
    exit_code = 1
class Unauthorized(KeyForgeError):
    """Authenticated, but missing a required scope. Same exit code as verify failure."""
    exit_code = 4
