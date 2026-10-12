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
