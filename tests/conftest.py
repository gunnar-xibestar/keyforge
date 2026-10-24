"""Patch a name where the running code looks it up.

``keyforge.kms`` re-exports ``pkcs11_from_env`` and ``read_user_pin``.
Patching those package names does not intercept calls made inside
``keyforge.kms.pkcs11`` or ``keyforge.kms.status``. The PIN cache is
``keyforge.kms.pkcs11._user_pin``.
Patches must target keyforge.audit.log, .chain or .report where the name is looked up, not the package.
"""
