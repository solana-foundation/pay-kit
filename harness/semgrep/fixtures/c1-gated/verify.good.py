# GOOD: assert presence first, then verify unconditionally.


def verify_credential(cred):
    if not cred.signature:
        raise ValueError("signature is required")
    verify_on_chain(cred.signature, cred.payload)
    return True


def verify_bare(signature, payload):
    if not signature:
        raise ValueError("missing signature")
    check_on_chain_proof(signature, payload)
    return True
