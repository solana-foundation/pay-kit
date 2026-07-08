# BAD (C1): on-chain proof only runs when signature is truthy; empty => bypass.


def verify_credential(cred):
    if cred.signature:
        verify_on_chain(cred.signature, cred.payload)
    return True


def verify_bare(signature, payload):
    if signature:
        check_on_chain_proof(signature, payload)
    return True
