class MemoryStore:
    pass


def build_with_or(config):
    store = config.store or MemoryStore()
    return store


def build_with_ternary(store):
    return store if store is not None else MemoryStore()


def build_with_default(store=MemoryStore()):
    return store
