class MemoryStore:
    pass


def build_required(config):
    if config.store is None:
        raise ValueError("a shared store is required outside single-process deploys")
    return config.store


def build_explicit_single_process(config):
    if not config.allow_single_process_memory_store:
        raise ValueError("memory store requires explicit single-process opt-in")
    explicit_single_process_store = MemoryStore()
    return explicit_single_process_store


def build_guarded(config, is_localnet):
    uses_memory_store = config.store is None or isinstance(config.store, MemoryStore)
    if uses_memory_store and not is_localnet and os.getenv("ALLOW_MEMORY") != "1":
        raise ValueError("shared store required")
    store = config.store if config.store is not None else MemoryStore()
    return store


def build_guarded_absence(config, network):
    if config.store is None and network != "localnet":
        raise ValueError("shared store required")
    store = config.store if config.store is not None else MemoryStore()
    return store
