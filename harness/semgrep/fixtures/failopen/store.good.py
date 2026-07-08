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
