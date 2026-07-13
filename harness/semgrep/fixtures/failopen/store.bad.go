package server

// BAD: replay/session store silently defaults to an in-memory implementation
// when the shared/persistent backing is not configured. Multi-instance => fails open.

type Config struct {
	Store SessionStore
}

func NewServer(config Config) *Server {
	if config.Store == nil {
		config.Store = core.NewMemoryStore() // <-- fail-open default (qualified ctor)
	}
	return &Server{store: config.Store}
}

func newSessionMethod(options Options) *Method {
	store := options.Store
	if store == nil {
		store = NewMemoryChannelStore() // <-- fail-open default (short-var form)
	}
	return &Method{store: store}
}
