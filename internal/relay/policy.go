package relay

import "git.gosuda.org/lemon-mint/proxygen/internal/model"

// DestinationPolicy decides whether an authenticated client flow may reach its
// requested destination. Relays require a non-nil policy.
type DestinationPolicy func(model.FlowKey) bool
