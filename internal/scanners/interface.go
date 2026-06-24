package scanners

import "context"

// Scanner runs a scan phase for a given scan ID.
// Each scanner fetches its own inputs from the store and writes results back.
type Scanner interface {
	Name() string
	Run(ctx context.Context, scanID int64) error
}
