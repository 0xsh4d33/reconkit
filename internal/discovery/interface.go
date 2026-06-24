package discovery

import (
	"context"

	"github.com/blackfly/reconkit/internal/models"
)

// Discoverer produces assets from a target string (domain or CIDR).
type Discoverer interface {
	Name() string
	Discover(ctx context.Context, target string) ([]models.Asset, error)
}
