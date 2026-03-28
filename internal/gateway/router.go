package gateway

import (
	"net"
	"net/http"
	"sort"
	"strings"

	"github.com/stormbane-security/bulwark/internal/config"
)

// route holds the routing info needed to proxy a matched request.
type route struct {
	id       string
	upstream string
}

// routeEntry is one entry in the router's sorted table.
type routeEntry struct {
	host       string
	pathPrefix string
	route      route
}

// router matches HTTP requests to configured routes using host + longest path prefix.
type router struct {
	entries []routeEntry
}

// newRouter builds a router from config routes.
// Entries are sorted by descending path prefix length so the first match
// is always the most specific.
func newRouter(routes []config.RouteConfig) *router {
	entries := make([]routeEntry, len(routes))
	for i, r := range routes {
		entries[i] = routeEntry{
			host:       r.Match.Host,
			pathPrefix: r.Match.PathPrefix,
			route:      route{id: r.ID, upstream: r.Upstream.URL},
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		return len(entries[i].pathPrefix) > len(entries[j].pathPrefix)
	})
	return &router{entries: entries}
}

// match returns the first (longest-prefix) route matching req, or nil.
func (r *router) match(req *http.Request) *route {
	host := req.Host
	// Strip port if present — config hosts are bare hostnames.
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	path := req.URL.Path
	for i := range r.entries {
		e := &r.entries[i]
		if strings.EqualFold(e.host, host) && strings.HasPrefix(path, e.pathPrefix) {
			return &e.route
		}
	}
	return nil
}
