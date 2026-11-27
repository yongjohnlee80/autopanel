package app

import (
	"context"

	coresite "github.com/yongjohnlee80/autopanel/core/site"
	hostgate "github.com/yongjohnlee80/autopanel/host/gate"
	"github.com/yongjohnlee80/autopanel/internal/auth"
)

// siteReaders is what the site needs to let members read on the app host:
// the user of a session cookie, found valid now by the browser login's own
// lookup (an enabled user, a session of the app host, not expired), and
// whether a name is the app host.
func siteReaders(m *apiModule) (coresite.Sessions, func(host string) bool) {
	return func(ctx context.Context, _ string, cookie string) *coresite.User {
			if m.sessions == nil {
				return nil
			}
			_, u, err := m.resolve(ctx, cookie, hostgate.HostApp)
			if err != nil {
				return nil
			}
			return &coresite.User{ID: u.ID, Admin: u.Role == auth.RoleAdmin}
		}, func(h string) bool {
			return h != "" && h == m.appHostOf(hostgate.HostApp)
		}
}

// sitePeople is the site's view of the users: who calls, and who a share
// list names, from the auth module, read at every call.
type sitePeople struct{ am *auth.Module }

func (p sitePeople) Caller(ctx context.Context) (coresite.Person, error) {
	u, err := p.am.Caller(ctx)
	if err != nil {
		return coresite.Person{}, err
	}
	return coresite.Person{ID: u.ID, Name: u.Name, Admin: u.Role == auth.RoleAdmin}, nil
}

func (p sitePeople) Named(ctx context.Context, name string) (coresite.Person, error) {
	u, err := p.am.UserNamed(ctx, name)
	if err != nil || u.DisabledAt != 0 {
		return coresite.Person{}, coresite.ErrNoUser
	}
	return coresite.Person{ID: u.ID, Name: u.Name, Admin: u.Role == auth.RoleAdmin}, nil
}

func (p sitePeople) Name(ctx context.Context, id int64) string {
	u, err := p.am.UserByID(ctx, id)
	if err != nil {
		return ""
	}
	return u.Name
}
