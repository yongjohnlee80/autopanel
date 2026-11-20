package app

import (
	"context"

	coresite "github.com/yongjohnlee80/autopanel/core/site"
	"github.com/yongjohnlee80/autopanel/internal/auth"
)

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
