package peercred

import "errors"

// errUnsupported is a platform with no record of a socket peer's user.
var errUnsupported = errors.New("peercred: no peer credentials on this platform")
