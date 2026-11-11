// Package module is how an AutoPanel feature offers verbs: a Module declares
// each verb's contract and handler, and every host (the control socket, the
// CLI's --contracts, later the panel's JSON API) is derived from the contract,
// so a verb is said once.
//
// Interim: a minimal form of AutoDoc's core/module, kept until golib ships the
// shared seam (ADR Q3, tracked by AutoPanel M1.8). Its shape follows AutoDoc's
// (Contract, Verb, Module, PublicError) so the move is mechanical.
package module

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// Contract is a verb as every surface sees it. It is pure data.
type Contract struct {
	Verb   string `json:"verb"`             // "gate.route.add"
	Since  int64  `json:"since"`            // the protocol it arrived in
	Param  string `json:"param,omitempty"`  // the one param's shape, for people: "{host, path_prefix?, upstream}"; "" for none
	Result string `json:"result,omitempty"` // the result's shape, for people
	Doc    string `json:"doc"`
	// Public marks a verb the panel's HTTPS API may serve. The default is
	// private: reachable only on the control socket.
	Public bool `json:"public,omitempty"`
	// Mutates marks a verb that changes state; its success is audited.
	Mutates bool `json:"mutates,omitempty"`
	// Open marks a verb callable before logging in. Only the login is.
	Open bool `json:"open,omitempty"`
	// Login marks the verb whose success authenticates the connection as the
	// user its result names ({"user": …}).
	Login bool `json:"login,omitempty"`
}

// Verb is a Contract and its handler. A verb takes zero or one param, an object.
type Verb struct {
	Contract
	Call func(ctx context.Context, params []any) (any, error)
}

// Module is a feature's verbs and the public errors they may answer.
type Module interface {
	Name() string
	Verbs() []Verb
	Errors() []PublicError
}

// PublicError is an error a client may see: the code is its identity on the
// wire, and the message is all of it that crosses. errors.Is decides.
type PublicError struct {
	Err     error  `json:"-"`
	Code    int64  `json:"code"`
	Name    string `json:"name"`
	Message string `json:"message"`
}

// ErrInvalidParams is a call whose params don't fit the verb's contract.
var ErrInvalidParams = errors.New("invalid params")

// Handle makes a Verb from a typed handler. P is decoded from the call's one
// param (or its zero value when the verb takes none); the result is returned
// as plain maps and slices, which every wire encodes.
func Handle[P, R any](c Contract, fn func(context.Context, P) (R, error)) Verb {
	return Verb{Contract: c, Call: func(ctx context.Context, params []any) (any, error) {
		var p P
		switch {
		case len(params) > 1:
			return nil, fmt.Errorf("%w: %s takes at most one param", ErrInvalidParams, c.Verb)
		case len(params) == 1 && params[0] != nil:
			if err := Decode(params[0], &p); err != nil {
				return nil, fmt.Errorf("%w: %s: %v", ErrInvalidParams, c.Verb, err)
			}
		}
		r, err := fn(ctx, p)
		if err != nil {
			return nil, err
		}
		return Wire(r)
	}}
}

// Decode fills p from a decoded wire value, refusing unknown fields.
func Decode(v any, p any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	return dec.Decode(p)
}

// Wire turns a result into plain maps, slices, strings, numbers and bools.
func Wire(v any) (any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Public finds the public form of err among errs; ok is false for an error no
// module declared, which a host reports as an internal error without detail.
func Public(err error, errs []PublicError) (PublicError, bool) {
	for _, pe := range errs {
		if errors.Is(err, pe.Err) {
			return pe, true
		}
	}
	return PublicError{}, false
}
