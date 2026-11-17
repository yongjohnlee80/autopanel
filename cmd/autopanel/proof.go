package main

import jwt "github.com/dgrijalva/jwt-go"

// A call govulncheck knows is vulnerable (GO-2020-0017): the gate must refuse it.
var _ = jwt.MapClaims{}.VerifyAudience("proof", true)
