// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package codec speaks the JSON-RPC spelling this repo's VMs serve. A client
// names a method as class.function with a lower-case initial, and the codec
// hands the server the exported Go method that answers it, so
// quantumvm.getBlock reaches Service.GetBlock.
//
// A function whose initial is already upper-case is refused, so exactly one
// spelling reaches a service.
package codec

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/gorilla/rpc/v2"
	"github.com/gorilla/rpc/v2/json2"
)

var (
	errUppercaseMethod = errors.New("method must start with a non-uppercase letter")
	errInvalidArg      = errors.New("couldn't unmarshal an argument. Ensure arguments are valid and properly formatted. See documentation for example calls")
)

// New returns a JSON-RPC codec that raises the initial of the function named
// after the dot.
func New() rpc.Codec {
	return codec{json2.NewCodec()}
}

type codec struct{ *json2.Codec }

func (c codec) NewRequest(r *http.Request) rpc.CodecRequest {
	return &request{c.Codec.NewRequest(r).(*json2.CodecRequest)}
}

type request struct{ *json2.CodecRequest }

// Method names the Go method the request asks for: the class unchanged, and
// the function with its initial raised. A name carrying no dot, or one whose
// initial is not a rune, is passed through as it arrived.
func (r *request) Method() (string, error) {
	method, err := r.CodecRequest.Method()
	parts := strings.SplitN(method, ".", 2)
	if len(parts) != 2 || err != nil {
		return method, err
	}
	class, function := parts[0], parts[1]
	initial, size := utf8.DecodeRuneInString(function)
	if initial == utf8.RuneError {
		return method, nil
	}
	if unicode.IsUpper(initial) {
		return method, errUppercaseMethod
	}
	raised := string(unicode.ToUpper(initial))
	return fmt.Sprintf("%s.%s%s", class, raised, function[size:]), nil
}

// ReadRequest reports one message for arguments it cannot read, so a caller
// learns its arguments are wrong and nothing further.
func (r *request) ReadRequest(args any) error {
	if err := r.CodecRequest.ReadRequest(args); err != nil {
		return errInvalidArg
	}
	return nil
}
