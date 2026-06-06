// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zkvm

import (
	"errors"

	"github.com/luxfi/node/vms/pcodecs"
)

const codecVersion = 0

var Codec pcodecs.Manager

func init() {
	Codec = pcodecs.NewMaxIntManager()
	lc := pcodecs.NewLinearCodec()

	err := errors.Join(
		lc.RegisterType(&Transaction{}),
		lc.RegisterType(&Block{}),
		lc.RegisterType(&UTXO{}),
		lc.RegisterType(&Genesis{}),
		lc.RegisterType(&ZConfig{}),
		Codec.RegisterCodec(codecVersion, lc),
	)
	if err != nil {
		panic(err)
	}
}
