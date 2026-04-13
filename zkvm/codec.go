// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zkvm

import (
	"errors"
	"math"

	"github.com/luxfi/codec"
	"github.com/luxfi/codec/linearcodec"
)

const codecVersion = 0

var Codec codec.Manager

func init() {
	Codec = codec.NewManager(math.MaxInt)
	lc := linearcodec.NewDefault()

	err := errors.Join(
		// Register ZVM-specific types
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
