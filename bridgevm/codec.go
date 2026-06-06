// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridgevm

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
		lc.RegisterType(&BridgeRequest{}),
		lc.RegisterType(&Block{}),
		lc.RegisterType(&Genesis{}),
		Codec.RegisterCodec(codecVersion, lc),
	)
	if err != nil {
		panic(err)
	}
}
