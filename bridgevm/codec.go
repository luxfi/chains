// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridgevm

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
		// Register BVM-specific types
		lc.RegisterType(&BridgeRequest{}),
		lc.RegisterType(&Block{}),
		lc.RegisterType(&Genesis{}),
		Codec.RegisterCodec(codecVersion, lc),
	)
	if err != nil {
		panic(err)
	}
}
