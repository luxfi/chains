// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package thresholdvm

import (
	"github.com/luxfi/node/vms/pcodecs"
)

const codecVersion = 0

// Codec is the codec for the threshold VM
var Codec pcodecs.Manager

func init() {
	c := pcodecs.NewLinearCodec()

	c.RegisterType(&Block{})
	c.RegisterType(&Operation{})
	c.RegisterType(&Genesis{})
	c.RegisterType(&ManagedKey{})
	c.RegisterType(&KeygenSession{})
	c.RegisterType(&SigningSession{})
	c.RegisterType(&ecdsaSignature{})
	c.RegisterType(&ThresholdConfig{})
	c.RegisterType(&ChainPermissions{})
	c.RegisterType(&ProtocolOptions{})
	c.RegisterType(&CrossChainMPCRequest{})

	Codec = pcodecs.NewDefaultManager()
	if err := Codec.RegisterCodec(codecVersion, c); err != nil {
		panic(err)
	}
}
