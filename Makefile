# The VMs that ship a luxd plugin binary, named rather than globbed: this
# directory also holds packages that are libraries (dexvm, fee, ownership,
# internal) and a tool (cmd), and a glob swept those in and stopped the build at
# the first one with no plugin entrypoint.
VMS := aivm bridgevm evm fhevm graphvm identityvm keyvm mpcvm oraclevm quantumvm relayvm schain zkvm

.PHONY: all test clean $(VMS)

all: $(VMS)

# evm has main.go at root; all other VMs ship their plugin under cmd/plugin.
$(VMS):
	@if [ -f $@/main.go ]; then \
		go build -trimpath -ldflags="-s -w" -o build/$@ ./$@; \
	else \
		go build -trimpath -ldflags="-s -w" -o build/$@ ./$@/cmd/plugin; \
	fi

test:
	go test ./...

clean:
	rm -rf build/
