VMS := $(shell ls -d */ 2>/dev/null | sed 's|/||' | grep -v '.github\|build\|node_modules')

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
