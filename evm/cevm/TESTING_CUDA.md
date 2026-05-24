# CUDA box validation checklist

What this PR set ships and what to verify on a Linux + NVIDIA host. Everything
below is locally validated on darwin/arm64; only the CUDA-specific bullets
require the NVIDIA host.

## 0. Prereqs on the CUDA box

- Ubuntu 22.04+ or RHEL 9+
- NVIDIA driver ≥ 535 (`nvidia-smi` works)
- CUDA Toolkit ≥ 12.0 (`nvcc --version`)
- Go ≥ 1.26.3
- CMake ≥ 3.20
- `pkg-config`
- `~/work/lux` and `~/work/lx` and `~/work/luxcpp` checked out at the same
  refs you build from

Set:

```bash
export LUXCPP_PREFIX=$HOME/work/luxcpp/install
export PKG_CONFIG_PATH=$LUXCPP_PREFIX/lib/pkgconfig:$PKG_CONFIG_PATH
export LD_LIBRARY_PATH=$LUXCPP_PREFIX/lib:$LD_LIBRARY_PATH
```

## 1. Build the new luxcpp CUDA targets

```bash
cd ~/work/luxcpp/dex
cmake -S . -B build \
  -DCMAKE_INSTALL_PREFIX=$LUXCPP_PREFIX \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_TESTS=OFF
cmake --build build --target amm_xyk_cuda dex_clob_cuda -j
cmake --install build
```

Expected output:

- `$LUXCPP_PREFIX/lib/libamm_xyk_cuda.a`
- `$LUXCPP_PREFIX/lib/libdex_clob_cuda.a`
- `$LUXCPP_PREFIX/lib/pkgconfig/lux-dex-amm-cuda.pc`
- `$LUXCPP_PREFIX/lib/pkgconfig/lux-dex-clob-cuda.pc`
- `$LUXCPP_PREFIX/include/lux/dex/cuda/amm_xyk_driver.h`
- `$LUXCPP_PREFIX/include/lux/dex/cuda/dex_clob_host.h`
- `$LUXCPP_PREFIX/include/lux/cuda/dex_swap.h`

Sanity:

```bash
pkg-config --cflags --libs lux-dex-amm-cuda
pkg-config --cflags --libs lux-dex-clob-cuda
```

Both should print `-I<...>/include/lux/dex/cuda -L<...>/lib -lamm_xyk_cuda`
and `-I<...>/include -L<...>/lib -ldex_clob_cuda` respectively.

## 2. ABI guards (catch struct drift at compile time)

The new C headers carry `DEX_ABI_ASSERT` (C11 `_Static_assert`) for every
struct size + field offset. If a refactor breaks the ABI, the build fails
here, not at runtime.

```bash
# Triggers asserts; should compile clean.
cc -std=c11 -c -o /tmp/dexabi.o -x c \
  -I$LUXCPP_PREFIX/include \
  -I$LUXCPP_PREFIX/include/lux/dex/cuda \
  - <<'EOF'
#include <lux/cuda/dex_swap.h>
#include "amm_xyk_driver.h"
#include "dex_clob_host.h"
int main(void) { return 0; }
EOF
```

## 3. Go-side build (CUDA + ABI mirror asserts)

```bash
cd ~/work/lx/dex
go build ./pkg/lx/
go vet ./pkg/lx/
```

`init()` in `pkg/lx/orderbook_cuda_types.go` mirrors the C-side
`_Static_assert`s in Go. Any size or offset drift panics at startup.

## 4. CLOB CUDA parity (the headline test)

```bash
cd ~/work/lx/dex
go test -count=1 -v -run TestMatchOrder_GPUMatchesCPU ./pkg/lx/
```

Expected:

- 8/8 subtests PASS
- `MatchOrderGPU` actually dispatches to CUDA (no fallback log)
- Trade list + remaining quantity byte-equal to `MatchOrderCPU` field-by-field
- Book state after match identical on both paths

If parity fails: the kernel produced different output for the same input —
real ABI or numeric bug. Save the failing seed (`t.Run("", ...)` index) and
dump `incoming`, `book`, `indices`.

## 5. AMM CUDA parity

```bash
cd ~/work/lx/dex
go test -count=1 -v -run TestBatchEvalConstantProduct ./pkg/lx/
```

Expected:

- All AMM batch evals byte-equal to the CPU oracle (`mulDiv64`)
- Length-mismatch + degenerate-pool edge cases handled

## 6. Backend probe + fallback observability

```bash
cd ~/work/lx/dex
go test -count=1 -v -run TestProbeSurfacesDisabledAndFallbacks \
  github.com/luxfi/crypto/backend
```

Print the probe live:

```bash
cat > /tmp/probe.go <<'EOF'
package main

import (
    "fmt"
    "github.com/luxfi/crypto/backend"
)

func main() {
    fmt.Println(backend.Probe())
}
EOF
go run /tmp/probe.go
```

Expected (NVIDIA box, CUDA available):

```
backend{default=auto resolved=gpu cgo=true gpu=true gpu_backend=cuda devices=N accel=<ver>}
```

## 7. LUX_GPU_DISABLE kill switch

```bash
cd ~/work/lx/dex

# Default: CUDA path
go run /tmp/probe.go

# Forced CPU
LUX_GPU_DISABLE=1 go run /tmp/probe.go
```

Second run should report `gpu=false disabled=true`. Re-run the parity test
under the kill switch and it must still pass (CPU oracle on both paths).

```bash
LUX_GPU_DISABLE=1 go test -count=1 -v -run TestMatchOrder_GPUMatchesCPU ./pkg/lx/
```

Expected single log line:

```
[crypto/backend] GPU fallback: reason=disabled where=clob
```

## 8. cevm GPU EVM strict mode

The cevm Go EVM fallback is now opt-OUT (strict by default). To verify the
strict policy:

```bash
cd ~/work/lux/chains
go test -count=1 ./evm/cevm/parallel/
```

To re-enable the legacy fallback during V5 transition (emergency rollback):

```bash
LUX_CEVM_STRICT=0 go test -count=1 ./evm/cevm/parallel/
```

V5 kernel work tracked at `chains/evm/cevm/V5_ABI.md`. Until that lands,
strict mode treats any CALL/CREATE block as `ErrGPUEVMRequired` — the lie
of silent Go-EVM shadowing is removed.

## 9. Full sweep (build everything, run everything)

```bash
# crypto layer (under the workspace go.work)
cd ~/work/lux/crypto
go test -count=1 -short ./...

# touched packages
cd ~/work/lux/lattice && go test -count=1 -short ./gpu/
cd ~/work/lux/corona  && go test -count=1 -short ./dkg2/
cd ~/work/lux/fhe     && go test -count=1 -short -run TestNTT .
cd ~/work/lux/chains  && go test -count=1 -short ./evm/cevm/parallel/

# DEX
cd ~/work/lx/dex && go test -count=1 -short ./pkg/lx/ ./pkg/trading/

# V4 DEX precompile e2e integration (7 steps)
cd ~/work/lux/precompile/dex
go test -count=1 -v -run TestIntegrationMultiHopMultiVenue .
```

All should be green. The single permitted failure is
`pulsar/TestAlgebraic_RealRNG_Smokes` — pre-existing, flagged as
"byte-equality pending" in commit `734d7e0`, unrelated to this PR set.

## 10. Bench (optional, NVIDIA-only signal)

```bash
cd ~/work/lx/dex
go test -bench BenchmarkMatchOrder -benchtime=3s -run xxx ./pkg/lx/
```

This is your "did the GPU actually help" sanity check. Expect significant
speedup over CPU for batch sizes ≥ 64; below that the kernel-launch
overhead dominates and CPU wins.

## What to look at if something breaks

| Symptom | Likely cause | First check |
|---|---|---|
| `init()` panic at startup, message mentions `ABI size drifted` | Go struct out of sync with C header | `git diff luxcpp/cuda/include/lux/cuda/dex_swap.h` and `lx/dex/pkg/lx/orderbook_cuda_types.go` |
| `dex_clob_match_order_host rc=-2` log line | CUDA driver not loaded or no device visible | `nvidia-smi`, `ldconfig -p \| grep libcudart` |
| `dex_clob_match_order_host rc=-3` | Device OOM | Reduce `book` size in the failing case; check device free memory |
| `dex_clob_match_order_host rc=-4` | Kernel launch / memcpy failure | Run with `cuda-memcheck`, check `cudaGetLastError` |
| Parity test fails with field mismatch | Kernel actually returned different value than CPU oracle — real bug | Dump `incoming`, `book`, `indices` from the failing seed and run both paths in isolation |
| `pkg-config --cflags lux-dex-clob-cuda` empty | `cmake --install` step skipped | Re-run step 1 |

## What's still on the luxcpp roadmap (not blocking this PR)

- **cevm V5 kernel**: CALL/CREATE on device per `chains/evm/cevm/V5_ABI.md`.
  Without V5, strict-mode cevm refuses any CALL-containing block. Operators
  needing the legacy fallback during the V5 transition set
  `LUX_CEVM_STRICT=0`.
- **Precompile-engine → MatchOrderGPU bridge**: the `lux/precompile/dex`
  engine's matching path uses its own embedded path today. Hooking it to
  `MatchOrderGPU` is one small Go change in `engine_embedded.go::Swap` /
  the CLOB match dispatch — wait for this PR to land + NVIDIA validation
  first.
- **Magnetar threshold SLH-DSA**: separate LP track, see
  `lps/LP-181-magnetar-threshold-slhdsa.md`.
