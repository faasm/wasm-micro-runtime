# Checkpoint-Restore for WASM modules with WAMR

This repository contains a proof-of-concept implementation of a library to
provide checkpoint-restore functionality to WebAssembly modules running on
WAMR.

## Build

The recommended build environment is using our development docker image:

```bash
docker run \
  --rm -it \
  -v $(pwd):/workspace/product-mini/platforms/linux-cr \
  --working-dir /workspace/product-mini/platforms/linux-cr \
  csegarragonz/wasm-micro-runtime:main \
  bash
```

Inside the container, you may run:

```bash
# Build iwasm-cr executable
./bin/build.sh [--clean]

# Build WASM apps
./bin/build_wasm.sh
```

## Run the demo

TODO: demo not working
