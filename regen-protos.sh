#!/usr/bin/env sh
# Regenerate Python protobuf modules from the .proto files under
# pyhindsight/lib/components/. Output lands in pyhindsight/lib/proto/components/
# (mirroring the source tree layout).
#
# Usage: ./regen-protos.sh
# Requires: pip install --group dev  (grpcio-tools, pinned in pyproject.toml)
set -e

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
SRC_ROOT="$REPO_ROOT/pyhindsight/lib"
OUT_ROOT="$SRC_ROOT/proto"

# .proto sources live at chromium-mirrored top-level paths under
# pyhindsight/lib/ (e.g. components/sync/protocol/, content/browser/devtools/).
# The corresponding _pb2.py modules land at the same path under lib/proto/.
SRC_TOP_DIRS="components content"

# Wipe previously-generated outputs so deletions in the source tree propagate.
for d in $SRC_TOP_DIRS; do
  rm -rf "$OUT_ROOT/$d"
done
mkdir -p "$OUT_ROOT"

# Preserve the package shim that aliases each chromium-mirrored top-level
# package so cross-file imports inside the generated _pb2.py files resolve.
{
  echo '# Package marker for generated protobuf modules.'
  echo '#'
  echo '# The generated code imports each top-level chromium-mirrored package'
  echo '# (`components.*`, `content.*`, ...) as if it were a top-level package.'
  echo '# When importing via `pyhindsight.lib.proto`, alias each one so those'
  echo '# imports resolve without requiring real top-level packages.'
  echo 'import sys as _sys'
  echo
  for d in $SRC_TOP_DIRS; do
    echo "from . import $d as _$d"
    echo "_sys.modules.setdefault(\"$d\", _$d)"
  done
} > "$OUT_ROOT/__init__.py"

PROTOS=""
for d in $SRC_TOP_DIRS; do
  if [ -d "$SRC_ROOT/$d" ]; then
    found=$(find "$SRC_ROOT/$d" -name "*.proto")
    PROTOS="$PROTOS $found"
  fi
done
PROTOS=$(echo $PROTOS)
if [ -z "$PROTOS" ]; then
  echo "No .proto files found under $SRC_ROOT/{$(echo $SRC_TOP_DIRS | tr ' ' ',')}" >&2
  exit 1
fi

python -m grpc_tools.protoc --python_out="$OUT_ROOT" -I "$SRC_ROOT" $PROTOS

echo "Generated $(echo $PROTOS | wc -w | tr -d ' ') _pb2.py files into $OUT_ROOT/{$(echo $SRC_TOP_DIRS | tr ' ' ',')}/"
