#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

package_name="sts-cli"
version="$(grep -m1 '^version = ' Cargo.toml | sed -E 's/version = "([^"]+)"/\1/')"
target_triple="${TARGET_TRIPLE:-$(rustc -vV | awk '/host:/ {print $2}')}"
archive_base="${package_name}-${version}-${target_triple}"
dist_dir="$repo_root/dist"
stage_dir="$dist_dir/$archive_base"
binary="$repo_root/target/release/$package_name"

case "$(uname -s)" in
  Darwin|Linux) ;;
  *)
    echo "unsupported host OS for local packaging: $(uname -s)" >&2
    exit 2
    ;;
esac

rm -rf "$stage_dir"
mkdir -p "$stage_dir"

cargo build --release -p "$package_name"
"$binary" --help >/dev/null

if "$binary" smoke >/tmp/sts-cli-package-smoke.log 2>&1; then
  smoke_status="pass"
else
  if grep -q "offline smoke requires IDP_JWKS_FILE" /tmp/sts-cli-package-smoke.log; then
    smoke_status="skipped: offline smoke requires runtime IDP_JWKS_FILE"
  else
    cat /tmp/sts-cli-package-smoke.log >&2
    exit 1
  fi
fi

cp "$binary" "$stage_dir/$package_name"
cp README.md "$stage_dir/README.md"
if [[ -f LICENSE ]]; then
  cp LICENSE "$stage_dir/LICENSE"
fi

cat > "$stage_dir/INSTALL.md" <<EOF
# sts-cli local archive

Build source: sts-delegate-rs
Version: $version
Target: $target_triple
Smoke: $smoke_status

## Install

\`\`\`bash
install -m 0755 sts-cli ~/.local/bin/sts-cli
sts-cli --help
\`\`\`

The server still requires runtime configuration for IdP issuer, actor JWKS,
target policy, and STS signing key before \`sts-cli serve\` can start.
EOF

archive="$dist_dir/$archive_base.tar.gz"
rm -f "$archive"
tar -C "$dist_dir" -czf "$archive" "$archive_base"

(
  cd "$repo_root"
  shasum -a 256 "dist/$(basename "$archive")" > "$dist_dir/SHA256SUMS"
)

echo "archive=$archive"
echo "checksums=$dist_dir/SHA256SUMS"
echo "smoke=$smoke_status"
