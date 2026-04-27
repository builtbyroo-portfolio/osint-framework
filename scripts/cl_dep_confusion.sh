#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  cl_dep_confusion.sh — Dependency Confusion Check              ║
# ║  Manifest discovery · Package name extraction                  ║
# ║  Public registry claimability check (npm/PyPI/RubyGems)       ║
# ╚══════════════════════════════════════════════════════════════╝
set -uo pipefail

SCRIPT_NAME="cl_dep_confusion.sh"
SCRIPT_DESC="Dependency Confusion Check"

script_usage() {
    echo "Usage: ${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo "  Discover exposed package manifests and check if private-looking"
    echo "  packages are claimable on public registries (npm, PyPI, RubyGems)."
    echo "  Dependency confusion = CRITICAL (supply chain attack vector)."
    echo ""
    echo "Options:"
    echo "  -d, --domain DOMAIN    Target domain"
    echo "  --domains FILE         File with domains (one per line)"
    echo "  -u, --urls FILE        File with URLs (one per line)"
    echo "  -o, --out DIR          Output directory (default: ./out)"
    echo "  -t, --threads N        Concurrency (default: 30)"
    echo "  --keyword KEYWORD      Keyword for bucket/resource name generation"
    echo "  -h, --help             Show this help"
}

LIB_DIR="$(cd "$(dirname "$0")/.." && pwd)"
source "${LIB_DIR}/lib.sh"
parse_common_args "$@"

phase_header "6" "$SCRIPT_DESC"

if [ -z "${DOMAIN:-}" ] && [ -z "${DOMAINS_FILE:-}" ] && [ -z "${URLS_FILE:-}" ]; then
    err "Provide --domain, --domains, or --urls"
    script_usage
    exit 1
fi

# ── Tool checks ──
check_tool curl 2>/dev/null || { err "curl is required"; exit 1; }

# ── Output files ──
DEP_FINDINGS="${OUT_DIR}/cl_dep_confusion_findings.txt"
MANIFESTS_FILE="${OUT_DIR}/cl_manifests.txt"
> "$DEP_FINDINGS"
> "$MANIFESTS_FILE"

# ── Derive keyword for org-specific package detection ──
if [ -z "${KEYWORD:-}" ] && [ -n "${DOMAIN:-}" ]; then
    KEYWORD=$(echo "$DOMAIN" | sed -E 's/\.(com|net|org|io|co|dev|app|cloud|xyz|info|biz)$//;s/\.[^.]*$//')
fi

# ── Severity tag helper ──
tag_finding() {
    local sev="$1" url="$2" desc="$3"
    echo "[${sev}] ${url} — ${desc}" >> "$DEP_FINDINGS"
    log "  [${sev}] ${url} — ${desc}"
}

# ── Probe helpers ──
probe_url() {
    local url="$1"
    curl -sk -o /dev/null -w "%{http_code} %{size_download}" \
        --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" "$url" 2>/dev/null || echo "000 0"
}

probe_body() {
    local url="$1"
    curl -sk --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" "$url" 2>/dev/null || echo ""
}

# ── Build target list ──
targets=()
if [ -n "${DOMAINS_FILE:-}" ] && [ -f "$DOMAINS_FILE" ]; then
    while IFS= read -r d; do
        d=$(echo "$d" | sed 's/\*\.//')
        [ -n "$d" ] && targets+=("$d")
    done < "$DOMAINS_FILE"
elif [ -n "${DOMAIN:-}" ]; then
    targets+=("$DOMAIN")
fi

# ── Manifest paths to probe ──
# Format: "path|type|description"
MANIFEST_PATHS=(
    "package.json|npm|Node.js package manifest"
    "package-lock.json|npm|Node.js lockfile"
    "yarn.lock|npm|Yarn lockfile"
    "npm-shrinkwrap.json|npm|npm shrinkwrap"
    "requirements.txt|pypi|Python requirements"
    "Pipfile|pypi|Pipenv Pipfile"
    "Pipfile.lock|pypi|Pipenv lockfile"
    "setup.py|pypi|Python setup.py"
    "setup.cfg|pypi|Python setup.cfg"
    "pyproject.toml|pypi|Python pyproject.toml"
    "Gemfile|rubygems|Ruby Gemfile"
    "Gemfile.lock|rubygems|Ruby Gemfile lockfile"
    "go.mod|go|Go module file"
    "go.sum|go|Go checksum file"
    "composer.json|packagist|PHP Composer manifest"
    "composer.lock|packagist|PHP Composer lockfile"
    "pom.xml|maven|Java Maven POM"
    "build.gradle|gradle|Java Gradle build"
    "build.gradle.kts|gradle|Kotlin Gradle build"
    "Cargo.toml|crates|Rust Cargo manifest"
    "Cargo.lock|crates|Rust Cargo lockfile"
    ".npmrc|npm|npm config (may contain registry URL)"
    ".yarnrc|npm|Yarn config"
    ".yarnrc.yml|npm|Yarn v2 config"
)

# ════════════════════════════════════════════════════════════════
# STEP 1: Discover exposed manifest files
# ════════════════════════════════════════════════════════════════
info "Step 1: Probing for exposed manifest files..."

manifest_hits=0
for domain in "${targets[@]}"; do
    for scheme in "https" "http"; do
        base_url="${scheme}://${domain}"

        # Quick connectivity check
        base_status=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 5 --max-time 8 "${HUNT_UA_CURL[@]}" "$base_url" 2>/dev/null || echo "000")
        [ "$base_status" = "000" ] && continue

        for entry in "${MANIFEST_PATHS[@]}"; do
            path=$(echo "$entry" | cut -d'|' -f1)
            pkg_type=$(echo "$entry" | cut -d'|' -f2)
            desc=$(echo "$entry" | cut -d'|' -f3)

            test_url="${base_url}/${path}"
            result=$(probe_url "$test_url")
            status=$(echo "$result" | awk '{print $1}')
            size=$(echo "$result" | awk '{print $2}')

            if [ "$status" = "200" ] && [ "${size%.*}" -gt 50 ] 2>/dev/null; then
                # Validate it's actually a manifest and not a custom error page
                body=$(probe_body "$test_url")
                is_valid=false

                case "$path" in
                    package.json|package-lock.json|npm-shrinkwrap.json|composer.json|composer.lock)
                        echo "$body" | grep -qP '^\s*\{' && is_valid=true
                        ;;
                    requirements.txt)
                        echo "$body" | grep -qP '^[a-zA-Z0-9_-]+[=><!]' && is_valid=true
                        ;;
                    Pipfile|pyproject.toml|Cargo.toml|setup.cfg|.yarnrc.yml)
                        echo "$body" | grep -qP '^\[|^\[packages\]|^\[tool\.|^\[dependencies\]|^\[build-system\]|^nodeLinker' && is_valid=true
                        ;;
                    setup.py)
                        echo "$body" | grep -qP 'install_requires|setup\(' && is_valid=true
                        ;;
                    Gemfile|Gemfile.lock)
                        echo "$body" | grep -qP '^source |^gem |^GEM$|^BUNDLED WITH' && is_valid=true
                        ;;
                    go.mod)
                        echo "$body" | grep -qP '^module |^require ' && is_valid=true
                        ;;
                    go.sum)
                        echo "$body" | grep -qP '^[a-zA-Z0-9./]+ v[0-9]' && is_valid=true
                        ;;
                    pom.xml)
                        echo "$body" | grep -q '<project\|<dependency>' && is_valid=true
                        ;;
                    build.gradle|build.gradle.kts)
                        echo "$body" | grep -qP 'dependencies\s*\{|implementation |compile ' && is_valid=true
                        ;;
                    Cargo.lock)
                        echo "$body" | grep -q '^\[\[package\]\]' && is_valid=true
                        ;;
                    yarn.lock)
                        echo "$body" | grep -qP '^# THIS IS AN AUTOGENERATED|^"?[a-zA-Z@]' && is_valid=true
                        ;;
                    .npmrc)
                        echo "$body" | grep -qP 'registry=|//.*:_authToken|always-auth' && is_valid=true
                        ;;
                    .yarnrc)
                        echo "$body" | grep -qP 'registry |npmRegistryServer' && is_valid=true
                        ;;
                esac

                if $is_valid; then
                    ((manifest_hits++)) || true
                    echo "${test_url}|${pkg_type}|${size}" >> "$MANIFESTS_FILE"
                    tag_finding "HIGH" "$test_url" "Exposed ${desc} (${size}B)"

                    # Check .npmrc for auth tokens
                    if [ "$path" = ".npmrc" ]; then
                        if echo "$body" | grep -qP '_authToken|_password|always-auth'; then
                            tag_finding "CRITICAL" "$test_url" "npmrc with auth tokens/credentials exposed"
                        fi
                        # Check for private registry URL (useful for dep confusion)
                        priv_registry=$(echo "$body" | grep -oP 'registry=\K[^\s]+' | head -1)
                        if [ -n "$priv_registry" ] && ! echo "$priv_registry" | grep -qP 'registry\.npmjs\.org'; then
                            tag_finding "HIGH" "$test_url" "Private npm registry: ${priv_registry}"
                        fi
                    fi
                fi
            fi
        done

        break  # Use first working scheme
    done
done

log "  Manifest discovery: ${manifest_hits} exposed manifests"

# ════════════════════════════════════════════════════════════════
# STEP 2: Extract package names from discovered manifests
# ════════════════════════════════════════════════════════════════
info "Step 2: Extracting package names from manifests..."

packages_file="${OUT_DIR}/_cl_packages.txt"
> "$packages_file"

while IFS='|' read -r manifest_url pkg_type size; do
    [ -z "$manifest_url" ] && continue
    body=$(probe_body "$manifest_url")
    [ -z "$body" ] && continue

    case "$pkg_type" in
        npm)
            # Extract dependencies from package.json
            python3 -c "
import json, sys
try:
    data = json.loads(sys.stdin.read())
    deps = {}
    for key in ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']:
        deps.update(data.get(key, {}))
    for pkg in deps:
        print(f'npm|{pkg}')
except: pass
" <<< "$body" 2>/dev/null >> "$packages_file" || true
            ;;
        pypi)
            # Extract from requirements.txt
            if echo "$manifest_url" | grep -q 'requirements.txt'; then
                echo "$body" | grep -oP '^[a-zA-Z0-9_][a-zA-Z0-9._-]*' 2>/dev/null | while IFS= read -r pkg; do
                    echo "pypi|${pkg}"
                done >> "$packages_file" || true
            fi
            # Extract from Pipfile
            if echo "$manifest_url" | grep -q 'Pipfile'; then
                echo "$body" | grep -oP '^\s*[a-zA-Z0-9_][a-zA-Z0-9._-]*(?=\s*=)' 2>/dev/null | sed 's/^\s*//' | while IFS= read -r pkg; do
                    echo "pypi|${pkg}"
                done >> "$packages_file" || true
            fi
            # Extract from setup.py
            if echo "$manifest_url" | grep -q 'setup.py'; then
                echo "$body" | grep -oP "'[a-zA-Z0-9_][a-zA-Z0-9._-]*'" 2>/dev/null | tr -d "'" | while IFS= read -r pkg; do
                    echo "pypi|${pkg}"
                done >> "$packages_file" || true
            fi
            ;;
        rubygems)
            # Extract from Gemfile
            echo "$body" | grep -oP "^gem\s+['\"]?\K[a-zA-Z0-9_][a-zA-Z0-9._-]*" 2>/dev/null | while IFS= read -r pkg; do
                echo "rubygems|${pkg}"
            done >> "$packages_file" || true
            ;;
        packagist)
            # Extract from composer.json
            python3 -c "
import json, sys
try:
    data = json.loads(sys.stdin.read())
    for key in ['require', 'require-dev']:
        for pkg in data.get(key, {}):
            print(f'packagist|{pkg}')
except: pass
" <<< "$body" 2>/dev/null >> "$packages_file" || true
            ;;
        go)
            # Extract from go.mod
            if echo "$manifest_url" | grep -q 'go.mod'; then
                echo "$body" | grep -oP '^\s+\K[a-zA-Z0-9./]+(?=\s+v)' 2>/dev/null | while IFS= read -r pkg; do
                    echo "go|${pkg}"
                done >> "$packages_file" || true
            fi
            ;;
    esac
done < "$MANIFESTS_FILE"

sort -u -o "$packages_file" "$packages_file" 2>/dev/null || true
pkg_count=$(count_lines "$packages_file")
log "  Extracted ${pkg_count} unique package names"

# ════════════════════════════════════════════════════════════════
# STEP 3: Filter for org-specific / private-looking packages
# ════════════════════════════════════════════════════════════════
info "Step 3: Filtering for organization-specific package names..."

private_pkgs="${OUT_DIR}/_cl_private_pkgs.txt"
> "$private_pkgs"

# Common public package prefixes to EXCLUDE
PUBLIC_PREFIXES="^(lodash|express|react|angular|vue|jquery|moment|axios|webpack|babel|eslint|prettier|typescript|next|gatsby|nuxt|tailwind|bootstrap|socket|aws-sdk|googleapis|azure|@types|@babel|@emotion|@mui|@chakra|@reduxjs|@testing-library)"

while IFS='|' read -r registry pkg; do
    [ -z "$pkg" ] && continue

    # Skip well-known public packages
    echo "$pkg" | grep -qP "$PUBLIC_PREFIXES" && continue

    # Check for org-specific indicators
    is_private=false

    # Scoped npm packages with org name
    if [ "$registry" = "npm" ] && echo "$pkg" | grep -qP '^@'; then
        # Scoped packages are often private
        is_private=true
    fi

    # Package contains keyword/company name
    if [ -n "${KEYWORD:-}" ] && echo "$pkg" | grep -qi "$KEYWORD"; then
        is_private=true
    fi

    # Package has internal-sounding names
    if echo "$pkg" | grep -qiP '(internal|private|corp|company|enterprise|custom|proprietary|core-lib|shared-lib|common-lib|platform-|service-)'; then
        is_private=true
    fi

    if $is_private; then
        echo "${registry}|${pkg}" >> "$private_pkgs"
    fi
done < "$packages_file"

sort -u -o "$private_pkgs" "$private_pkgs" 2>/dev/null || true
private_count=$(count_lines "$private_pkgs")
log "  Found ${private_count} potentially private/org-specific packages"

# ════════════════════════════════════════════════════════════════
# STEP 4: Check public registry for claimable packages
# ════════════════════════════════════════════════════════════════
info "Step 4: Checking public registries for claimable packages..."

claimable=0
while IFS='|' read -r registry pkg; do
    [ -z "$pkg" ] && continue

    case "$registry" in
        npm)
            # Check npm registry
            npm_url="https://registry.npmjs.org/${pkg}"
            npm_status=$(curl -sk -o /dev/null -w "%{http_code}" \
                --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
                "$npm_url" 2>/dev/null || echo "000")

            if [ "$npm_status" = "404" ]; then
                ((claimable++)) || true
                tag_finding "CRITICAL" "$npm_url" "DEPENDENCY CONFUSION — npm package '${pkg}' is CLAIMABLE (404 on registry)"
            elif [ "$npm_status" = "200" ]; then
                # Package exists — check if it's a placeholder or very low download count
                info "  npm '${pkg}': exists on registry"
            fi
            ;;

        pypi)
            # Check PyPI
            pypi_url="https://pypi.org/pypi/${pkg}/json"
            pypi_status=$(curl -sk -o /dev/null -w "%{http_code}" \
                --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
                "$pypi_url" 2>/dev/null || echo "000")

            if [ "$pypi_status" = "404" ]; then
                ((claimable++)) || true
                tag_finding "CRITICAL" "$pypi_url" "DEPENDENCY CONFUSION — PyPI package '${pkg}' is CLAIMABLE (404 on registry)"
            elif [ "$pypi_status" = "200" ]; then
                info "  PyPI '${pkg}': exists on registry"
            fi
            ;;

        rubygems)
            # Check RubyGems
            gem_url="https://rubygems.org/api/v1/gems/${pkg}.json"
            gem_status=$(curl -sk -o /dev/null -w "%{http_code}" \
                --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
                "$gem_url" 2>/dev/null || echo "000")

            if [ "$gem_status" = "404" ]; then
                ((claimable++)) || true
                tag_finding "CRITICAL" "$gem_url" "DEPENDENCY CONFUSION — RubyGem '${pkg}' is CLAIMABLE (404 on registry)"
            elif [ "$gem_status" = "200" ]; then
                info "  RubyGem '${pkg}': exists on registry"
            fi
            ;;

        packagist)
            # Check Packagist
            # Packagist requires vendor/package format
            if echo "$pkg" | grep -q '/'; then
                packagist_url="https://repo.packagist.org/p2/${pkg}.json"
                pack_status=$(curl -sk -o /dev/null -w "%{http_code}" \
                    --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
                    "$packagist_url" 2>/dev/null || echo "000")

                if [ "$pack_status" = "404" ]; then
                    ((claimable++)) || true
                    tag_finding "CRITICAL" "$packagist_url" "DEPENDENCY CONFUSION — Packagist '${pkg}' is CLAIMABLE (404)"
                fi
            fi
            ;;

        go)
            # Go modules are typically hosted on source repos, harder to claim
            # Check pkg.go.dev for existence
            go_url="https://pkg.go.dev/${pkg}"
            go_status=$(curl -sk -o /dev/null -w "%{http_code}" \
                --connect-timeout 8 --max-time 15 "${HUNT_UA_CURL[@]}" \
                "$go_url" 2>/dev/null || echo "000")

            if [ "$go_status" = "404" ]; then
                tag_finding "HIGH" "$go_url" "Go module '${pkg}' not found on pkg.go.dev — check source repo"
            fi
            ;;
    esac

    # Rate limiting — don't hammer public registries
    sleep 0.3
done < "$private_pkgs"

log "  Claimable packages: ${claimable}"

# ════════════════════════════════════════════════════════════════
# STEP 5: Check for .npmrc / pip.conf registry misconfig
# ════════════════════════════════════════════════════════════════
info "Step 5: Checking for registry configuration leaks..."

registry_leaks=0
for domain in "${targets[@]}"; do
    for scheme in "https" "http"; do
        base_url="${scheme}://${domain}"
        base_status=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 5 --max-time 8 "${HUNT_UA_CURL[@]}" "$base_url" 2>/dev/null || echo "000")
        [ "$base_status" = "000" ] && continue

        # Check pip.conf
        for conf_path in "pip.conf" ".pip/pip.conf" "pip/pip.conf"; do
            conf_url="${base_url}/${conf_path}"
            result=$(probe_url "$conf_url")
            status=$(echo "$result" | awk '{print $1}')
            size=$(echo "$result" | awk '{print $2}')

            if [ "$status" = "200" ] && [ "${size%.*}" -gt 10 ] 2>/dev/null; then
                body=$(probe_body "$conf_url")
                if echo "$body" | grep -qP 'index-url|extra-index-url|trusted-host'; then
                    ((registry_leaks++)) || true
                    tag_finding "HIGH" "$conf_url" "pip.conf exposed — private PyPI registry configuration"
                    # Extract registry URL
                    priv_index=$(echo "$body" | grep -oP '(index-url|extra-index-url)\s*=\s*\K\S+' | head -1)
                    if [ -n "$priv_index" ]; then
                        tag_finding "HIGH" "$conf_url" "Private PyPI index: ${priv_index}"
                    fi
                fi
            fi
        done

        # Check .gemrc
        gemrc_url="${base_url}/.gemrc"
        result=$(probe_url "$gemrc_url")
        status=$(echo "$result" | awk '{print $1}')
        size=$(echo "$result" | awk '{print $2}')

        if [ "$status" = "200" ] && [ "${size%.*}" -gt 10 ] 2>/dev/null; then
            body=$(probe_body "$gemrc_url")
            if echo "$body" | grep -qP 'sources:|gem_sources'; then
                ((registry_leaks++)) || true
                tag_finding "HIGH" "$gemrc_url" ".gemrc exposed — Ruby gem source configuration"
            fi
        fi

        break  # Use first working scheme
    done
done

log "  Registry config leaks: ${registry_leaks}"

# ── Cleanup ──
rm -f "$packages_file" "$private_pkgs"

# ── Dedup output ──
for f in "$DEP_FINDINGS" "$MANIFESTS_FILE"; do
    [ -f "$f" ] && sort -u -o "$f" "$f" 2>/dev/null || true
done

# ── Summary ──
total_findings=$(count_lines "$DEP_FINDINGS")
manifest_count=$(count_lines "$MANIFESTS_FILE")
critical_count=$(grep -c '^\[CRITICAL\]' "$DEP_FINDINGS" 2>/dev/null || echo 0)
high_count=$(grep -c '^\[HIGH\]' "$DEP_FINDINGS" 2>/dev/null || echo 0)

log "Dependency confusion check complete:"
log "  Total findings:       ${total_findings}"
log "    CRITICAL:           ${critical_count}"
log "    HIGH:               ${high_count}"
log "  Exposed manifests:    ${manifest_count}"
log "  Claimable packages:   ${claimable}"
log "  Output: ${DEP_FINDINGS}"
log "  Output: ${MANIFESTS_FILE}"
