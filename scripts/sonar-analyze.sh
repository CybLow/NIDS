#!/usr/bin/env bash
# sonar-analyze.sh — Run static analysis, optional coverage, and upload to SonarQube
#
# Usage:
#   ./scripts/sonar-analyze.sh                  # cppcheck + sonar scan (no coverage)
#   ./scripts/sonar-analyze.sh --with-coverage   # build with coverage, test, generate
#                                                # Cobertura XML, then cppcheck + scan
#   ./scripts/sonar-analyze.sh --cppcheck-only   # cppcheck only
#   ./scripts/sonar-analyze.sh --scan-only       # sonar scan only
#   ./scripts/sonar-analyze.sh --coverage-only   # coverage build + Cobertura XML only
#
# Prerequisites:
#   - Podman (rootless) running with socket enabled
#   - SonarQube 26.3+ running at localhost:9000
#   - sonar-cxx plugin installed
#   - For non-coverage modes: cmake-build-debug/compile_commands.json must exist
#   - For coverage: gcc, gcovr (pip install gcovr), cmake, ninja or make
#
# Environment:
#   SONAR_TOKEN  — SonarQube authentication token (required for scan)
#   SONAR_URL    — SonarQube server URL (default: http://localhost:9000)
#   CC           — C compiler for coverage build (default: gcc)
#   CXX          — C++ compiler for coverage build (default: g++)

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SONAR_URL="${SONAR_URL:-http://localhost:9000}"
COVERAGE_BUILD_DIR="${PROJECT_ROOT}/cmake-build-coverage"
COBERTURA_XML="${PROJECT_ROOT}/coverage-cobertura.xml"

require_sonar_token() {
    if [[ -z "${SONAR_TOKEN:-}" ]]; then
        echo "ERROR: SONAR_TOKEN environment variable is required"
        echo "  export SONAR_TOKEN=squ_..."
        exit 1
    fi
}

run_cppcheck() {
    echo "=== Running cppcheck ==="
    local cppcheck_version
    cppcheck_version="$(cppcheck --version 2>/dev/null || echo 'unknown')"
    echo "  Version: ${cppcheck_version}"

    cppcheck --xml --xml-version=2 \
        --enable=all \
        --suppress=missingInclude \
        --suppress=missingIncludeSystem \
        --suppress=unusedFunction \
        --suppress=unusedStructMember \
        --suppress=unknownMacro \
        --inline-suppr \
        --std=c++20 \
        --language=c++ \
        -I "${PROJECT_ROOT}/src" \
        "${PROJECT_ROOT}/src/" 2> "${PROJECT_ROOT}/cppcheck-report.xml"

    echo "  Report: ${PROJECT_ROOT}/cppcheck-report.xml"
    python3 -c "
import xml.etree.ElementTree as ET
tree = ET.parse('${PROJECT_ROOT}/cppcheck-report.xml')
errors = [e for e in tree.findall('.//error') if e.get('severity') != 'information']
print(f'  Found {len(errors)} issue(s) (excluding information)')
for e in errors[:10]:
    loc = e.find('location')
    f = loc.get('file', '?') if loc is not None else '?'
    line = loc.get('line', '?') if loc is not None else '?'
    print(f'    {e.get(\"severity\")}: {e.get(\"msg\")} [{f}:{line}]')
if len(errors) > 10:
    print(f'    ... and {len(errors) - 10} more')
" 2>/dev/null || echo "  (install python3 to see issue count)"
}

run_coverage() {
    echo "=== Building with coverage instrumentation ==="
    local cc="${CC:-gcc}"
    local cxx="${CXX:-g++}"

    cmake -B "${COVERAGE_BUILD_DIR}" -S "${PROJECT_ROOT}" \
        -DCMAKE_BUILD_TYPE=Debug \
        -DCMAKE_C_COMPILER="${cc}" \
        -DCMAKE_CXX_COMPILER="${cxx}" \
        -DNIDS_BUILD_TESTS=ON \
        -DNIDS_COVERAGE=ON

    echo "=== Building ==="
    cmake --build "${COVERAGE_BUILD_DIR}" -j"$(nproc)"

    echo "=== Running tests ==="
    ctest --test-dir "${COVERAGE_BUILD_DIR}" --output-on-failure --timeout 120

    echo "=== Generating Cobertura XML via gcovr ==="
    gcovr --root "${PROJECT_ROOT}" \
        "${COVERAGE_BUILD_DIR}" \
        --cobertura "${COBERTURA_XML}" \
        --exclude-unreachable-branches \
        --exclude-throw-branches \
        --filter 'src/'

    # Fix source path so sonar-scanner (running inside container at /usr/src) resolves
    # file paths correctly. Replace absolute <source> path with relative ".".
    sed -i 's|<source>[^<]*</source>|<source>.</source>|g' "${COBERTURA_XML}"

    echo "  Cobertura report: ${COBERTURA_XML}"
    python3 -c "
import xml.etree.ElementTree as ET
tree = ET.parse('${COBERTURA_XML}')
root = tree.getroot()
line_rate = float(root.get('line-rate', 0)) * 100
branch_rate = float(root.get('branch-rate', 0)) * 100
print(f'  Line coverage:   {line_rate:.1f}%')
print(f'  Branch coverage: {branch_rate:.1f}%')
" 2>/dev/null || echo "  (install python3 to see coverage summary)"
}

run_scanner() {
    require_sonar_token
    echo "=== Running SonarQube scanner ==="
    podman run --rm --network=host --security-opt label=disable \
        -e SONAR_HOST_URL="${SONAR_URL}" \
        -e SONAR_TOKEN="${SONAR_TOKEN}" \
        -e SONAR_SCANNER_OPTS="-Dsonar.scm.disabled=true" \
        -v "${PROJECT_ROOT}:/usr/src" \
        docker.io/sonarsource/sonar-scanner-cli:latest

    echo ""
    echo "=== Analysis complete ==="
    echo "  Dashboard: ${SONAR_URL}/dashboard?id=nids"
}

case "${1:-all}" in
    --cppcheck-only)
        run_cppcheck
        ;;
    --scan-only)
        require_sonar_token
        run_scanner
        ;;
    --coverage-only)
        run_coverage
        ;;
    --with-coverage)
        run_coverage
        echo ""
        run_cppcheck
        echo ""
        run_scanner
        ;;
    all|*)
        require_sonar_token
        run_cppcheck
        echo ""
        run_scanner
        ;;
esac
