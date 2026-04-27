#!/bin/bash

# Verify OSINT toolkit structure

echo "════════════════════════════════════════════════════════════"
echo "  OSINT TOOLKIT STRUCTURE VERIFICATION"
echo "════════════════════════════════════════════════════════════"
echo ""

TOOLS=("hunt" "social" "api" "access" "cache" "cloud" "cve" "campaign" "apply-keys")
PASSED=0
FAILED=0

check_tool() {
    local tool=$1
    echo -n "Checking $tool/ ... "
    
    if [ ! -d "$tool" ]; then
        echo "✗ MISSING"
        ((FAILED++))
        return 1
    fi
    
    # Check required files
    local checks=0
    [ -f "$tool/$tool.sh" ] && ((checks++)) || echo -n "[no $tool.sh] "
    [ -f "$tool/lib.sh" ] && ((checks++)) || echo -n "[no lib.sh] "
    [ -f "$tool/README.md" ] && ((checks++)) || echo -n "[no README] "
    [ -f "$tool/.gitignore" ] && ((checks++)) || echo -n "[no .gitignore] "
    
    if [ $checks -eq 4 ]; then
        echo "✓ COMPLETE"
        ((PASSED++))
        return 0
    else
        echo "⚠ PARTIAL ($checks/4)"
        ((FAILED++))
        return 1
    fi
}

# Check main docs
echo "Main Documentation:"
[ -f "MASTER_README.md" ] && echo "  ✓ MASTER_README.md" || echo "  ✗ MASTER_README.md MISSING"
[ -f "RESTRUCTURE_COMPLETE.md" ] && echo "  ✓ RESTRUCTURE_COMPLETE.md" || echo "  ✗ RESTRUCTURE_COMPLETE.md MISSING"
[ -f "TOOL_TEMPLATE_README.md" ] && echo "  ✓ TOOL_TEMPLATE_README.md" || echo "  ✗ TOOL_TEMPLATE_README.md MISSING"
[ -f "TOOL_TEMPLATE_CLAUDE.md" ] && echo "  ✓ TOOL_TEMPLATE_CLAUDE.md" || echo "  ✗ TOOL_TEMPLATE_CLAUDE.md MISSING"
echo ""

# Check each tool
echo "Tools Directory Status:"
for tool in "${TOOLS[@]}"; do
    check_tool "$tool"
done

echo ""
echo "════════════════════════════════════════════════════════════"
echo "Results: $PASSED Complete, $FAILED Partial/Missing"
echo "════════════════════════════════════════════════════════════"
echo ""

# Test tools
echo "Tool Verification:"
for tool in hunt social api access; do
    echo -n "  Testing $tool.sh --help ... "
    if cd "$tool" 2>/dev/null && timeout 5 ./$tool.sh --help >/dev/null 2>&1; then
        echo "✓ Works"
        cd ..
    else
        echo "✗ Failed or missing"
        cd ..
    fi
done

echo ""
echo "Next Steps:"
echo "  1. cd ~/Desktop/osint/hunt && ./hunt.sh --help"
echo "  2. cd ~/Desktop/osint/social && ./social.sh --help"
echo "  3. Run tests on small domain: hunt --target Test -d example.com"
echo "  4. Read RESTRUCTURE_COMPLETE.md for next phases"
echo ""
