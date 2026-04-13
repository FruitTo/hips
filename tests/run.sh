#!/bin/bash

echo "Running HIPS Tests..."
echo "====================="

# Test 1: XSS Detection Benchmark
echo -e "\n[TEST 1] XSS Detection Benchmark"
if [ -f "xss-bypass-gen" ]; then
    ./xss-bypass-gen 2>&1 | grep -E "(Detection Rate|Total Payloads|Detected|Bypassed)"
else
    echo "FAIL: xss-bypass-gen not compiled"
fi

# Test 2: XSS Detect (alternative)
echo -e "\n[TEST 2] XSS Detect Benchmark"
if [ -f "xss-regex/xss-detect" ]; then
    cd xss-regex && ./xss-detect 2>&1 | grep -E "(Detection Rate|Total Payloads|Detected|Bypassed)"
    cd ..
else
    echo "FAIL: xss-detect not found"
fi

echo -e "\n====================="
echo "Tests Complete!"
