#!/bin/bash
# tests/test_integration.sh

set -e

# Create a dummy target file (for example, with a local IP address or a MAC address)
echo "127.0.0.1" > test_targets.txt

# Run the executable (assumes it was built as "wakey")
./wakey test_targets.txt

# Check if the ARP cache file was generated (or updated)
if [ -f "arp_cache.txt" ]; then
    echo "Integration test passed: ARP cache file exists."
else
    echo "Integration test failed: ARP cache file does not exist."
    exit 1
fi
