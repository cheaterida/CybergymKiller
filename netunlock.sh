#!/usr/bin/env bash
# Lift the network isolation applied by netlock.sh.
# Usage: sudo bash netunlock.sh
set -e

iptables -F OUTPUT
iptables -P OUTPUT ACCEPT

echo "OUTPUT chain flushed and policy restored to ACCEPT."
iptables -L OUTPUT -n --line-numbers
