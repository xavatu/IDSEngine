#!/bin/bash
set -e

CONFIG="/etc/suricata/config/suricata.yaml"
LOGDIR="/var/log/suricata"

exec suricata -c "$CONFIG" -q 0 -l "$LOGDIR"
