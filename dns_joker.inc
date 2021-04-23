#!/bin/bash
#
# Usage: source dns_joker.inc <domain> [<value>]
#
# Expects the following environmental variables to be set:
#   * USERNAME
#   * PASSWORD
#   * ZONE
#   * LABEL
#
# Joker's DNS servers support updating a single TXT record for a
# given full domain. If multiple exists they will be replaced by
# the single new TXT record.
#
# This does result in an incredibly simple 'write only' API that
# has a single endpoint with only a handful of parameters.
#
# The only bit of 'magic' here is converting "full DNS" + "zone"
# into just the "label" as Joker calls it, the prefix portion of
# the DNS record.

LABEL="${1%"${ZONE}"}"
LABEL="${LABEL%.}"

printf "Setting %s TXT record...\r" "${1}"

OUTPUT="$(curl --silent --include \
	--data "username=${USERNAME}" \
	--data "password=${PASSWORD}" \
	--data "zone=${ZONE}" \
	--data "label=${LABEL}" \
	--data "type=TXT" \
	--data "value=${2}" \
	https://svc.joker.com/nic/replace)"

if [[ "$(echo "${OUTPUT}" | grep -oP "HTTP/[0-9.]+ \K[0-9][0-9][0-9]" )" -ne "200" ]]
then
	echo "Error setting TXT record on JokerDNS. Are the credentials correct?" > /dev/stderr
	exit 1
fi

if echo "${OUTPUT}" | grep -qP '^OK: [0-9]+ inserted, [0-9]+ deleted'
then : ; else
	echo "Unexpected response format from JokerDNS API. Verify compatability." > /dev/stderr
	exit 0
fi
