#!/bin/bash

CA="https://acme-staging-v02.api.letsencrypt.org/directory"

# First, a preface for those reading this source code, be it for
# curiosity, to audit it before using it, or just out of boredom
# on a lazy day:
#
# Whenever possible I opt to use coding patterns which avoid any
# "escaped characters" in strings. So you will see 'printf' used
# almost exclusively instead of 'echo' for instance, as JSON has
# so many double-quotes that it becomes extremely messy to write
# let alone read later otherwise.
#
# Values are kept in one and only one place whenever possible to
# avoid things getting mismatched. A prime example of this is in
# the initial "order request" step: Instead of passing a list of
# domains we pass in the CSR and go through the extra steps that
# parsing the domain list out involves. The CSR is the canonical
# list of domains, so only the CSR creation function can be sent
# an explicit list of domains, all others rely on the CSR.
#
# We cache values whenever possible. This acts akin to a promise
# when we require the cache being populated before proceeding as
# well, allowing more code to be merged together and as a result
# simplifying the overall script.
#
# Legibility is the primary goal in this entire script. Yes, you
# can do things better/faster/smaller by doing <X>. This is true
# all over the script. But much like avoiding escaped characters
# several choices of how to implement things are taking the road
# more legible.

# Used to print 'progress spinners'
SPINNER="|/-\\"

# Fetched the fist time it's needed
DIRECTORY=""
TOSURL="null"

# Used to track Key ID once looked up
KEYID=""

# Used to track _acme-challenge domains to purge at completion.
declare -A SCRUB_DOMAINS

# Verify tools we use exist and any version requirements

# grep is used for selectively finding lines that match patterns
# as a first step of parsing "screen scraped" output from all of
# the other programs used, in particular OpenSSL's output.
if grep --version > /dev/null; then : ; else
	echo -e '\tERROR:\tgrep not found'
	echo 'This is used in various places for filtering and parsing.'
	exit 1
fi

# The carry-forward of the above decision is we'll also need the
# other GNU coreutil of "tr" to do the character switching which
# is the only difference of base64URL versus normal base64.
if tr --version > /dev/null; then : ; else
	echo -e '\tERROR:\tGNU coreutil 'tr' not found'
	echo 'This is used to convert base64 to and from base64URL which JW* uses.'
	exit 2
fi

# OpenSSL "version string" is generally of the format:
#
#	Name Major.Minor.Patch[Letter]
#
# Name is the 'flavor' of implementation: OpenSSL, LibreSSL, etc.
#
# This code could break if any sub-digit exceeds 9, however there
# is little risk of this with the OpenSSL versioning specifically
# as they have had a handful of versions: 0.9.X, 1.0.X, 1.1.X, or
# the upcoming 3.X.X re-engineering release.
if [[ "$(
	openssl version | \
	grep -oP '^[^ ]+ \K[0-9]\.[0-9]\.[0-9]' | \
	tr -d '.'
)" -lt "111" ]]
then
	echo -e '\tERROR:\tOpenSSL is not at least v1.1.1'
	echo '-addext required for CSR generation is not available in earlier versions.'
	exit 3
fi

# This could be done with "openssl base64" however that sub-tool
# lacks a way to disable the line-wrap, so it's less useful when
# you want to create base64URL encoded binary strings instead of
# base64-armored blocks to attach to an e-mail.
if base64 --version > /dev/null; then : ; else
	echo -e '\tERROR:\tGNU coreutil 'base64' not found.'
	echo 'This is used instead of 'openssl base64' for better line-wrap controls.'
	exit 4
fi

# JSON parsing. There do exist pure bash parser implementations,
# however that adds greatly to the script complexity and as this
# is meant to be auditable by someone with modest scripting it's
# unsuitable versus simply relying on a dedicated CLI JSON tool,
# of which 'jq' is effectively the only game in town.
if jq --version > /dev/null; then : ; else
	echo -e '\tERROR:\tJQ command line JSON utility not found'
	echo 'This is used for JSON parsing in lieu of attempting it in BASH.'
	exit 5
fi

# While some distributions (especially cloud VMs) only include a
# copy of wget (smaller, fewer library dependencies), curl is by
# far the winner here for simplifying the script, similar to the
# reasons for requiring Python 3.
if curl --version > /dev/null; then : ; else
	echo -e '\tERROR:\tcurl not found'
	echo 'This is used for all requests to/from the CA.'
	exit 6
fi

# xxd is used for a single purpose: Converting hex strings. This
# could be done via python3, however the code to do so it rather
# long and surprisingly messy.
if echo | xxd -r -p; then : ; else
	echo -e '\tERROR:\txxd not found'
	echo 'This is used for parsing hex strings from OpenSSL.'
	exit 7
fi

# Usage: hard_abort <output>
#
# The 'oh shit' function; show the contents of the last request,
# and exit. This is ONLY used for unrecoverable issues generally
# outside of expected protocol flow.
hard_abort () {
	printf '-=-=-=-=-=-\n' > /dev/stderr
	cat headers.txt > /dev/stderr
	printf '-=-=-=-=-=-\n' > /dev/stderr
	printf '%s\n' "${1}" > /dev/stderr
	printf '-=-=-=-=-=-\n' > /dev/stderr
	exit 1
}

hex2bin () {
	xxd -r -p
}

base64url () {
	base64 -w 0 | \
	tr '/+' '_-' | \
	tr -d '='
}

# Usage: jwk <keyfile> | ...
jwk () {
	# This complexity is due to a quirk of how EC public keys
	# are displayed by OpenSSL by default: In ASN.1 format.
	#
	# EC keys do have a similar 'pair of values' which define
	# the specific public key component, however as they're X
	# and Y coordinates we'll need to un-ASN.1 them before we
	# can extract the raw hex from that output.
	#
	# The final step is (as long as we get a proper "code 04"
	# pubkey output to indicate "uncompressed" in EC parlance
	# so we have X _AND_ Y) is trim the "header" from the hex
	# string, split the remaining piece in half, then convert
	# that from a hex string to a base64url string.
	RAW="$(
		openssl ec -in "${1}.key" -pubout 2>/dev/null | \
		openssl ec -pubin -text -noout -conv_form uncompressed 2>/dev/null | \
		grep '    ' | \
		tr -d ' :\n\r'
	)"
	HALF=$[((${#RAW}-2)/2)]
	SPLIT=$[${HALF}+2]
	if [[ "${RAW:0:2}" != "04" ]]
	then
		printf '\tERROR:\tOpenSSL did not return "uncompressed" EC key format.\n' > /dev/stderr
		printf 'Aborting because arguments passed to OpenSSL did not work as intended.\n' > /dev/stderr
		exit 1
	fi

	ECX="$(
		echo -n "${RAW:2:${HALF}}" | \
		hex2bin | \
		base64url
	)"
	ECY="$(
		echo -n "${RAW:${SPLIT}:${HALF}}" | \
		hex2bin | \
		base64url
	)"
	printf '{"crv":"P-384","kty":"EC","x":"%s","y":"%s"}' "${ECX}" "${ECY}"
}

# Usage: fingerprint <key> | ...
fingerprint () {
	jwk "${1}" | \
	openssl sha256 -binary | \
	base64url
}

wdfcurl () {
	curl -s -D headers.txt -A 'wdfCert/1.0' -H 'Content-Type: application/jose+json' "$@"
}

# Usage: wdfcurl_response_code | ...
#
# Utility function for extracting the status code from the headers.txt
wdfcurl_response_code () {
	grep -oP "HTTP/[0-9.]+ \K[0-9][0-9][0-9]" headers.txt
}

cache_directory () {
	if [[ -z "${DIRECTORY}" ]]
	then
		printf 'Loading "directory" from CA...' > /dev/stderr

		DIRECTORY="$(wdfcurl "${CA}")"

		TOSURL="$(
			echo "${DIRECTORY}" | \
			jq -r '.meta.termsOfService'
		)"

		echo 'Done!' > /dev/stderr
	fi
}

# Usage: directory_lookup <entry name> | ...
directory_lookup () {
	echo -n "${DIRECTORY}" | \
	jq -r ".${1}"
}

# Usage: get_nonce | ...
#
# While in theory you can capture updated nonces from a previous
# call to the CAs by checking for the same header, doing so adds
# complexity versus fetching a fresh nonce for each request.
get_nonce () {
	cache_directory

	wdfcurl "$(directory_lookup newNonce)"

	grep -oPi '^replay-nonce: *\K.*$' headers.txt | \
	tr -d '\n\r'
}

# Usage: create_key <keyfile>
#
# Supports 384-bit ECDSA exclusively, stored in the most compact
# ASCII-based format possible: X-coordinate-only "Compressed" w/
# the public-key values excluded from the private key on disk.
#
# This can be easily augmented to store data in sqlite3 or other
# database/archive systems to avoid littering the workspace with
# hundreds or thousands of private/public key file pairs.
create_key () {
	if [[ -f "${1}.key" ]]
	then
		printf 'Using existing key %s.key.\n' "${1}" > /dev/stderr
		return 0
	fi

	printf 'Creating new 384-bit ECDSA key %s.key.\n' "${1}" > /dev/stderr

	openssl ecparam -name secp384r1 -noout -genkey | \
	openssl ec -no_public -conv_form compressed -out "${1}.key" 2>/dev/null
}

# Usage: create_csr <keyfile> <domain> [ ... <domain> ]
#
# This is the only function where domain names are specified, as
# all other locations will refer back to this CSR. Re-use of the
# same CSR to regenerate the certificate is generally acceptable
# and safe as long as the key used for it remains uncompromised.
create_csr () {
	create_key "${1}"

	local FILE="${1}"
	local SAN="DNS:${2}"
	while [[ "$#" -gt "2" ]]
	do
		shift
		SAN="${SAN},DNS:${2}"
	done

	if [[ -f "${FILE}.csr" ]]
	then
		printf 'CSR %s.csr already exists.\n' "${FILE}" > /dev/stderr
		return 0
	fi

	# Empty 'subject line' as it is unused for newer "domain
	# verified" certificates, and is not be used to list any
	# domain names any longer, per RFC 6125 section 6.4.4.
	#
	# With all major browser vendors ignoring the field, and
	# all other fields in the subject line being optional as
	# almost all SSL vendors create the subject line as they
	# are signing the final certificate, an empty subject is
	# the best option and removed any need for customization
	# which simplifies the code.
	openssl req -new -sha384 -key "${FILE}.key" -out "${FILE}.csr" -subj "/" -addext "subjectAltName=${SAN}"

	printf 'CSR %s.csr created\n' "${1}" > /dev/stderr
}

# Usage: ... | sign_string <keyfile> | ...
sign_string () {
	# Much like public keys, digest signatures are ALSO done
	# in ASN.1 format for EC keys, so we need to extract the
	# X/Y coordinates just like above.
	#
	# The difference here is we want to concatanate them, so
	# we can shortcut by simply grepping the hex strings out
	# and merging them together directly from "asn1parse"
	openssl dgst -sha384 -sign "${1}.key" | \
	openssl asn1parse -inform der | \
	grep -E -o '[0-9A-F]{96}' | \
	tr -d '\n\r' | \
	hex2bin | \
	base64url
}

# Usage: send_signed_request <keyfile> <url> <header> <payload> | ...
#
# This function is exclusively a 'glue' function linking several
# other functions together: Converting the header and payload to
# the required base64URL format, signing them with the key, then
# sending them to the correct URL.
send_signed_request () (
	set +x
	local HEADER64="$(
		echo -n "${3}" | \
		base64url
	)"

	local PAYLOAD64="$(
		echo -n "${4}" | \
		base64url
	)"

	local SIGNATURE64="$(
		echo -n "${HEADER64}.${PAYLOAD64}" | \
		sign_string "${1}"
	)"

	local DATA="$(printf '{"protected":"%s","payload":"%s","signature":"%s"}' "${HEADER64}" "${PAYLOAD64}" "${SIGNATURE64}")"

	wdfcurl --data "${DATA}" "${2}"
)

# Usage: check_account <keyfile>
#
# Attempts to look up the account, explicitly setting the 'check
# only' setting, and NOT setting the terms-of-service setting.
#
# Fills in the KEYID entry if the account is found.
check_account () {
	if [[ ! -f "${1}.key" ]]
	then
		printf 'No key found for account %s, aborting!\n' "${1}" > /dev/stderr
		return 1
	fi

	cache_directory

	local URL="$(directory_lookup newAccount)"

	local HEADER="$(printf '{"alg":"ES384","jwk":%s,"nonce":"%s","url":"%s"}' "$(jwk "${1}")" "$(get_nonce)" "${URL}")"

	local PAYLOAD="$(printf '{"onlyReturnExisting":true}')"

	printf 'Looking up account for key %s...' "${1}" > /dev/stderr

	local OUTPUT="$(send_signed_request "${1}" "${URL}" "${HEADER}" "${PAYLOAD}")"

	if [[ "$(wdfcurl_response_code)" -ge "300" ]]
	then
		echo 'Unable to find!' > /dev/stderr

		if [[ "${TOSURL}" != "null" ]]
		then
			printf 'The current Terms Of Service can be viewed at:\n\n%s\n\n' "${TOSURL}" > /dev/stderr
		fi

		echo 'You will most likely need to run the --accept-tos command.' > /dev/stderr

		return 1
	fi

	echo 'Found!' > /dev/stderr

	KEYID="$(
		grep -oPi '^location: +\K.*$' headers.txt | \
		tr -d '\n\r'
	)"

	return 0
}

# Usage: create_account <keyfile> <e-mail address>
#
# Attempts to create an account, or return any existing one that
# uses the same key. Explicitly sets the terms-of-service option
# and sets the E-Mail address.
#
# Fills in the KEYID entry if the account is created or one that
# already exists is found.
create_account () {
	create_key "${1}"

	cache_directory

	local URL="$(directory_lookup newAccount)"

	local HEADER="$(printf '{"alg":"ES384","jwk":%s,"nonce":"%s","url":"%s"}' "$(jwk "${1}")" "$(get_nonce)" "${URL}")"

	local PAYLOAD="$(printf '{"termsOfServiceAgreed":true,"contact":["mailto:%s"]}' "${2}")"

	printf 'Creating account %s...' "${1}" > /dev/stderr

	local OUTPUT="$(send_signed_request "${1}" "${URL}" "${HEADER}" "${PAYLOAD}")"

	if [[ "$(wdfcurl_response_code)" -ge "300" ]]
	then
		printf 'Error creating account!\n' > /dev/stderr
		hard_abort "${OUTPUT}"
	fi

	echo 'Created!' > /dev/stderr

	KEYID="$(
		grep -oPi '^location: +\K.*$' headers.txt | \
		tr -d '\n\r'
	)"

	if [[ -z "${KEYID}" ]]
	then
		printf '\tERROR: No Key ID returned despite 'successful' account creation!.\n' > /dev/stderr
		hard_abort "${OUTPUT}"
	fi
}

# Usage: cache_keyid <accountKey>
#
# Convenience function to wrap check_account with an appropriate
# error message with details if it fails to find the account.
#
# Exists to avoid looking up the account multiple times and also
# avoiding duplication of code.
cache_keyid () {
	if [[ ! -z "${KEYID}" ]]
	then
		return 0
	fi

	check_account "${1}"

	if [[ "$(wdfcurl_response_code)" -ge "300" ]]
	then
		printf '\tERROR:\nUnable to find account for %s.key\n' "${1}" > /dev/stderr
		printf 'You most likely need to create_account to (re-)accept the Terms of Service.\n' > /dev/stderr

		exit 1
	fi
}

# Usage: get_authorization_dns_challenge <accountKeyFile> <URL> | ...
#
# This function requests the challenges for a given domain, then
# filters that down to only the "dns-01" challenge simplified to
# just the three key values:
#   * Domain without the _acme-challenge prefix
#   * Token which will be merged with our JWK thumbprint
#   * URL to access to indicate the TXT record is in place
get_authorization_dns_challenge () {
	cache_keyid "${1}"

	local HEADER="$(printf '{"alg":"ES384","kid":"%s","nonce":"%s","url":"%s"}' "${KEYID}" "$(get_nonce)" "${2}")"

	local OUTPUT="$(send_signed_request "${1}" "${2}" "${HEADER}" "")"

	echo "${OUTPUT}" | \
	jq '[ ( .identifier.value? ), ( .status? ), ( .challenges? | unique_by( .type ) | .[] | select( .type == "dns-01" ) | ( .token?, .url? ) ) ] | { domain: .[0], status: .[1], token: .[2], callback: .[3] }'
}

# Usage: update_dns_txt <domain> <token>
#
# Domain configuration blocks are registrar-specific
#
# Only included provider is Joker as it has been badly supported
# by most Let's Encrypt clients due to a combination of "purity"
# mindset by many coders that their API only supports one single
# TXT record which requires incremental domain validations.
#
# One caveat: Do not setup a "*.example.com" CNAME record, these
# will break the 'delete record' check as there's no way to look
# for a lack of a TXT record if a wildcard CNAME is in place, as
# that will generally pull in any SPF records or other things.
#
# Instead create wildcard A and/or AAAA records. You'll have far
# fewer issues troubleshooting DNS-reliant tools then.
update_dns_txt () {
	if [[ ! -f "config_dns.inc" ]]
	then
		echo "config_dns.inc file missing; note that you need to copy" > /dev/stderr
		echo "the config_dns_template.inc file and edit it to create" > /dev/stderr
		echo "an actual DNS configuration. config_dns.inc is excluded" > /dev/stderr
		echo "from the git repo to avoid accidental credential leakage." > /dev/stderr
		exit 1
	fi

	source ./config_dns.inc

	if [[ ! -f "dns_${PROVIDER}.inc" ]]
	then
		echo "Unknown domain, zone, and/or provider. Aborting." > /dev/stderr

		if [[ -z "${PROVIDER}" ]]
		then
			echo "Update config_dns.inc to have a valid match for ${1}." > /dev/stderr
		else
			echo "There is no dns_${PROVIDER}.inc script." > /dev/stderr
			echo "Check dns_joker.inc for an example." > /dev/stderr
		fi

		exit 1
	fi

	local NAMESERVERS=($(dig "${ZONE}" ns +short))
	local TOTAL="${#NAMESERVERS[@]}"
	local DUG

	local UPDATE="unrequired"
	for NAMESERVER in "${NAMESERVERS[@]}"
	do
		DUG="$(dig "@${NAMESERVER%.}" "${1}" txt +short)"
		DUG="${DUG%\"}"
		DUG="${DUG#\"}"

		if [[ "=${DUG}=" != "=${2}=" ]]
		then
			UPDATE="needed"
			break
		fi
	done

	if [[ "${UPDATE}" != "needed" ]]
	then
		echo -e "DNS TXT records for ${1} already correct.\e[0K"
		return 0
	fi

	echo -e -n "Setting ${1} TXT record...\e[0K\r"

	if source "dns_${PROVIDER}.inc"; then : ; else
		echo "Error setting ${1} TXT record!" > /dev/stderr
		exit 1
	fi

	# No errors, so get full list of NS servers for the zone
	# to scan until each shows the updated TXT record.

	local LOOP_TXT
	for LOOP_TXT in {1..300}
	do
		while [[ "${#NAMESERVERS[@]}" -ge "1" ]]
		do
			printf '%s TXT record set, %i/%i DNS servers propagated, checking %s... %s\e[0K\r' \
				"${1}" \
				"$[${TOTAL}-${#NAMESERVERS[@]}]" \
				"${TOTAL}" \
				"${NAMESERVERS[-1]%.}" \
				"${SPINNER:$[${LOOP_TXT}%4]:1}"
			DUG="$(dig "@${NAMESERVERS[-1]%.}" "${1}" txt +short)"
			DUG="${DUG%\"}"
			DUG="${DUG#\"}"

			if [[ "=${DUG}=" != "=${2}=" ]]
			then
				break
			fi

			unset 'NAMESERVERS[-1]'
		done

		if [[ "${#NAMESERVERS[@]}" -lt "1" ]]
		then
			printf '%s TXT record set, all DNS servers propagated.\e[0K\n' \
				"${1}"
			break
		fi

		sleep 1
	done
}

# Usage: handle_challenge_dns <account> <challengeURL>
handle_challenge_dns () {
	printf 'Checking challenge %s...\e[0K\r' "${2}" > /dev/stderr

	local JSON="$(get_authorization_dns_challenge "${1}" "${2}")"

	local STATUS="$(
		echo "${JSON}" |\
		jq -r '.status'
	)"

	if [[ "${STATUS}" -eq "pending" ]]
	then
		local DOMAIN="$(
			echo "${JSON}" | \
			jq -r '.domain'
		)"
		local TOKEN="$(
			echo "${JSON}" | \
			jq -r '.token'
		)"
		local CALLBACK="$(
			echo "${JSON}" | \
			jq -r '.callback'
		)"
		local FINGERPRINT="$(fingerprint account)"
		local DIGEST="$(
			echo -n "${TOKEN}.${FINGERPRINT}" | \
			openssl sha256 -binary | \
			base64url
		)"

		update_dns_txt "_acme-challenge.${DOMAIN}" "${DIGEST}"

		SCRUB_DOMAINS[${DOMAIN}]="."

		cache_keyid "${1}"

		local HEADER="$(printf '{"alg":"ES384","kid":"%s","nonce":"%s","url":"%s"}' "${KEYID}" "$(get_nonce)" "${CALLBACK}")"

		local OUTPUT="$(send_signed_request "${1}" "${CALLBACK}" "${HEADER}" "{}")"

		local LOOP_DNS
		for LOOP_DNS in {1..300}
		do
			echo -e -n "CertAuth: ${SPINNER:$[${LOOP_DNS}%4]:1}\e[0K\r"
			local OUTPUT_STATUS="$(
				get_authorization_dns_challenge "${1}" "${2}"
			)"
			local STATUS_STATUS="$(
				echo "${OUTPUT_STATUS}" | \
				jq -r '.status'
			)"
			case "${STATUS_STATUS}" in
			processing | pending)
				continue
				;;
			valid)
				echo "CertAuth: Success!"
				return 0
				;;
			invalid | *)
				echo "CertAuth: Error, invalid validation!" > /dev/stderr
				hard_abort "${OUTPUT_STATUS}"
				;;
			esac
			sleep 1
		done
	fi
}

# Usage: certificate_order <accountKeyfile> <domainKeyfile>
#
# Instead of passing the list of domains in again and risking an
# inconsistency, we fetch and parse out the SANs from the CSR to
# reduce the risk of accidental mistakes.
#
# This function has several valid processing paths:
#
#   - If we run out of time and end up in the 'invalid' state we
#     notify the user to restart things.
#
#   - Initially a 'newOrder' call will end up in 'pending' state
#     so this function records the 'authorization' URLs so we're
#     able to process them later individually.
#
#   - Once all authorizations are accepted we move into the next
#     state: 'ready' We make a request to the 'finalize' URL and
#     then get switched to the 'processing' state to wait on the
#     CA to finish work on it's side.
#
#   - When the state changes from 'processing' to 'valid' we can
#     fetch the completed certificate with a POST-as-GET request
#     to the 'certificate' URL provided by the CA.
certificate_order () {
	if [[ -f "${2}.crt" ]]
	then
		# Fixed timestamp to minimize race conditions
		local CERT_NOW="$(date -u '+%s')"

		# How close was our starting date?
		local CERT_START="$(
			date -u --date="$(
				openssl x509 -in "${2}.crt" -noout -startdate | \
				grep -oP '^notBefore=\K.*$'
			)" '+%s'
		)"
		local CERT_START_DISTANCE="$[${CERT_START}-${CERT_NOW}]"

		# How close is/war our ending date?
		local CERT_FINISH="$(
			date -u --date="$(
				openssl x509 -in "${2}.crt" -noout -enddate | \
				grep -oP '^notAfter=\K.*$'
			)" '+%s'
		)"
		local CERT_FINISH_DISTANCE="$[${CERT_FINISH}-${CERT_NOW}]"

		# Don't renew if things are closer to start than
		# the end. This trips at roughly the 50% mark in
		# the certificate lifespan, and still works even
		# after the expiration date as we stay closer to
		# the end date than the start date forever more.
		#
		# Note the "#-" parameter expansion here behaves
		# as a sort of absolute value function by simply
		# stripping the negative sign off if present.
		#
		# Technically a hack, but a straightforward one.
		if [[ "${CERT_START_DISTANCE#-}" -lt "${CERT_FINISH_DISTANCE#-}" ]]
		then
			echo "Certificate ${2}.crt is not due to be renewed yet, skipping." > /dev/stderr
			return 0
		fi
	fi

	cache_directory

	local URL_ORDER="$(directory_lookup newOrder)"

	local DOMAINS=($(
		openssl req -text -noout -in "${2}.csr" | \
		grep -oP 'DNS:\K[-*._a-z0-9]+'
	))

	local PAYLOAD_ORDER=""
	for DOMAIN in "${DOMAINS[@]}"
	do
		PAYLOAD_ORDER="$(printf '%s,{"type":"dns","value":"%s"}' "${PAYLOAD_ORDER}" "${DOMAIN}")"
	done
	PAYLOAD_ORDER="$(printf '{"identifiers":[%s]}' "${PAYLOAD_ORDER:1}")"

	cache_keyid "${1}"

	local LOOP_ORDER
	for LOOP_ORDER in {1..300}
	do
		local HEADER_ORDER="$(printf '{"alg":"ES384","kid":"%s","nonce":"%s","url":"%s"}' "${KEYID}" "$(get_nonce)" "${URL_ORDER}")"

		local OUTPUT_ORDER="$(send_signed_request "${1}" "${URL_ORDER}" "${HEADER_ORDER}" "${PAYLOAD_ORDER}")"

		# If provided the 'location' header switch to POST-as-GET requests
		if grep -qPi '^location: +' headers.txt
		then
			URL_ORDER="$(
				grep -oPi '^location: +\K.*$' headers.txt | \
				tr -d '\n\r'
			)"
			PAYLOAD_ORDER=""
		fi

		local STATUS="$(
			echo "${OUTPUT_ORDER}" | \
			jq -r '.status'
		)"

		case "${STATUS}" in

		invalid)
			echo -e "\tERROR\tCertificate order invalidated." > /dev/stderr
			echo -e "\tDomains: ${DOMAINS[@]}" > /dev/stderr
			echo "This certificate request will need to be restarted entirely; it has expired." > /dev/stderr
			return 1
			;;

		pending)
			local AUTHORIZATIONS=($(
				echo "${OUTPUT_ORDER}" | \
				jq -r '.authorizations | .[]'
			))

			for ENTRY in "${AUTHORIZATIONS[@]}"
			do
				handle_challenge_dns account "${ENTRY}"
			done
			;;

		ready)
			printf 'Certificate authorized... %s\e[0K\r' "${SPINNER:$[${LOOP_ORDER}%4]:1}"
			local URL_FINALIZE="$(
				echo "${OUTPUT_ORDER}" | \
				jq -r '.finalize'
			)"

			local CSR_BASE64URL="$(
				openssl req -outform der -in "${2}.csr" | \
				base64url
			)"

			local PAYLOAD_FINALIZE="$(printf '{"csr":"%s"}' "${CSR_BASE64URL}")"

			local HEADER_FINALIZE="$(printf '{"alg":"ES384","kid":"%s","nonce":"%s","url":"%s"}' "${KEYID}" "$(get_nonce)" "${URL_FINALIZE}")"

			local OUTPUT_FINALIZE="$(send_signed_request "${1}" "${URL_FINALIZE}" "${HEADER_FINALIZE}" "${PAYLOAD_FINALIZE}")"

			echo 'Purging DNS txt records...'

			for DOMAIN in "${!SCRUB_DOMAINS[@]}"
			do
				update_dns_txt "_acme-challenge.${DOMAIN}" ""
			done
			declare -gA SCRUB_DOMAINS

			;;

		processing)
			printf 'Certificate processing... %s\e[0K\r' "${SPINNER:$[${LOOP_ORDER}%4]:1}"
			;;

		valid)
			local URL_CERTIFICATE="$(
				echo "${OUTPUT_ORDER}" | \
				jq -r '.certificate'
			)"

			local HEADER_CERTIFICATE="$(printf '{"alg":"ES384","kid":"%s","nonce":"%s","url":"%s"}' "${KEYID}" "$(get_nonce)" "${URL_CERTIFICATE}")"

			local OUTPUT_CERTIFICATE="$(send_signed_request "${1}" "${URL_CERTIFICATE}" "${HEADER_CERTIFICATE}" "")"

			if [[ "$(wdfcurl_response_code)" -ne "200" ]]
			then
				echo -e "\tERROR:\tFailed to download certificate!" > /dev/stderr
				echo "Saving output to ${2}.crt.error and ${2}.txt.error" > /dev/stderr
				echo "${OUTPUT_CERTIFICATE}" > "${2}.crt.error"
				cp headers.txt "${2}.txt.error"

				hard_abort "${OUTPUT_CERTIFICATE}"
			fi

			echo "Certificate for ${2} downloaded."
			echo "${OUTPUT_CERTIFICATE}" > "${2}.crt"

			break
			;;

		*)
			echo -e "\tERROR\tUnknown status from newOrder endpoint." > /dev/stderr
			echo "The status of '${STATUS}' was returned, which is not a valid option in RFC 8555, the ACME protocol." > /dev/stderr
			echo '-=-=-=-=-=-' > /dev/stderr
			echo "Account Key:     ${1}" > /dev/stderr
			echo "Current URL:     ${URL_ORDER}" > /dev/stderr
			echo "Current Header:  ${HEADER_ORDER}" > /dev/stderr
			echo "Current Payload: ${PAYLOAD_ORDER}" > /dev/stderr
			hard_abort "${OUTPUT}"
			;;
		esac

		sleep 1
	done
}

usage () {
cat <<- __EOF__
	Usage: ${0##*/} <options>

	Options may be one or more of the following, and are processed in
	order as encountered:

	--key <keyfile>
	        Creates the requested keyfile if it doesn't exist.
	        Appends '.key' to the filename.
	        The keyfile will always be a 384-bit ECDSA key.

	--accept-tos <keyfile> <e-mail>
	        Accept the latest Terms of Service for the account
	        identified by <keyfile>. If no such account exists
	        then one will be created.

	--csr <keyfile> <domain> ... <domain>
	        Creates a CSR using the requested keyfile and domains.
	        Appends '.key' and '.csr' to the keyfile as appropriate.
	        Treats all remaining arguments as domains to request.

	--order <accountKeyfile> <CSRkeyfile>
	        Places an order with the CA using the requested keyfiles.
	        Appends '.key' to the account key.
	        Appends '.csr' and (if successful) '.crt' to the CSR keyfile as appropriate.

	--txt <domain> <value>
	        Convenience function for manually setting a DNS TXT record.
	        Deletes the record if value is empty.

	--live
	        Makes requests against the 'live' instead of 'staging' Let's Encrypt API.
	        BEWARE OF RATE LIMITS! Test without --live first!
__EOF__
exit 0
}

if [[ "$#" -eq "0" ]]
then
	usage
fi

declare -A PARAMETERS
PARAMETERS["--live"]=1
PARAMETERS["--key"]=2
PARAMETERS["--accept-tos"]=3
PARAMETERS["--csr"]=3
PARAMETERS["--order"]=3
PARAMETERS["--txt"]=3

while [[ "$#" -gt "0" ]]
do
	if [[ -z "${PARAMETERS[${1}]}" ]]
	then
		usage
	fi

	if [[ "$#" -lt "${PARAMETERS[${1}]}" ]]
	then
		printf '\tERROR:\tInsufficient arguments passed to %s\n' "${1}" > /dev/stderr
		usage
	fi

	case "${1}" in
	"--live")
		CA="https://acme-v02.api.letsencrypt.org/directory"
		shift
		;;

	"--key")
		create_key "${2}"
		shift 2
		;;

	"--accept-tos")
		create_account "${2}" "${3}"
		shift 3
		;;

	"--csr")
		shift
		create_csr "${@}"
		shift "$#"
		;;

	"--order")
		certificate_order "${2}" "${3}"
		shift 3
		;;

	"--txt")
		update_dns_txt "${2}" "${3}"
		shift 3
		;;
	esac
done
