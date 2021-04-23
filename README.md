# wdfcert.sh

This script came about due to the poor support for automating
Let's Encrypt for the common use case of a root + wildcard
certificate if using the "Joker" registrar's built-in DNS services.

It was expanded upon as even for the few tools that worked with
that provider none of them supported modern ECDSA account keys
and few if any supported ECDSA certificate generation.

A friend read the script after I was finished writing it and
showed them a copy, and suggested I publish it on github as
others may both find it useful to learn how Let's Encrypt works
or may be in a similar situation I was in.

Most of the documentation is in the wdfcert script itself.

Finally: Why wdfcert? It's something I do for 'throwaway' one-off
tools: With the name of Wolf it's a common typographical failure
of various fonts that merges the **ol** into a **d** so
**wolf** -> **wdf**
