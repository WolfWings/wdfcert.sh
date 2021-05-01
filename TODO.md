The DNS challenges can be handled much quicker done in parallel.

Would need to break into two passes done iteratively:
* Set all possible TXT records
  * Can't blindly do all TXT records at once. Both *.example.com
    and example.com both use the _acme-challenge.example.com TXT
    record, but not all DNS allows multiple TXT records set with
    their respective API's.
  * Tracking for domains to 'clear' can double as a 'have we set
    this domain yet in this pass?' tracker using the pass number
    instead of a fixed identifier.
* Wait for propagation
  * Need to only wait for records updated.
  * DON'T set the 'scrub' entry if we don't update a TXT record!
