# Learning

Firewall rules are ordered packet-set tests. A larger source CIDR and a wider
port interval can contain a later rule's matches; an earlier terminal action
then prevents that later rule from being evaluated for those packets.

An identical match with a different action is a conflicting shadow, while an
identical match with the same action is a duplicate. Either may be unreachable;
that alone does not justify changing a real policy.

Zero counters can reflect idle traffic, a recent reset or the collection window.
They do not prove structural unreachability. Missing counters remain unknown.

Unknown syntax must survive parsing so that the analyzer cannot silently invent
a broader rule. Unknown targets must never be assumed to terminate or return.

Python splitlines recognizes additional control characters beyond newline;
validate the entire input before splitting it. Tests caught the need to handle
normal built-in policies in explicitly excluded non-filter tables as well.
