# msgtap

`msgtap` is a structured binary log format for abitrary messages.

## Features

### Simplicity

The binary structure of log messages is intentionally simple, even
at the cost of some space, to make it easy to generate, parse, and
restructure with minimal to no dependencies.

### Record independence

Each `msgtap` record is independent from every other record. This
allows messages from multiple sources to be easily aggregated by
writing them into the same stream. Files containing msgtap records
can be merged together by simply concatenating them.

The data contained in an individual `msgtap` record is typed. This
supports the logging of high level messages exchanged by applications
as well as the more traditional capture of low level messages such
as network packets. For examle, `msgtap` supports logging of DNS
messages like what is provided by [`dnstap`], but is not limited
to the logging of DNS packets. A stream or file containing msgtap
records may also contain Ethernet or IP packet captures as well as
DNS messages.

### Abitrary Metadata

The base `msgtap` header is only concerned with the type of the
message in the record, and how much data is associated with the
record. All other information about the message is represented by
a series of metadata fields before the actual message payload.

Examples of metadata include the names of the host and program that
generated the record, the time at which the message was generated,
or a sequence number or transaction identifier associated with the
request the record was generated for.

# Links

[`dnstap`]: https://dnstap.info/
