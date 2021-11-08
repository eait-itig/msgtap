# msgtap

`msgtap` is a structured binary log format for arbitrary messages.

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
as network packets. For example, `msgtap` supports logging of DNS
messages like what is provided by [`dnstap`], but is not limited
to the logging of DNS packets. A stream or file containing DNS
`msgtap` records may also contain Ethernet or IP packet captures
as well.

### Abitrary Metadata

The base `msgtap` header is only concerned with the type of the
message in the record, and how much data is associated with the
record. All other information about the message is represented by
a series of metadata fields before the actual message payload.

Examples of metadata include the names of the host and program that
generated the record, the time at which the message was generated,
or a sequence number or transaction identifier associated with the
request the record was generated for.

## Structure

Multi-byte fields in the `msgtap` protocol are in big-endian format.
There is no provision for alignment of multi-byte fields, they can
appear on any byte boundary.

A `msgtap` record in a stream immediately follows the preceeding
record. There is no padding or framing of records within a stream.

### Record Header

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version| Reserved              | Type of Message               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Metadata Length                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Length                                                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Captured                                                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- Version (4 bits): The current version number is 0.
- Reserved (12 bits): These bits MUST be zero when records are
  generated, and MUST be ignored when processed.
- Type of Message (16 bits): Identifies the type of message data
  attached to the record.
- Metadata Length (32 bits): The amount of metadata in the record,
  in bytes.
- Length (32 bits): The original length of the message attached to
  this record, in bytes.
- Captured (32 bits): The amount of data from the message that is
  attached to this record, in bytes. The amount of data that is
  captured may be less than the original length of the message.

The total length of a `msgtap` record is the size of this header,
plus the metadata length, plus the captured message length.

### Metadata fields

Each metadata field is identified by a 4 byte header, which may be
followed by a value.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Class         | Type          | Length                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- Class (8 bits): Namespace for the "Type" field. If the class is
  0xff (255), the type namespace is provided by the msgtap header
  Type field.
- Type (8 bits): Type indicating the format of the data contained
  in this metadata field.
- Length (16 bits): The length of the data following the metadata
  header, in bytes.

## Inspiration

- [`dnstap`] - a flexible, structured binary log format for DNS
  software
- [Geneve] - RFC 8926: Generic Network Virtualisation Encapsulation
- [NSH] - RFC 8300: Network Service Header
- [libpcap]
- [ERF] - Endace Extensible Record Format (ERF)

[`dnstap`]: https://dnstap.info/
[Geneve]: https://tools.ietf.org/html/rfc8926
[NSH]: https://tools.ietf.org/html/rfc8300
[libpcap]: https://www.tcpdump.org/
[ERF]: https://www.endace.com/endace-high-speed-packet-capture-solutions/technologies/erf/

