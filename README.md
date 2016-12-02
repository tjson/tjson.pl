A Perl parser for TJSON: https://www.tjson.org

NOTE: The TJSON spec is a DRAFT: This format is still in a draft state and subject to change!

This parser should be compliant as of Revision: 20 of [draft-tjson-examples.txt](https://github.com/tjson/tjson-spec/blob/7f22407949badd13ef918acc3cc3132e1131875a/draft-tjson-examples.txt)

NOTE: This module requires unmerged changes to either Cpanel::JSON::XS or JSON::PP

There are pull requests at https://github.com/rurban/Cpanel-JSON-XS/pull/75 (in discussion) and https://github.com/makamaka/JSON-PP/pull/30 (declined)

My forks are at https://github.com/rabcyr/Cpanel-JSON-XS and https://github.com/rabcyr/JSON-PP

Currently it only handles decoding, with either the exported `decode_tjson($tjson_string)`, or via `TJSON->new->decode($tjson_string)`

Proper documentation is lacking.

THIS IS PROOF-OF-CONCEPT CODE FOR AN UNSTABLE DRAFT SPEC. You have been warned.
