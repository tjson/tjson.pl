package TJSON;

# ABSTRACT: turns baubles into trinkets

use 5.12.0;
use warnings;

use boolean;
use base qw/ Exporter /;
use DateTime::Format::RFC3339;
use Math::Int64 qw/int64 uint64 :die_on_overflow/;
use MIME::Base32;	# FIXME: MIME::Base32 is a bad module
use MIME::Base64 qw/ encode_base64url decode_base64url /;
use Scalar::Util qw/ isdual looks_like_number /;
use Time::Moment;

@TJSON::EXPORT = qw/ decode_tjson encode_tjson /;

my @modules = qw/ Cpanel::JSON::XS JSON::PP /;

if (exists $ENV{PERL_JSON_BACKEND}) {
    @modules = split ',', $ENV{PERL_JSON_BACKEND};
}

my %RequiredVersion = (
    'JSON::PP' => '2.27400',		# FIXME: actually next version
    'Cpanel::JSON::XS' => '3.0222',	# FIXME: actually next version
);


my $MODULE;
my @last_err;
while (my $module = shift @modules) {
    push @last_err, $@ if $@;
    eval qq/ use $module $RequiredVersion{$module} () /;

    if ($@) {
        next if @modules;
        die join '', @last_err, $@;
    }
    if (!defined $module->can('disallow_dupkeys')) {
        $@ = "$module does not have feature disallow_dupkeys";
        next if @modules;
        die join '', @last_err, $@;
    }
    $MODULE = $module;
    last;
}

sub new {
    bless {}, shift;
}

sub decode {
    decode_tjson($_[1]);
}

sub decode_tjson {
    my ($json) = @_;
    decode_thash($MODULE->new->utf8->allow_nonref->disallow_dupkeys->decode($json));
}

sub encode {
    encode_tjson($_[1]);
}

sub encode_tjson {
    my ($hash) = @_;
    $MODULE->new->utf8->encode(encode_thash($hash));
}

sub encode_thash {
    my ($hash, $coerce) = @_;
    $coerce //= 1;	# FIXME
    my $thash = {};
    if (ref $hash eq 'HASH') {
        for my $key (keys %$hash) {
            if (ref $hash->{$key} eq 'TJSON::Object') {
            } elsif (ref $hash->{$key} eq 'TJSON::Array') {
            } elsif (ref $hash->{$key} eq 'TJSON::String') {
            } elsif (ref $hash->{$key} eq 'TJSON::Int64') {
            } elsif (ref $hash->{$key} eq 'TJSON::UInt64') {
            } elsif (ref $hash->{$key} eq 'TJSON::Base16') {
            } elsif (ref $hash->{$key} eq 'TJSON::Base32') {
            } elsif (ref $hash->{$key} eq 'TJSON::Base64url') {
            } elsif (ref $hash->{$key} eq 'TJSON::Timestamp') {
            } elsif (ref $hash->{$key} eq 'TJSON::Double') {	# NOTE: spec just saying "floating points"
            } elsif (ref $hash->{$key} eq 'TJSON::Boolean') {	# NOTE: not in spec
            } elsif (ref $hash->{$key} eq 'TJSON::Null') {	# NOTE: not in spec
            } elsif ($coerce) {
                if (ref $hash->{$key} eq 'HASH') {
                    $thash->{"$key:O"} = encode_thash($hash->{$key});
                } elsif (ref $hash->{$key} eq 'ARRAY') {
                    my ($tag, $tarray) = encode_tarray($hash->{$key});
                    $thash->{"$key:$tag"} = $tarray;
                } elsif (ref $hash->{$key} eq '') {	# string, number, undef (null not in spec), other? (should fail if other)
                    my $type = scalar_typer($hash->{$key}, {coerce_num => 0});
                    if ($type eq 'String') {
                        $type = 's';
                        # FIXME: if not all Unicode strings, they need to be BaseXX-encoded
                    } elsif ($type eq 'Int64') {
                        $type = 'i';
                    } elsif ($type eq 'UInt64') {	# FIXME: scalar_typer() will not return this
                        $type = 'u';
                    } elsif ($type eq 'Double') {
                        $thash->{$key} = $hash->{$key};
                        next;
                    } else {
                        die "oh no";
                    }
                    $thash->{"$key:$type"} = "$hash->{$key}";
                } elsif (ref $hash->{$key} eq 'Math::Int64') {
                    $thash->{"$key:i"} = "$hash->{$key}";	# FIXME: does just stringifying it work?
                } elsif (ref $hash->{$key} eq 'Math::UInt64') {
                    $thash->{"$key:u"} = "$hash->{$key}";	# FIXME: does just stringifying it work?
                } elsif (ref $hash->{$key} eq 'DateTime') {
                   $thash->{"$key:t"} = DateTime::Format::RFC3339->new->format_datetime($hash->{$key});	# FIXME: TJSON only allows a subset of RFC 3339
                } elsif (ref $hash->{$key} eq 'Time::Moment') {
                   $thash->{"$key:t"} = DateTime::Format::RFC3339->new->format_datetime($hash->{$key});	# FIXME: TJSON only allows a subset of RFC 3339
                } elsif (ref $hash->{$key} eq 'boolean' or ref $hash->{$key} eq 'JSON::PP::Boolean') {
                    die "TJSON currently does not define boolean";
                } else {
                    die "oh no: ", ref $hash->{$key}, " ($hash->{$key})";
                }
            } else {
                die "oh no";
            }
        }
    } else {
        die "TJSON allows only object as the top-level element\n";
    }
    $thash;
}

sub encode_tarray {
    my ($array) = @_;
    my %refs = map { ref $_ => undef } @$array;
    die "TJSON cannot coerce type of an empty array\n" unless keys %refs;
    die "TJSON does not allow arrays of mixed types\n" unless keys %refs == 1;
    my ($ref) = keys %refs;
    my $tarray = [];
    my $tag;
    if ($ref eq 'HASH') {
        $tag = 'A<O>';
        @$tarray = map { encode_thash($_) } @$array;
    } elsif ($ref eq 'ARRAY') {
        my %tags;
        for my $v (@$array) {
            my ($tag, $subtarray) = encode_tarray($v);
            $tags{$tag} = undef;
            die "TJSON does not allow arrays of mixed types\n" unless keys %tags == 1;
            push @$tarray, $subtarray;
        }
        my ($subtag) = keys %tags;
        $tag = "A<$subtag>";
    } elsif ($ref eq '') {	# string, number, undef (null not in spec), other? (should fail if other)
        my %types;
        for my $v (@$array) {
            my $type = scalar_typer($v, {coerce_num => 0});
            $types{$type} = undef;
            die "TJSON does not allow arrays of mixed types\n" unless keys %types == 1;
        }
        my ($type) = keys %types;
        if ($type eq 'String') {
            $type = 's';
            # FIXME: if not all Unicode strings, they need to be BaseXX-encoded
        } elsif ($type eq 'Int64') {
            $type = 'i';
        } elsif ($type eq 'UInt64') {	# FIXME: scalar_typer() will not return this
            $type = 'u';
        } elsif ($type eq 'Double') {
            die "TJSON does not currently define how to type doubles/floats\n";
            $type = 'd';
        } else {
            die "oh no";
        }
        $tag = "A<$type>";
        @$tarray = map { "$_" } @$array;	# FIXME: quoting $_ would break doubles/floats, if they were defined for arrays
    } elsif ($ref eq 'Math::Int64') {
        $tag = 'A<i>';
        @$tarray = map { "$_" } @$array;	# FIXME: does just stringifying it work?
    } elsif ($ref eq 'Math::UInt64') {
        $tag = 'A<u>';
        @$tarray = map { "$_" } @$array;	# FIXME: does just stringifying it work?
    } elsif ($ref eq 'DateTime') {
        $tag = 'A<t>';
        @$tarray = map { DateTime::Format::RFC3339->new->format_datetime($_) } @$array;	# FIXME: TJSON only allows a subset of RFC 3339
    } elsif ($ref eq 'Time::Moment') {
        $tag = 'A<t>';
        @$tarray = map { DateTime::Format::RFC3339->new->format_datetime($_) } @$array;	# FIXME: TJSON only allows a subset of RFC 3339
    } elsif ($ref eq 'boolean' or $ref eq 'JSON::PP::Boolean') {
        die "TJSON currently does not define boolean";
        $tag = 'A<B>';				# NOTE: I made up 'B'
        @$tarray = map { $_ ? 'true' : 'false' } @$array;
    } else {
        die "oh no";
    }
    $tag, $tarray;
}

sub decode_thash {
    my ($data) = @_;
    my $hash = {};
    if (ref $data eq 'HASH') {
        for my $tagged (keys %$data) {
            my $sep = rindex $tagged, ':';
            die "TJSON requires all keys be tagged\n" if $sep == -1;
            my $key = substr $tagged, 0, $sep;
            die "TJSON requires names to be distinct\n" if exists $hash->{$key};
            my $tag = substr $tagged, $sep+1;
            die "TJSON requires all keys be tagged\n" if $tag eq '';
            my $type = parse_tag($tag);
            $hash->{$key} = decode_value($data->{$tagged}, $type);
        }
        $hash;
    } else {
        die "TJSON allows only object as the top-level element\n";
    }
}

sub decode_value {
    my ($value, $type) = @_;
    if ("$type" eq 'Array') {
        die "TJSON expected an Array but got: '$value'" unless ref $value eq 'ARRAY';
        for my $e (@$value) {
            $e = decode_value($e, $type->{subtype});
        }
        $value;
    } elsif ("$type" eq 'Object') {
        die "TJSON expected an Object but got: '$value'" unless ref $value eq 'HASH';
        decode_thash($value);
    } else {
        if ("$type" eq 'String') {
            my $actual_type = scalar_typer($value);
            die "TJSON expected a String but got: '$actual_type'\n" unless $actual_type eq 'String';
            $value;
        } elsif ("$type" eq 'Int64') {
            my $actual_type = scalar_typer($value);
            die "TJSON expected a Int64 but got: '$actual_type'\n" unless $actual_type eq 'Int64';
            int64($value);
        } elsif ("$type" eq 'UInt64') {
            die "TJSON expected a UInt64 but got: '$value'\n" unless looks_like_number($value) == 1;
            # if 2, greater than max; if 1, less than zero
            uint64($value);
        } elsif ("$type" eq 'Timestamp') {
            # TJSON only allows a subset of RFC3339. Ex: 2016-10-02T07:31:51Z
            die "TJSON expected a RFC3339 timestamp with the upper-case UTC time zone identifier 'Z'\n" unless $value =~ /Z$/;
            DateTime::Format::RFC3339->new->parse_datetime($value);
        } elsif ("$type" eq 'Base16') {
            die "TJSON Base16 values must be all lowercase\n" if $value =~ /[A-Z]/;
            pack 'H*', $value;
        } elsif ("$type" eq 'Base32') {
            die "TJSON Base32 values must be all lowercase\n" if $value =~ /[A-Z]/;
            die "TJSON does not allow padding of Base32 values\n" if $value =~ /=$/;
            decode_base32(uc $value);	# FIXME: MIME::Base32 is a bad module
        } elsif ("$type" eq 'Base64url') {
            die "TJSON does not allow padding of Base64url values\n" if $value =~ /=$/;
            die "Invalid characters for Base64url\n" if $value =~ /[^A-Za-z0-9_-]/;
            decode_base64url($value);
        } else {
            die "oh no";
        }
    }
}

# \x01 \x02 \x0A \x10 \x12
# Int64 Double String
sub scalar_typer {
    my ($scalar, $args) = @_;
    $args->{coerce_num} //= 1;
    die "No value passed to scalar_typer" unless defined $scalar;
    die "Not a scalar: $scalar" if ref $scalar;
    my $isdual = isdual($scalar);
    my $n = looks_like_number($scalar);
    if ($isdual) {
        if ($n == 1 or $n == 9) {
            if ($scalar >= -9223372036854775808 and $scalar <= 9223372036854775807) {
                'Int64';
            } else {
                die "Integer not within signed 64 bit range: '$scalar'\n"
            }
        } elsif ($n == 5 or $n == 13) {
            'Double';
        } else {
            die "Unknown value: '$scalar' ($n)";
        }
    } else {
        # is not dual
        if ($n == 20 or $n == 28 or $n == 36) {
            $args->{inf_and_nan} ? 'Double' : 'String';
        } elsif ($n == 4352) {
            if ($scalar >= -9223372036854775808 and $scalar <= 9223372036854775807) {
                'Int64';
            } else {
                die "Integer not within signed 64 bit range: '$scalar'\n"
            }
        } elsif ($n == 8704) {
            'Double';
        } elsif ($args->{coerce_num}) {
            if ($n == 4) {
                "\x01";	# double exp
            } elsif ($n == 1 or $n == 9) {
                if ($scalar >= -9223372036854775808 and $scalar <= 9223372036854775807) {
                    'Int64';
                } else {
                    die "Integer not within signed 64 bit range: '$scalar'"
                }
            } elsif ($n == 5 or $n == 13) {
                'Double';
            } elsif ($n == 0) {
                'String';
            } else {
                die "Unknown value: '$scalar' ($n)";
            }
        } elsif ($n == 0 or $n == 1 or $n == 4 or $n == 5 or $n == 9 or $n == 13) {
            'String';
        } else {
            die "Unknown value: '$scalar' ($n)";
        }
    }
}


# undefined tags but valid: decimal numbers, true, false, null
sub parse_tag {
    my ($tag) = @_;
    if ($tag eq 'O') {	# Object
        TJSON::Type->new('Object');
    } elsif ($tag =~ /^[a-z][a-z0-9]*$/) {	# Scalar
        if ($tag eq 's') {
            TJSON::Type->new('String');
        } elsif ($tag eq 'i') {
            TJSON::Type->new('Int64');
        } elsif ($tag eq 'u') {
            TJSON::Type->new('UInt64');
        } elsif ($tag eq 't') {
            TJSON::Type->new('Timestamp');
        } elsif ($tag eq 'b16') {
            TJSON::Type->new('Base16');		# lowercase hex
        } elsif ($tag eq 'b32') {
            TJSON::Type->new('Base32');		# lowercase	MIME::Base32 is broken and only works with uppercase, but spec is case-insensitive
        } elsif ($tag eq 'b64') {
            TJSON::Type->new('Base64url');	# MIME::Base64 qw/ encode_base64url decode_base64url /;	https://tools.ietf.org/html/rfc4648#section-5	s/+/-/g; s/\/_/g; 
        } else {
            die "Unsupported tag: '$tag'\n";
        }
    } elsif ($tag =~ /^[A-Z][a-z0-9]*<.+>$/) {	# Type Expression
        if ($tag =~ /^A<(.+)>$/) {
            my $subtag = $1;
            #bless { type => 'Array', subtype => parse_tag($subtag) }, 'TJSON::Type';
            #bless { subtype => parse_tag($subtag) }, 'TJSON::Type::Array';
            TJSON::Type->new('Array', parse_tag($subtag));
        } else {
            die "Unsupported tag: '$tag'\n";
        }
    } else {
        die "Unsupported tag: '$tag'\n";
    }
}

package TJSON::Type;

use overload '""' => sub { $_[0]->{type} };
sub new {
    my ($class, $type, $subtype) = @_;
    bless { type => $type, subtype => $subtype }, $class;
}

1;

__END__

$object_tag = qr/O/;
$scalar_tag = qr/[a-z][a-z0-9]*/;
$non_scalar_tag = qr/[A-Z][a-z0-9]*/;
$type_expression = qr/$non_scalar_tag<$tag>/;
$tag = qr/(?:$type_expression|$scalar_tag|$object_tag)/;


$tag = qw/(?: [A-Z][a-z0-9]*<$tag> | [a-z][a-z0-9]* | O )/x;

__END__

# https://tools.ietf.org/html/rfc7159 (JSON)
char = unescaped /
          escape (
              %x22 /          ; "    quotation mark  U+0022
              %x5C /          ; \    reverse solidus U+005C
              %x2F /          ; /    solidus         U+002F
              %x62 /          ; b    backspace       U+0008
              %x66 /          ; f    form feed       U+000C
              %x6E /          ; n    line feed       U+000A
              %x72 /          ; r    carriage return U+000D
              %x74 /          ; t    tab             U+0009
              %x75 4HEXDIG )  ; uXXXX                U+XXXX

      escape = %x5C              ; \

      quotation-mark = %x22      ; "

      unescaped = %x20-21 / %x23-5B / %x5D-10FFFF

unescaped = All valid Unicode characters starting at SPACE, except for " and \
            These may be escaped via: \" and \\
            The SLASH may also be escaped, but does not have to be: \/ or /
            The only valid control characters are: \b \f \r \n \t
