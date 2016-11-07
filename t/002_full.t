#!/usr/bin/env perl

use 5.12.0;
use warnings;

use Test::More tests => 58;
use Test::Deep qw/ cmp_deeply /;

use TJSON;

use Math::Int64 qw/int64 uint64 :die_on_overflow/;
use Time::Moment;
use boolean;

# Tests via https://github.com/tjson/tjson-spec/blob/master/draft-tjson-examples.txt with additions

cmp_deeply decode_tjson('{}'), {}, 'Empty Object';
cmp_deeply decode_tjson('{"example:s":"foobar"}'), {example => 'foobar'}, 'Object with UTF-8 String Key';
cmp_deeply decode_tjson('{"example:A<i>": ["1", "2", "3"]}'), { example => [ int64(1), int64(2), int64(3) ] }, 'Array of integers';
cmp_deeply decode_tjson('{"example:A<O>": [{"a:i": "1"}, {"b:i": "2"}]}'), { example => [ { a => int64(1) }, { b => int64(2) } ] }, 'Array of objects';
cmp_deeply decode_tjson('{"example:A<A<i>>": [["1", "2"], ["3", "4"], ["5", "6"]]}'), { example => [ [ int64(1), int64(2) ], [ int64(3), int64(4) ], [ int64(5), int64(6) ] ] }, 'Multidimensional array of integers';
cmp_deeply decode_tjson('{"example:b16":"48656c6c6f2c20776f726c6421"}'), { example => 'Hello, world!' }, 'Base16 Binary Data';
cmp_deeply decode_tjson('{"example:b32":"jbswy3dpfqqho33snrscc"}'), { example => 'Hello, world!' }, 'Base32 Binary Data';
cmp_deeply decode_tjson('{"example:b64":"SGVsbG8sIHdvcmxkIQ"}'), { example => 'Hello, world!' }, 'Base64url Binary Data';
cmp_deeply decode_tjson('{"example:i":"42"}'), { example => int64(42) }, 'Signed Integer';
cmp_deeply decode_tjson('{"min:i":"-9223372036854775808", "max:i":"9223372036854775807"}'), { min => int64('-9223372036854775808'), max => int64('9223372036854775807') }, 'Signed Integer Range Test';
cmp_deeply decode_tjson('{"example:u":"42"}'), { example => uint64(42) }, 'Unsigned Integer';
cmp_deeply decode_tjson('{"maxint:u":"18446744073709551615"}'), { maxint => uint64('18446744073709551615') }, 'Unsigned Integer Range Test';
cmp_deeply decode_tjson('{"example:t":"2016-10-02T07:31:51Z"}'), { example => DateTime::Format::RFC3339->new->parse_datetime('2016-10-02T07:31:51Z') }, 'Timestamp';

undef $@; eval { decode_tjson '1' }; is $@, "TJSON allows only object as the top-level element\n", 'Invalid Toplevel Number (CUSTOM)';
undef $@; eval { decode_tjson 'null' }; is $@, "TJSON allows only object as the top-level element\n", 'Invalid Toplevel Null Value (CUSTOM)';
undef $@; eval { decode_tjson 'true' }; is $@, "TJSON allows only object as the top-level element\n", 'Invalid Toplevel Boolean (CUSTOM)';
undef $@; eval { decode_tjson 'false' }; is $@, "TJSON allows only object as the top-level element\n", 'Invalid Toplevel Boolean (CUSTOM)';
undef $@; eval { decode_tjson '"foo"' }; is $@, "TJSON allows only object as the top-level element\n", 'Invalid Toplevel String (CUSTOM)';
undef $@; eval { decode_tjson '[]' }; is $@, "TJSON allows only object as the top-level element\n", 'Invalid Toplevel Array';
undef $@; eval { decode_tjson '{"example":"foobar"}' }; is $@, "TJSON requires all keys be tagged\n", 'Invalid Object with Untagged Name';
undef $@; eval { decode_tjson '{"example:":"foobar"}' }; is $@, "TJSON requires all keys be tagged\n", 'Invalid Object with Empty Tag';
undef $@; eval { decode_tjson '{"example:i":"1","example:i":"2"}' }; like $@, qr/^Duplicate keys not allowed,/, 'Invalid Object with Repeated Member Names';
undef $@; eval { decode_tjson '{"example:i":"1","example:i":"1"}' }; like $@, qr/^Duplicate keys not allowed,/, 'Invalid Object with Repeated Member Names and Values';
undef $@; eval { decode_tjson '{"example:i":"1","example:u":"2"}' }; is $@, "TJSON requires names to be distinct\n", 'Invalid Object with Repeated Member Names but Distinct Tags (CUSTOM)';
undef $@; eval { decode_tjson '{"example:b16":"48656C6C6F2C20776F726C6421"}' }; is $@, "TJSON Base16 values must be all lowercase\n", 'Invalid Base16 Binary Data with bad case';
undef $@; eval { decode_tjson '{"example:b16":"This is not a valid hexadecimal string"}' }; is $@, "TJSON Base16 values must be all lowercase\n", 'Invalid Base16 Binary Data';
undef $@; eval { decode_tjson '{"example:b32":"JBSWY3DPFQQHO33SNRSCC"}' }; is $@, "TJSON Base32 values must be all lowercase\n", 'Invalid Base32 Binary Data with bad case';
undef $@; eval { decode_tjson '{"example:b32":"jbswy3dpfqqho33snrscc==="}' }; is $@, "TJSON does not allow padding of Base32 values\n", 'Invalid Base32 Binary Data with padding';
undef $@; eval { decode_tjson '{"example:b32":"This is not a valid base32 string"}' }; is $@, "TJSON Base32 values must be all lowercase\n", 'Invalid Base32 Binary Data';
undef $@; eval { decode_tjson '{"example:b64":"SGVsbG8sIHdvcmxkIQ=="}' }; is $@, "TJSON does not allow padding of Base64url values\n", 'Invalid Base64url Binary Data with padding';
undef $@; eval { decode_tjson '{"example:b64":"+/+/"}' }; is $@, "Invalid characters for Base64url\n", 'Invalid Base64url Binary Data with non-URL safe characters';
undef $@; eval { decode_tjson '{"example:b64":"This is not a valid base64url string"}' }; is $@, "Invalid characters for Base64url\n", 'Invalid Base64url Binary Data';
undef $@; eval { decode_tjson '{"oversize:i":"9223372036854775808"}' }; like $@, qr/^Integer not within signed 64 bit range: /, 'Oversized Signed Integer Test';
undef $@; eval { decode_tjson '{"undersize:i":"-9223372036854775809"}' }; like $@, qr/^Math::Int64 overflow: Number is out of bounds for int64_t conversion/, 'Undersized Signed Integer Test';
undef $@; eval { decode_tjson '{"invalid:i":"This is not a valid integer"}' }; is $@, "TJSON expected a Int64 but got: 'String'\n", 'Invalid Signed Integer';
undef $@; eval { decode_tjson '{"oversized:u":"18446744073709551616"}' }; is $@, "TJSON expected a UInt64 but got: '18446744073709551616'\n", 'Oversized Unsigned Integer Test';
undef $@; eval { decode_tjson '{"negative:u":"-1"}' }; is $@, "TJSON expected a UInt64 but got: '-1'\n", 'Negative Unsigned Integer Test';
undef $@; eval { decode_tjson '{"invalid:u":"This is not a valid integer"}' }; is $@, "TJSON expected a UInt64 but got: 'This is not a valid integer'\n", 'Invalid Unsigned Integer';
undef $@; eval { decode_tjson '{"invalid:t":"2016-10-02T07:31:51-08:00"}' }; is $@, "TJSON expected a RFC3339 timestamp with the upper-case UTC time zone identifier 'Z'\n", 'Timestamp With Invalid Time Zone';
undef $@; eval { decode_tjson '{"invalid:t":"This is not a valid timestamp"}' }; is $@, "TJSON expected a RFC3339 timestamp with the upper-case UTC time zone identifier 'Z'\n", 'Invalid Timestamp';

# coerce tests:
is encode_tjson({}), '{}', 'Empty Object';
is encode_tjson({ example => 'foobar' }), '{"example:s":"foobar"}', 'Object with UTF-8 String Key';
is encode_tjson({ example => [ int64(1), int64(2), int64(3) ] }), '{"example:A<i>":["1","2","3"]}', 'Array of integers';
is encode_tjson({ example => [ { a => int64(1) }, { b => int64(2) } ] }), '{"example:A<O>":[{"a:i":"1"},{"b:i":"2"}]}', 'Array of objects';
is encode_tjson({ example => [ [ int64(1), int64(2) ], [ int64(3), int64(4) ], [ int64(5), int64(6) ] ] }), '{"example:A<A<i>>":[["1","2"],["3","4"],["5","6"]]}', 'Multidimensional array of integers';
# N/A: is encode_tjson({ example => 'Hello, world!' }), '{"example:b16":"48656c6c6f2c20776f726c6421"}', 'Base16 Binary Data';
# N/A: is encode_tjson({ example => 'Hello, world!' }), '{"example:b32":"jbswy3dpfqqho33snrscc"}', 'Base32 Binary Data';
# N/A: is encode_tjson({ example => 'Hello, world!' }), '{"example:b64":"SGVsbG8sIHdvcmxkIQ"}', 'Base64url Binary Data';
is encode_tjson({ example => int64(42) }), '{"example:i":"42"}', 'Signed Integer';
is encode_tjson({ min => int64('-9223372036854775808') }), '{"min:i":"-9223372036854775808"}', 'Signed Integer Mininum Test';
is encode_tjson({ max => int64('9223372036854775807') }), '{"max:i":"9223372036854775807"}', 'Signed Integer Maximum Test';
is encode_tjson({ example => uint64(42) }), '{"example:u":"42"}', 'Unsigned Integer';
is encode_tjson({ maxint => uint64('18446744073709551615') }), '{"maxint:u":"18446744073709551615"}', 'Unsigned Integer Range Test';
is encode_tjson({ example => DateTime::Format::RFC3339->new->parse_datetime('2016-10-02T07:31:51Z') }), '{"example:t":"2016-10-02T07:31:51Z"}', 'Timestamp';

undef $@; eval { encode_tjson(1) }; is $@, "TJSON allows only object as the top-level element\n", 'Invalid Toplevel Number (CUSTOM)';
undef $@; eval { encode_tjson(undef) }; is $@, "TJSON allows only object as the top-level element\n", 'Invalid Toplevel Null Value (CUSTOM)';
undef $@; eval { encode_tjson(true) }; is $@, "TJSON allows only object as the top-level element\n", 'Invalid Toplevel Boolean (CUSTOM)';
undef $@; eval { encode_tjson(false) }; is $@, "TJSON allows only object as the top-level element\n", 'Invalid Toplevel Boolean (CUSTOM)';
undef $@; eval { encode_tjson("foo") }; is $@, "TJSON allows only object as the top-level element\n", 'Invalid Toplevel String (CUSTOM)';
undef $@; eval { encode_tjson([]) }; is $@, "TJSON allows only object as the top-level element\n", 'Invalid Toplevel Array';
# N/A: undef $@; eval { encode_tjson({"example":"foobar"}) }; is $@, "TJSON requires all keys be tagged\n", 'Invalid Object with Untagged Name';
# N/A: undef $@; eval { encode_tjson({"example:":"foobar"}) }; is $@, "TJSON requires all keys be tagged\n", 'Invalid Object with Empty Tag';
# N/A: undef $@; eval { encode_tjson({"example:i":"1","example:i":"2"}) }; like $@, qr/^Duplicate keys not allowed,/, 'Invalid Object with Repeated Member Names';
# N/A: undef $@; eval { encode_tjson({"example:i":"1","example:i":"1"}) }; like $@, qr/^Duplicate keys not allowed,/, 'Invalid Object with Repeated Member Names and Values';
# N/A: undef $@; eval { encode_tjson({"example:i":"1","example:u":"2"}) }; is $@, "TJSON requires names to be distinct\n", 'Invalid Object with Repeated Member Names but Distinct Tags (CUSTOM)';
# N/A: undef $@; eval { encode_tjson({"example:b16":"48656C6C6F2C20776F726C6421"}) }; is $@, "TJSON Base16 values must be all lowercase\n", 'Invalid Base16 Binary Data with bad case';
# N/A: undef $@; eval { encode_tjson({"example:b16":"This is not a valid hexadecimal string"}) }; is $@, "TJSON Base16 values must be all lowercase\n", 'Invalid Base16 Binary Data';
# N/A: undef $@; eval { encode_tjson({"example:b32":"JBSWY3DPFQQHO33SNRSCC"}) }; is $@, "TJSON Base32 values must be all lowercase\n", 'Invalid Base32 Binary Data with bad case';
# N/A: undef $@; eval { encode_tjson({"example:b32":"jbswy3dpfqqho33snrscc==="}) }; is $@, "TJSON does not allow padding of Base32 values\n", 'Invalid Base32 Binary Data with padding';
# N/A: undef $@; eval { encode_tjson({"example:b32":"This is not a valid base32 string"}) }; is $@, "TJSON Base32 values must be all lowercase\n", 'Invalid Base32 Binary Data';
# N/A: undef $@; eval { encode_tjson({"example:b64":"SGVsbG8sIHdvcmxkIQ=="}) }; is $@, "TJSON does not allow padding of Base64url values\n", 'Invalid Base64url Binary Data with padding';
# N/A: undef $@; eval { encode_tjson({"example:b64":"+/+/"}) }; is $@, "Invalid characters for Base64url\n", 'Invalid Base64url Binary Data with non-URL safe characters';
# N/A: undef $@; eval { encode_tjson({"example:b64":"This is not a valid base64url string"}) }; is $@, "Invalid characters for Base64url\n", 'Invalid Base64url Binary Data';
undef $@; eval { encode_tjson({oversize => 9223372036854775808}) }; like $@, qr/^Integer not within signed 64 bit range:/, 'Oversized Signed Integer Test';
# UNTESTABLE: gets turned into -9.22337203685478e+18 by Perl: undef $@; eval { encode_tjson({undersize => -9223372036854775809}) }; like $@, qr/^Integer not within signed 64 bit range:/, 'Undersized Signed Integer Test';
# N/A: undef $@; eval { encode_tjson({"invalid:i":"This is not a valid integer"}) }; is $@, "TJSON expected a Int64 but got: 'String'\n", 'Invalid Signed Integer';
# UNTESTABLE: gets turned into 1.84467440737096e+19 by Perl: undef $@; eval { encode_tjson({oversized: => 18446744073709551616}) }; like $@, qr/Integer not within unsigned 64 bit range:/, 'Oversized Unsigned Integer Test';
# N/A: undef $@; eval { encode_tjson({"negative:u":"-1"}) }; is $@, "TJSON expected a UInt64 but got: '-1'\n", 'Negative Unsigned Integer Test';
# N/A: undef $@; eval { encode_tjson({"invalid:u":"This is not a valid integer"}) }; is $@, "TJSON expected a UInt64 but got: 'This is not a valid integer'\n", 'Invalid Unsigned Integer';
# N/A: undef $@; eval { encode_tjson({"invalid:t":"2016-10-02T07:31:51-08:00"}) }; is $@, "TJSON expected a RFC3339 timestamp with the upper-case UTC time zone identifier 'Z'\n", 'Timestamp With Invalid Time Zone';
# N/A: undef $@; eval { encode_tjson({"invalid:t":"This is not a valid timestamp"}) }; is $@, "TJSON expected a RFC3339 timestamp with the upper-case UTC time zone identifier 'Z'\n", 'Invalid Timestamp';

#done_testing;

__END__

say 'TESTING FOR SUCCESS';
for my $json (@VALID) {
#    my $data = Cpanel::JSON::XS->new->utf8->allow_nonref->disallow_dupkeys->decode($json);
    try {
#        my $hash = decode_tjson $json;
        my $hash = TJSON->new->decode($json);
        say "SUCCESS: $json";
        warn Dumper $hash;
    } catch {
        warn $_;
        say "FAILED: $json";
    };
}



my @INVALID = (
    '1',
    'null',
    'true',
    'false',
    '"foo"',
    '[]',
    '{"example":"foobar"}',
    '{"example:":"foobar"}',
    '{"example:i":"1","example:i":"2"}',
    '{"example:i":"1","example:i":"1"}',
    '{"example:i":"1","example:u":"2"}',
    '{"example:b16":"48656C6C6F2C20776F726C6421"}',	# NOTE: uppercase
    '{"example:b16":"This is not a valid hexadecimal string"}',
    '{"example:b32":"JBSWY3DPFQQHO33SNRSCC"}',
    '{"example:b32":"jbswy3dpfqqho33snrscc==="}',
    '{"example:b32":"This is not a valid base32 string"}',
    '{"example:b64":"SGVsbG8sIHdvcmxkIQ=="}',
    '{"example:b64":"+/+/"}',				# must be Base64url, not traditional Base64
    '{"example:b64":"This is not a valid base64url string"}',
    '{"oversize:i":"9223372036854775808"}',
    '{"undersize:i":"-9223372036854775809"}',
    '{"invalid:i":"This is not a valid integer"}',
    '{"oversized:u":"18446744073709551616"}',
    '{"negative:u":"-1"}',
    '{"invalid:u":"This is not a valid integer"}',
    '{"invalid:t":"2016-10-02T07:31:51-08:00"}',
    '{"invalid:t":"This is not a valid timestamp"}',
);


















use 5.12.0;
use warnings;

use Cpanel::JSON::XS;
use Data::Dumper;
use File::Path qw/remove_tree/;
use File::Slurp;
use MongoDB;
use Net::HTTP::Client;
use POSIX qw(setsid);
use Try::Tiny::Retry;

use lib 'lib';
use Disbatch;
use Disbatch::Roles;
use Disbatch::Web;

my $use_ssl = $ENV{USE_SSL} // 1;
my $use_auth = $ENV{USE_AUTH} // 1;

unless ($ENV{AUTHOR_TESTING}) {
    plan skip_all => 'Skipping author tests';
    exit;
}

sub get_free_port {
    my ($port, $sock);
    do {
        $port = int rand()*32767+32768;
        $sock = IO::Socket::INET->new(Listen => 1, ReuseAddr => 1, LocalAddr => 'localhost', LocalPort => $port, Proto => 'tcp')
                or warn "\n# cannot bind to port $port: $!";
    } while (!defined $sock);
    $sock->shutdown(2);
    $sock->close();
    $port;
}

my $mongoport = get_free_port;

# define config and make up a database name:
my $config = {
    mongohost => "localhost:$mongoport",
    database => "disbatch_test$$" . int(rand(10000)),
    attributes => { ssl => { SSL_verify_mode => 0x00 } },
    auth => {
        disbatchd => 'qwerty1',		# { username => 'disbatchd', password => 'qwerty1' },
        disbatch_web => 'qwerty2',	# { username => 'disbatch_web', password => 'qwerty2' },
        task_runner => 'qwerty3',	# { username => 'task_runner', password => 'qwerty3' },
        plugin => 'qwerty4',		# { username => 'plugin', password => 'qwerty3' },
    },
    plugins => [ 'Disbatch::Plugin::Demo' ],
    web_root => 'etc/disbatch/htdocs/',
    task_runner => './bin/task_runner',
    log4perl => {
        level => 'TRACE',
        appenders => {
            filelog => {
                type => 'Log::Log4perl::Appender::File',
                layout => '[%p] %d %F{1} %L %C %c> %m %n',
                args => { filename => 'disbatchd.log' },
            },
            screenlog => {
                type => 'Log::Log4perl::Appender::ScreenColoredLevels',
                layout => '[%p] %d %F{1} %L %C %c> %m %n',
                args => { },
            }
        }
    },
};
delete $config->{auth} unless $use_auth;
delete $config->{attributes} unless $use_ssl;

mkdir "/tmp/$config->{database}";
my $config_file = "/tmp/$config->{database}/config.json";
write_file $config_file, encode_json $config;

say "database = $config->{database}";

my @mongo_args = (
    '--logpath' => "/tmp/$config->{database}/mongod.log",
    '--dbpath' => "/tmp/$config->{database}/",
    '--pidfilepath' => "/tmp/$config->{database}/mongod.pid",
    '--port' => $mongoport,
    '--noprealloc',
    '--nojournal',
    '--fork'
);
push @mongo_args, $use_auth ? '--auth' : '--noauth';
push @mongo_args, '--sslMode' => 'requireSSL', '--sslPEMKeyFile' => 't/test-cert.pem', if $use_ssl;
my $mongo_args = join ' ', @mongo_args;
say `mongod $mongo_args`;	# FIXME: use system or IPC::Open3 instead

# Get test database, authed as root:
my $attributes = {};
$attributes->{ssl} = $config->{attributes}{ssl} if $use_ssl;
if ($use_auth) {
    my $admin = MongoDB->connect($config->{mongohost}, $attributes)->get_database('admin');
    retry { $admin->run_command([createUser => 'root', pwd => 'kjfiwey76r3gjm', roles => [ { role => 'root', db => 'admin' } ]]) } catch { die $_ };
    $attributes->{username} = 'root';
    $attributes->{password} = 'kjfiwey76r3gjm';
}
my $test_db_root = retry { MongoDB->connect($config->{mongohost}, $attributes)->get_database($config->{database}) } catch { die $_ };

# Create roles and users for a database:
my $plugin_perms = { reports => [ 'insert' ] };	# minimal permissions for Disbatch::Plugin::Demo
Disbatch::Roles->new(db => $test_db_root, plugin_perms => $plugin_perms, %{$config->{auth}})->create_roles_and_users if $use_auth;

# Create users collection:
for my $username (qw/ foo bar /) {
    retry { $test_db_root->coll('users')->insert({username => $username, migration => 'test'}) } catch { die $_ };
}

# Ensure indexes:
my $disbatch = Disbatch->new(class => 'Disbatch', config_file => $config_file);
$disbatch->load_config;
$disbatch->ensure_indexes;

# make sure node document exists:
$disbatch->update_node_status;	# FIXME: add tests for this

#####################################
# Start web:
sub daemonize {
    open STDIN, '<', '/dev/null'  or die "can't read /dev/null: $!";
    open STDOUT, '>', '/dev/null' or die "can't write to /dev/null: $!";
    defined(my $pid = fork)       or die "can't fork: $!";
    return $pid if $pid;
    setsid != -1                  or die "Can't start a new session: $!";
    open STDERR, '>&', 'STDOUT'   or die "can't dup stdout: $!";
    0;
}

my $webport = get_free_port;

my $webpid = daemonize();
if ($webpid == 0) {
    Disbatch::Web::init(config_file => $config_file);
    Disbatch::Web::limp({workers => 5}, LocalPort => $webport);
    die "This shouldn't have happened";
} else {
    # Run tests:
    my $uri = "localhost:$webport";
    my ($res, $data, $content);

    my $queueid;	# OID
    my $threads;	# integer
    my $name;	# queue name
    my $plugin;	# plugin name
    my $object;	# array of task parameter objects
    my $collection;	# name of the MongoDB collection to query
    my $filter;	# query. If you want to query by OID, use the key "id" and not "_id"
    my $params;	# object of task params. To insert a document value from a query into the params, prefix the desired key name with "document." as a value.
    my $limit;	# integer
    my $skip;	# integer
    my $count;	# boolean
    my $terse;	# boolean

    $name = 'test_queue';
    $plugin = $config->{plugins}[0];

    # make sure web server is running:
    retry { Net::HTTP::Client->request(GET => "$uri/") } catch { die $_ };

    ### BROWSER ROUTES ###

    # Returns the contents of "/index.html" – the queue browser page.
    $res = Net::HTTP::Client->request(GET => "$uri/");
    is $res->status_line, '200 OK', '200 status';
    is $res->content_type, 'text/html', 'text/html';

    # Returns the contents of the request path.
    $res = Net::HTTP::Client->request(GET => "$uri/js/queues.js");
    is $res->status_line, '200 OK', '200 status';
    is $res->content_type, 'application/javascript', 'application/javascript';

    ### GET JSON ROUTES ####

    # Returns array of queues.
    # Each item has the following keys: id, plugin, name, threads, queued, running, completed
    $res = Net::HTTP::Client->request(GET => "$uri/scheduler-json");
    is $res->status_line, '200 OK', '200 status';
    is $res->content_type, 'application/json', 'application/json';
    is $res->content, '[]', 'empty array';

    # Returns an object where both keys and values are values of currently defined plugins in queues.
    $res = Net::HTTP::Client->request(GET => "$uri/queue-prototypes-json");
    is $res->status_line, '200 OK', '200 status';
    is $res->content_type, 'application/json', 'application/json';
    is $res->content, "{\"$plugin\":\"$plugin\"}", 'empty hash';

    ### POST JSON ROUTES ####

    # Returns array: C<< [ success, inserted_id, $reponse_object ] >>
    $data = { name => $name, type => $plugin };
    $res = Net::HTTP::Client->request(POST => "$uri/start-queue-json", 'Content-Type' => 'application/json', encode_json($data));
    is $res->status_line, '200 OK', '200 status';
    is $res->content_type, 'application/json', 'application/json';
    $content = decode_json($res->content);
    is ref $content, 'ARRAY', 'content is ARRAY';
    is $content->[0], 1, 'success';
    $queueid = $content->[1]{'$oid'};

    # Returns array: C<< [ success, count_inserted, array_of_inserted, $reponse_object ] >> or C<< [ 0, $error_string ] >>
    # "object" is an array of task parameter objects.
    $data = { queueid => $queueid, object => [ {commands => 'a'}, {commands => 'b'}, {commands => 'c'}] };
    $res = Net::HTTP::Client->request(POST => "$uri/queue-create-tasks-json", 'Content-Type' => 'application/json', encode_json($data));
    is $res->status_line, '200 OK', '200 status';
    is $res->content_type, 'application/json', 'application/json';
    $content = decode_json($res->content);
    is ref $content, 'ARRAY', 'content is ARRAY';
    is $content->[0], 1, 'success';
    is $content->[1], 3, 'count';
    my @task_ids = map { $_->{_id}{'$oid'} } @{$content}[2..4];

    $data = { queue => $queueid, count => 1 };
    $res = Net::HTTP::Client->request(POST => "$uri/search-tasks-json", 'Content-Type' => 'application/json', encode_json($data));
    is $res->status_line, '200 OK', '200 status';
    is $res->content_type, 'application/json', 'application/json';
    $content = decode_json($res->content);
    is ref $content, 'ARRAY', 'content is ARRAY';
    is $content->[0], 1, 'success';
    is $content->[1], 3, 'count';

    $data = { queue => $queueid, count => 1, filter => { 'params.commands' => 'b' } };
    $res = Net::HTTP::Client->request(POST => "$uri/search-tasks-json", 'Content-Type' => 'application/json', encode_json($data));
    is $res->status_line, '200 OK', '200 status';
    is $res->content_type, 'application/json', 'application/json';
    $content = decode_json($res->content);
    is ref $content, 'ARRAY', 'content is ARRAY';
    is $content->[0], 1, 'success';
    is $content->[1], 1, 'count';

    # Returns array of tasks (empty if there is an error in the query), C<< [ status, $count_or_error ] >> if "count" is true, or C<< [ 0, error ] >> if other error.
    # All parameters are optional.
    # "filter" is the query. If you want to query by Object ID, use the key "id" and not "_id".
    # "limit" and "skip" are integers.
    # "count" and "terse" are booleans.
    $data = { queue => $queueid, filter => $filter, limit => $limit, skip => $skip, terse => $terse };
    $res = Net::HTTP::Client->request(POST => "$uri/search-tasks-json", 'Content-Type' => 'application/json', encode_json($data));
    is $res->status_line, '200 OK', '200 status';
    is $res->content_type, 'application/json', 'application/json';
    $content = decode_json($res->content);
    is ref $content, 'ARRAY', 'content is ARRAY';
    #say Dumper $content;

    # Returns array: C<< [ success, count_inserted ] >> or C<< [ 0, $error_string ] >>
    # "collection" is the name of the MongoDB collection to query.
    # "jsonfilter" is the query.
    # "params" is an object of task params. To insert a document value from a query into the params, prefix the desired key name with C<document.> as a value.
    $collection = 'users';
    $filter = { migration => 'test' };
    $params = { user1 => 'document.username', migration => 'document.migration', commands => '*' };
    $data =  { queueid => $queueid, collection => $collection, jsonfilter => $filter, params => $params };
    $res = Net::HTTP::Client->request(POST => "$uri/queue-create-tasks-from-query-json", 'Content-Type' => 'application/json', encode_json($data));
    is $res->status_line, '200 OK', '200 status';
    is $res->content_type, 'application/json', 'application/json';
    $content = decode_json($res->content);
    is ref $content, 'ARRAY', 'content is ARRAY';
    is $content->[0], 1, 'success';
    is $content->[1], 2, 'count inserted';

    $res = Net::HTTP::Client->request(GET => "$uri/scheduler-json");
    is $res->status_line, '200 OK', '200 status';
    is $res->content_type, 'application/json', 'application/json';
    $content = decode_json($res->content);
    is ref $content, 'ARRAY', 'content is ARRAY';
    is scalar @$content, 1, 'size';
    is $content->[0]{id}, $queueid, 'id';
    is $content->[0]{plugin}, $plugin, 'plugin';
    is $content->[0]{name}, 'test_queue', 'name';
    is $content->[0]{threads}, undef, 'threads';
    is $content->[0]{queued}, 5, 'queued';
    is $content->[0]{running}, 0, 'running';
    is $content->[0]{completed}, 0, 'completed';

    # Returns C<< { "success": 1, ref $res: Object } >> or C<< { "success": 0, "error": error } >>
    $data = { queueid => $queueid, attr => 'threads', value => 1 };
    $res = Net::HTTP::Client->request(POST => "$uri/set-queue-attr-json", 'Content-Type' => 'application/json', encode_json($data));
    is $res->status_line, '200 OK', '200 status';
    is $res->content_type, 'application/json', 'application/json';
    $content = decode_json($res->content);
    is ref $content, 'HASH', 'content is HASH';
    is $content->{success}, 1, 'success';

    $res = Net::HTTP::Client->request(GET => "$uri/scheduler-json");
    is $res->status_line, '200 OK', '200 status';
    is $res->content_type, 'application/json', 'application/json';
    $content = decode_json($res->content);
    is ref $content, 'ARRAY', 'content is ARRAY';
    is scalar @$content, 1, 'size';
    is $content->[0]{threads}, 1, 'threads';

    # Returns an object where both keys and values are values of currently defined plugins in queues.
    $res = Net::HTTP::Client->request(GET => "$uri/queue-prototypes-json");
    is $res->status_line, '200 OK', '200 status';
    is $res->content_type, 'application/json', 'application/json';
    is $res->content, "{\"$plugin\":\"$plugin\"}", 'defined plugins';

    # This will run 1 task:
    $disbatch->validate_plugins;
    $disbatch->process_queues;

    # Make sure queue count updated:
    $data = { queue => $queueid, count => 1, filter => { status => -2 } };
    $res = Net::HTTP::Client->request(POST => "$uri/search-tasks-json", 'Content-Type' => 'application/json', encode_json($data));
    is $res->status_line, '200 OK', '200 status';
    is $res->content_type, 'application/json', 'application/json';
    $content = decode_json($res->content);
    is ref $content, 'ARRAY', 'content is ARRAY';
    is $content->[0], 1, 'success';
    is $content->[1], 4, 'count';

    # Get report for task:
    my $report = retry { $disbatch->mongo->coll('reports')->find_one() or die 'No report found' } catch { warn $_; {} };	# status done task_id
    is $report->{status}, 'SUCCESS', 'report success';

    # Get task of report:
    my $task = $disbatch->tasks->find_one({_id => $report->{task_id}});
    is $task->{status}, 1, 'task success';

    # Returns array: C<< [ success, $error_string_or_reponse_object ] >>
    $data = { id => $queueid };
    $res = Net::HTTP::Client->request(POST => "$uri/delete-queue-json", 'Content-Type' => 'application/json', encode_json($data));
    is $res->status_line, '200 OK', '200 status';
    is $res->content_type, 'application/json', 'application/json';
    $content = decode_json($res->content);
    is ref $content, 'ARRAY', 'content is ARRAY';
    is $content->[0], 1, 'success';
    is $content->[1]{'MongoDB::DeleteResult'}{deleted_count}, 1, 'count';

    done_testing;
}

END {
    # Cleanup:
    if (defined $config and $config->{database}) {
        kill -9, $webpid if $webpid;
        my $pidfile = "/tmp/$config->{database}/mongod.pid";
        if (-e $pidfile) {
            my $mongopid = read_file $pidfile;
            chomp $mongopid;
            kill 9, $mongopid;
        }
        remove_tree "/tmp/$config->{database}";
    }
}
