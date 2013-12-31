#vi:filetype=perl

use lib 'lib';
use Test::Nginx::Socket;

repeat_each(3);

plan tests => repeat_each(1) * blocks();
no_root_location();
no_long_string();
$ENV{TEST_NGINX_SERVROOT} = server_root();
run_tests();

__DATA__
=== TEST 1: status
--- config
location / {
    basic_rule ARGS regex:foobar phase:1 status:500 lev:LOG|BLOCK;
    root $TEST_NGINX_SERVROOT/html/;
    index index.html index.htm;
}
--- request
GET /?t=foobar
--- error_code: 500

=== TEST 1: default status
--- config
location / {
    basic_rule ARGS regex:foobar phase:1 lev:LOG|BLOCK;
    root $TEST_NGINX_SERVROOT/html/;
    index index.html index.htm;
}
--- request
GET /?t=foobar
--- error_code: 412
