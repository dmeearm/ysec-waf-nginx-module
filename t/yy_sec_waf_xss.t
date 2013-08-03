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
=== TEST 1: script tag
--- config
location / {
    include ../../../yy_sec_waf.conf;
    root $TEST_NGINX_SERVROOT/html/;
    index index.html index.htm;
}
--- request
GET /?a="<script>alert(1)</script>"
--- error_code: 412

