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
=== TEST 1: Basic GET request
--- config
location / {
    basic_rule regex:<script[^>]*> msg:test pos:ARGS gids:XSS;
    root $TEST_NGINX_SERVROOT/html/;
    index index.html index.htm;
}
--- request
GET /
--- error_code: 200

=== TEST 2: DENY: Short Char Rule
--- config
location / {
    basic_rule regex:<script[^>]*> msg:test pos:ARGS gids:XSS;
    root $TEST_NGINX_SERVROOT/html/;
    index index.html index.htm;
}
--- request
GET /?a="<script>alert(1)</script>"
--- error_code: 403

=== TEST 3: Regex
--- config
location / {
    basic_rule regex:<script[^>]*> msg:test pos:ARGS gids:XSS;
    root $TEST_NGINX_SERVROOT/html/;
    index index.html index.htm;
}
--- request
GET /?a="<script>alert(1)</script>"
--- error_code: 403

=== TEST 4: Multi Rules
--- config
location / {
    basic_rule str:< msg:test pos:BODY|ARGS gids:XSS;
    basic_rule regex:<script[^>]*> msg:test pos:BODY|ARGS gids:XSS;
    root $TEST_NGINX_SERVROOT/html/;
    index index.html index.htm;
}
--- request
GET /?a="<script>alert(1)</script>"
--- error_code: 403

=== TEST 5: POS, Not in Args pos
--- config
location / {
    basic_rule regex:<script[^>]*> msg:test pos:BODY gids:XSS;
    root $TEST_NGINX_SERVROOT/html/;
    index index.html index.htm;
}
--- request
GET /?a="<script>alert(1)</script>"
--- error_code: 200

