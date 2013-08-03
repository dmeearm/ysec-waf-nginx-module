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
--- error_code: 412

=== TEST 3: Regex
--- config
location / {
    basic_rule regex:<script[^>]*> msg:test pos:ARGS gids:XSS;
    root $TEST_NGINX_SERVROOT/html/;
    index index.html index.htm;
}
--- request
GET /?a="<script>alert(1)</script>"
--- error_code: 412

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
--- error_code: 412

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

=== TEST 6: LEV, log
--- config
location / {
    basic_rule regex:<script[^>]*> msg:test pos:ARGS gids:XSS lev:LOG;
    root $TEST_NGINX_SERVROOT/html/;
    index index.html index.htm;
}
--- request
GET /?a="<script>alert(1)</script>"
--- error_code: 200

=== TEST 7: LEV, block
--- config
location / {
    basic_rule regex:<script[^>]*> msg:test pos:ARGS gids:XSS lev:BLOCK;
    root $TEST_NGINX_SERVROOT/html/;
    index index.html index.htm;
}
--- request
GET /?a="<script>alert(1)</script>"
--- error_code: 412

=== TEST 7: LEV, log and block
--- config
location / {
    basic_rule regex:<script[^>]*> msg:test pos:ARGS gids:XSS lev:LOG|BLOCK;
    root $TEST_NGINX_SERVROOT/html/;
    index index.html index.htm;
}
--- request
GET /?a="<script>alert(1)</script>"
--- error_code: 412

=== TEST 8: yy_sec_waf flag
--- config
location / {
    yy_sec_waf off;
    basic_rule regex:<script[^>]*> msg:test pos:ARGS gids:XSS lev:LOG|BLOCK;
    root $TEST_NGINX_SERVROOT/html/;
    index index.html index.htm;
}
--- request
GET /?a="<script>alert(1)</script>"
--- error_code: 200

=== TEST 9: basic post
--- user_files
>>> foobar
eh yo
--- config
location / {
    yy_sec_waf off;
    basic_rule regex:<script[^>]*> msg:test pos:ARGS|HEADER gids:XSS lev:LOG|BLOCK;
    root $TEST_NGINX_SERVROOT/html/;
    index index.html index.htm;
    error_page 405 = $uri;
}
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- request eval
use URI::Escape;
"POST /
foo1=ba%%2f%3c%3D%3%D%33%DD%FF%2F%3cr1&foo2=bar2"
--- error_code: 200
