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
    basic_rule ARGS regex:script phase:2 id:1001 msg:test gids:XSS lev:LOG|BLOCK;

    root $TEST_NGINX_SERVROOT/html/;
    index index.html index.htm;
}
--- request
GET /
--- error_code: 200

=== TEST 2: DENY: Short Char Rule
--- config
location / {
    basic_rule ARGS str:script phase:2 id:1001 msg:test gids:XSS lev:LOG|BLOCK;
    root $TEST_NGINX_SERVROOT/html/;
    index index.html index.htm;
}
--- request
GET /?a="<script>alert(1)</script>"
--- error_code: 412

=== TEST 3: Regex
--- config
location / {
    basic_rule ARGS regex:script phase:2 id:1001 msg:test gids:XSS lev:LOG|BLOCK;
    root $TEST_NGINX_SERVROOT/html/;
    index index.html index.htm;
}
--- request
GET /?a="<script>alert(1)</script>"
--- error_code: 412

=== TEST 4: Multi Rules
--- config
location / {
    basic_rule ARGS regex:script phase:2 id:1001 msg:test gids:XSS lev:LOG|BLOCK;
    basic_rule ARGS regex:test phase:2 id:1002 msg:test gids:XSS lev:LOG|BLOCK;
    root $TEST_NGINX_SERVROOT/html/;
    index index.html index.htm;
}
--- request
GET /?a="<script>alert(1)</script>"
--- error_code: 412

=== TEST 6: LEV, log
--- config
location / {
    basic_rule ARGS regex:script phase:2 id:1001 msg:test gids:XSS lev:LOG;
    root $TEST_NGINX_SERVROOT/html/;
    index index.html index.htm;
}
--- request
GET /?a="<script>alert(1)</script>"
--- error_code: 200

=== TEST 7: LEV, block
--- config
location / {
    basic_rule ARGS regex:script phase:2 id:1001 msg:test gids:XSS lev:BLOCK;
    root $TEST_NGINX_SERVROOT/html/;
    index index.html index.htm;
}
--- request
GET /?a="<script>alert(1)</script>"
--- error_code: 412

=== TEST 8: yy_sec_waf, off
--- config
location / {
    yy_sec_waf off;
    basic_rule ARGS regex:script phase:2 id:1001 msg:test gids:XSS lev:BLOCK;
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
    basic_rule ARGS regex:script phase:2 id:1001 msg:test gids:XSS lev:LOG|BLOCK;
    root $TEST_NGINX_SERVROOT/html/;
    index index.html index.htm;
    error_page 405 = $uri;
}
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- request eval
use URI::Escape;
"POST /
foo1=%3Cscript%3E&foo2=bar2"
--- error_code: 412
