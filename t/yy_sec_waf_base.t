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
    include /home/liqi/yy-sec-waf-1.2.3/yy_sec_waf.conf;
    root $TEST_NGINX_SERVROOT/html/;
    index index.html index.htm;
}
--- request
GET /
--- error_code: 200

=== TEST 2: DENY: Short Char Rule
--- config
location / {
    include /home/liqi/yy-sec-waf-1.2.3/yy_sec_waf.conf;
    root $TEST_NGINX_SERVROOT/html/;
    index index.html index.htm;
}
--- request
GET /?a="<script>alert(1)</script>"
--- error_code: 412

=== TEST 3: Regex
--- config
location / {
    include /home/liqi/yy-sec-waf-1.2.3/yy_sec_waf.conf;
    root $TEST_NGINX_SERVROOT/html/;
    index index.html index.htm;
}
--- request
GET /?a="<script>alert(1)</script>"
--- error_code: 412

=== TEST 4: Multi Rules
--- config
location / {
    include /home/liqi/yy-sec-waf-1.2.3/yy_sec_waf.conf;
    root $TEST_NGINX_SERVROOT/html/;
    index index.html index.htm;
}
--- request
GET /?a="<script>alert(1)</script>"
--- error_code: 412

=== TEST 6: LEV, log
--- config
location / {
    include /home/liqi/yy-sec-waf-1.2.3/yy_sec_waf.conf;
    root $TEST_NGINX_SERVROOT/html/;
    index index.html index.htm;
}
--- request
GET /?a="<script>alert(1)</script>"
--- error_code: 412

=== TEST 7: LEV, block
--- config
location / {
    include /home/liqi/yy-sec-waf-1.2.3/yy_sec_waf.conf;
    root $TEST_NGINX_SERVROOT/html/;
    index index.html index.htm;
}
--- request
GET /?a="<script>alert(1)</script>"
--- error_code: 412

=== TEST 9: basic post
--- user_files
>>> foobar
eh yo
--- config
location / {
    include /home/liqi/yy-sec-waf-1.2.3/yy_sec_waf.conf;
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
