#
#===============================================================================
#
#  DESCRIPTION: test 
#
#        FILES:  ---
#         BUGS:  ---
#        NOTES:  ---
#       AUTHOR:  Weibin Yao (http://yaoweibin.cn/), yaoweibin@gmail.com
#      COMPANY:  
#      VERSION:  1.0
#      CREATED:  03/02/2010 03:18:28 PM
#     REVISION:  ---
#===============================================================================


# vi:filetype=perl

use lib 'lib';
use Test::Nginx::LWP;

plan tests => repeat_each() * 2 * blocks();

#no_diff;

run_tests();

__DATA__

=== TEST 1: the simple_get succful test
--- config
server {
    listen       1982;
    server_name  localhost;

    location  /{
        secure_cookie $cookie_CAPTCHA_SESSION,$cookie_CAPTCHA_EXPIRES;
        secure_cookie_md5 private_key$binary_remote_addr$cookie_CAPTCHA_EXPIRES;

        if ($secure_cookie = "") {
            return 403;
        }

        if ($secure_cookie = "0") {
            return 404;
        }

        root   html;
        index  index.html index.htm;
    }
}
--- request_headers
Cookie: CAPTCHA_SESSION=ejVtUc+8FfjNd2TfCuxzOw==; CAPTCHA_EXPIRES=Mon, 04-Jan-16 06:41:02 GMT
--- request
GET /
--- response_body_like: ^.*$

=== TEST 2: the simple_get test of bad CAPTCHA_SESSION
--- config
server {
    listen       1982;
    server_name  localhost;

    location  /{
        secure_cookie $cookie_CAPTCHA_SESSION,$cookie_CAPTCHA_EXPIRES;
        secure_cookie_md5 private_key$binary_remote_addr$cookie_CAPTCHA_EXPIRES;

        if ($secure_cookie = "") {
            return 403;
        }

        if ($secure_cookie = "0") {
            return 404;
        }

        root   html;
        index  index.html index.htm;
    }
}
--- request_headers
Cookie: CAPTCHA_SESSION=jVtUc+8FfjNd2TfCuxzOw==; CAPTCHA_EXPIRES=Mon, 04-Jan-16 06:41:02 GMT
--- request
GET /
--- error_code: 403
--- response_body_like: ^.*$

=== TEST 3: the simple_get test of bad CAPTCHA_EXPIRES
--- config
server {
    listen       1982;
    server_name  localhost;

    location  /{
        secure_cookie $cookie_CAPTCHA_SESSION,$cookie_CAPTCHA_EXPIRES;
        secure_cookie_md5 private_key$binary_remote_addr$cookie_CAPTCHA_EXPIRES;

        if ($secure_cookie = "") {
            return 403;
        }

        if ($secure_cookie = "0") {
            return 404;
        }

        root   html;
        index  index.html index.htm;
    }
}
--- request_headers
Cookie: CAPTCHA_SESSION=ejVtUc+8FfjNd2TfCuxzOw==; CAPTCHA_EXPIRES=Mon, 4-Jan-16 06:41:02 GMT
--- request
GET /
--- error_code: 403
--- response_body_like: ^.*$
