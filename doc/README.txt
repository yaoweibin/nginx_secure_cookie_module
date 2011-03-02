Name
    nginx_secure_cookie_module - support secure cookie with Nginx

Status
    This module is at its very early phase of development and considered
    highly experimental. But you're encouraged to test it out on your side
    and report any quirks that you experience.

    We need your help! If you find this module useful and/or interesting,
    please consider joining the development!

examples
  a simple example
    This module is usally used with the reCAPTCHA module, See also:
    https://github.com/yaoweibin/nginx_http_recaptcha_module

    location / {

        secure_cookie $cookie_CAPTCHA_SESSION,$cookie_CAPTCHA_EXPIRES;
        secure_cookie_md5 private_key$binary_remote_addr$cookie_CAPTCHA_EXPIRES;

        if ($cookie_CAPTCHA_SESSION = "") {
            rewrite ^.*$ http://the_captcha_server/ redirect;
        }

        if ($cookie_CAPTCHA_EXPIRES = "") {
            rewrite ^.*$ http://the_captcha_server/ redirect;
        }

        if ($secure_cookie = "") {
            return 403;
        }

        if ($secure_cookie = "0") {
            rewrite ^.*$ http://the_captcha_server/ redirect;
        }

        root   html;
        index  index.html index.htm;
    }

     #You can add a captcha page here or in another server. If the user 
     #pass the verification, then you can add this secure cookie by 
     #Nginx or by your application.

    location /set_secure_cookie {

        internal;
        secure_expires  3600;
        secure_cookie_md5 private_key$binary_remote_addr$secure_cookie_set_expires_base64;

        add_header Set-Cookie "CAPTCHA_SESSION=$secure_cookie_set_md5; expires=$secure_cookie_set_expires; path=/; domain=.yourhost.com";
        add_header Set-Cookie "CAPTCHA_EXPIRES=$secure_cookie_set_expires_base64; expires=$secure_cookie_set_expires; path=/; domain=.yourhost.com";

        rewrite ^.*$ http://www.your_host.com/index.html last;

        return 302;
    }

    And the request example is like this:

     $wget -d --header="Cookie: CAPTCHA_SESSION=uHYYvMzm4m2WQweGD8nu2g==; CAPTCHA_EXPIRES=TW9uLCAyOS1GZWItMTYgMDg6NDQ6NTkgR01U" http://your_host/

Description
    Add the support of secure cookie with Nginx. This module can be used to
    add and verify secure cookie for some real requests and deny any
    malevolent request.

Directives
  secure_cookie
    syntax:*secure_cookie $md5_hash[,$expires_time_base64]*

    default: *none*

    context: *http, server, location*

    description: This directive specifies the MD5 hash value and the expires
    time of this secure cookie. The $md5_hash should equal to the hash value
    of string which specified by "secure_cookie_md5". The $expires_time is
    the expires time of this cookie. It is specified in the "Wdy,
    DD-Mon-YYYY HH:MM:SS GMT" format and encoded by base64. If you did not
    add the $expires_time, then the secure cookie will never be expired.

  secure_cookie_md5
    syntax:*secure_cookie_md5 $the_string_you_want_to_hashed_by_md5*

    default: *none*

    context: *http, server, location*

    description: This directive specifies the string you want to be hashed
    by MD5. The string can include variables. The hash equation is like
    this:

    hash_string := base64(md5($the_string_you_want_to_hashed_by_md5));

  secure_cookie_expires
    syntax:*secure_cookie_expires expires_time*

    default: *none*

    context: *http, server, location*

    description: Set the expires time for the secure cookie. It's used to
    produce the variable $secure_cookie_set_expires. Default expire time is
    1 day. The unit of time can be: s(second,default), m(minute), h(hour),
    d(day), w(week), M(month), y(year).

Variables
  $secure_cookie
    description: The hash value computed from secure_cookie_md5 compares
    with the $md5_hash which specified by "secure_cookie". If the result is
    the same, the variable of $secure_cookie is '1'. If the local time has
    exceeded the $expires_time, $secure_cookie is equal to '0'. Otherwise,
    it's null string.

  $secure_cookie_set_md5
    description: The result of hash value with the string specified in the
    directive "secure_cookie_md5".

  $secure_cookie_set_expires
    description: This variable equals to current time plus the expires time
    which set by "secure_cookie_expires". The format is also like "Wdy,
    DD-Mon-YYYY HH:MM:SS GMT".

  $secure_cookie_set_expires_base64
    description: This variable is the base64 value of
    $secure_cookie_set_expires.

Installation
    Download the latest version of the release tarball of this module from
    github (<https://github.com/yaoweibin/nginx_secure_cookie_module>).

    Grab the nginx source code from nginx.org (<http://nginx.org/>), for
    example, the version 0.8.54 (see nginx compatibility), and then build
    the source with this module:

        $ wget 'http://nginx.org/download/nginx-0.8.54.tar.gz'
        $ tar -xzvf nginx-0.8.54.tar.gz
        $ cd nginx-0.8.54/

        $ ./configure --add-module=/path/to/nginx_secure_cookie_module 

        $ make
        $ make install

Compatibility
    *   My test bed is 0.8.54.

TODO
Known Issues
    *   Developing

Changelogs
  v0.1
    *   first release

Authors
    Weibin Yao(姚伟斌) *yaoweibin at gmail dot com*

Copyright & License
    I borrow most of the code from the nginx_secure_link_module
    (<http://wiki.nginx.org/HttpSecureLinkModule>).

    This README template copy from agentzh (<http://github.com/agentzh>).

    This module is licensed under the BSD license.

    Copyright (C) 2010 by Weibin Yao <yaoweibin@gmail.com>.

    All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are
    met:

    *   Redistributions of source code must retain the above copyright
        notice, this list of conditions and the following disclaimer.

    *   Redistributions in binary form must reproduce the above copyright
        notice, this list of conditions and the following disclaimer in the
        documentation and/or other materials provided with the distribution.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
    IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
    TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
    PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
    HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
    SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
    TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
    PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
    LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
    NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
    SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

