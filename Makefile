with-debug:
	cd $(shell pwd)/../../../../ && $(shell chmod +x $(shell pwd)/../../../../../3rdParty/*/configure) \
		./configure --user=www-data --group=www-data --prefix=/usr/local/nginx \
		--add-module=$(shell pwd) \
		--add-module=$(shell pwd)/../../../../../3rdParty/nginx_upstream_hash \
		--add-module=$(shell pwd)/../../../../../3rdParty/simpl-ngx_devel_kit \
		--add-module=$(shell pwd)/../../../../../3rdParty/set-misc-nginx-module \
		--add-module=$(shell pwd)/../../../../../3rdParty/echo-nginx-module \
		--add-module=$(shell pwd)/../../../../../3rdParty/memc-nginx-module \
		--add-module=$(shell pwd)/../../../../../3rdParty/srcache-nginx-module \
		--add-module=$(shell pwd)/../../../../../3rdParty/redis2-nginx-module \
		--add-module=$(shell pwd)/../../../../../3rdParty/ngx_http_redis \
		--add-module=$(shell pwd)/../../../../../3rdParty/nginx-http-concat \
		--with-zlib=$(shell pwd)/../../../../../3rdParty/zlib-1.2.8 \
		--with-openssl=$(shell pwd)/../../../../../3rdParty/openssl-1.0.1e \
		--with-pcre=$(shell pwd)/../../../../../3rdParty/pcre-8.33 \
		--with-pcre-opt="-g -O1" \
		--with-pcre-jit \
		--without-mail_pop3_module \
		--without-mail_smtp_module \
		--without-mail_imap_module \
		--without-http_uwsgi_module \
		--without-http_scgi_module \
		--with-http_realip_module \
		--with-http_addition_module \
		--with-http_sub_module \
		--with-http_dav_module \
		--with-http_flv_module \
		--with-http_mp4_module \
		--with-http_gzip_static_module \
		--with-http_random_index_module \
		--with-http_secure_link_module \
		--with-file-aio \
		--with-http_stub_status_module \
		--with-http_ssl_module \
		--with-debug && make

without-debug:
	cd $(shell pwd)/../../../../ && $(shell chmod +x $(shell pwd)/../../../../../3rdParty/*/configure) \
		./configure --user=www-data --group=www-data --prefix=/usr/local/nginx \
		--add-module=$(shell pwd) \
		--add-module=$(shell pwd)/../../../../../3rdParty/nginx_upstream_hash \
		--without-mail_pop3_module \
		--without-mail_smtp_module \
		--without-mail_imap_module \
		--without-http_uwsgi_module \
		--without-http_scgi_module \
		--with-http_stub_status_module \
		--with-http_ssl_module \
		--with-zlib=$(shell pwd)/../../../../../3rdParty/zlib-1.2.8 \
		--with-openssl=$(shell pwd)/../../../../../3rdParty/openssl-1.0.1e \
		--with-pcre=$(shell pwd)/../../../../../3rdParty/pcre-8.33 \
		--with-pcre-opt="-g -O2" \
		--with-pcre-jit \
		--with-debug && make

with-pcre-lib:
	cd $(shell pwd)/../../../../ && ./configure --add-module=$(shell pwd) --without-mail_pop3_module --without-mail_smtp_module --without-mail_imap_module --without-http_uwsgi_module --without-http_scgi_module --with-http_stub_status_module --with-http_ssl_module --with-pcre --with-pcre-jit && make -j6
nginx:
	cd $(shell pwd)/../../../../ && make -j6

clean:
	cd $(shell pwd)/../../../../ && make clean

test:
	prove -r t/*.t

install:
	cd $(shell pwd)/../../../../ && make install
