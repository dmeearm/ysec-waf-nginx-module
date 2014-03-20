NGINX_PATH=nginx-1.2.3

with-debug:
		$(shell chmod +x ../3rdparty/*/configure ../$(NGINX_PATH)/configure) \
		cd $(NGINX_PATH) && ./configure --prefix=/usr/local/nginx \
		--add-module=../ \
		--add-module=../3rdparty/nginx_upstream_hash \
		--add-module=../3rdparty/simpl-ngx_devel_kit \
		--add-module=../3rdparty/set-misc-nginx-module \
		--add-module=../3rdparty/echo-nginx-module \
		--add-module=../3rdparty/memc-nginx-module \
		--add-module=../3rdparty/srcache-nginx-module \
		--add-module=../3rdparty/redis2-nginx-module \
		--add-module=../3rdparty/lua-nginx-module \
		--add-module=../3rdparty/ngx_http_redis \
		--add-module=../3rdparty/nginx-http-concat \
		--with-zlib=../3rdparty/zlib-1.2.8 \
		--with-pcre=../3rdparty/pcre-8.33 \
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
	$(shell chmod +x ./3rdparty/*/configure) \
		cd $(NGINX_PATH) && ./configure --user=www-data --group=www-data --prefix=/usr/local/nginx \
		--add-module=. \
		--add-module=../3rdparty/nginx_upstream_hash \
		--without-mail_pop3_module \
		--without-mail_smtp_module \
		--without-mail_imap_module \
		--without-http_uwsgi_module \
		--without-http_scgi_module \
		--with-http_stub_status_module \
		--with-http_ssl_module \
		--with-zlib=../3rdparty/zlib-1.2.8 \
		--with-openssl=../3rdparty/openssl-1.0.1e \
		--with-pcre=../3rdparty/pcre-8.33 \
		--with-pcre-opt="-g -O2" \
		--with-pcre-jit \
		--with-debug && make

mac:
	$(shell chmod +x ./3rdparty/*/configure) \
		cd $NGINX_PATH && ./configure --prefix=/usr/local/nginx \
		--add-module=$(shell pwd) \
		--add-module=$(shell pwd)/../echo-nginx-module \
		--without-mail_pop3_module \
		--without-mail_smtp_module \
		--without-mail_imap_module \
		--without-http_uwsgi_module \
		--without-http_scgi_module \
		--with-http_stub_status_module \
		--with-pcre-opt="-g -O2" \
        --with-pcre-jit \
		--with-debug && make


with-pcre-lib:
	cd $NGINX_PATH && ./configure --add-module=. --without-mail_pop3_module --without-mail_smtp_module --without-mail_imap_module --without-http_uwsgi_module --without-http_scgi_module --with-http_stub_status_module --with-http_ssl_module --with-pcre --with-pcre-jit && make -j6
nginx:
	cd $NGINX_PATH && make -j6

clean:
	cd $NGINX_PATH && make clean

test:
	prove -r t/*.t

install:
	cd $NGINX_PATH && make install
