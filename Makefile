with-debug:
	cd $(shell pwd)/../../../../ && ./configure \
		--add-module=$(shell pwd) \
		--add-module=$(shell pwd)/../../../../../../3rdParty/nginx_upstream_hash \
		--without-mail_pop3_module \
		--without-mail_smtp_module \
		--without-mail_imap_module \
		--without-http_uwsgi_module \
		--without-http_scgi_module \
		--with-http_stub_status_module \
		--with-http_ssl_module \
		--with-zlib=$(shell pwd)/../../../../../../3rdParty/zlib-1.2.8 \
		--with-openssl=$(shell pwd)/../../../../../../3rdParty/openssl-1.0.1e \
		--with-pcre=$(shell pwd)/../../../../../../3rdParty/pcre-8.33 \
		--with-pcre-opt="-g -O1" \
		--with-pcre-jit \
		--with-debug && make

without-debug:
	cd $(shell pwd)/../../../../ && ./configure --add-module=$(shell pwd) --without-mail_pop3_module --without-mail_smtp_module --without-mail_imap_module --without-http_uwsgi_module --without-http_scgi_module --with-http_stub_status_module --with-http_ssl_module --with-pcre=$(shell pwd)/../../../../../../../pcre-8.33 --with-pcre-opt="-O2" --with-pcre-jit && make

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
