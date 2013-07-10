nginx:
	cd $(shell pwd)/../../../../ && make -j6&& make install
with:
	cd $(shell pwd)/../../../../ && ./configure --add-module=$(shell pwd) --with-pcre=$(shell pwd)/../pcre-8.33 --with-zlib=$(shell pwd)/../zlib-1.2.8 --without-mail_pop3_module --without-mail_smtp_module --without-mail_imap_module --without-http_uwsgi_module --without-http_scgi_module --with-debug && make -j6 && make install
