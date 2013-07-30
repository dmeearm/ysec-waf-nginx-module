with-debug:
	cd $(shell pwd)/../../../../ && ./configure --add-module=$(shell pwd) --without-mail_pop3_module --without-mail_smtp_module --without-mail_imap_module --without-http_uwsgi_module --without-http_scgi_module --with-pcre=$(shell pwd)/../../../../../../../pcre-8.33 --with-pcre-opt="-g -O1" --with-pcre-jit --with-debug && make && make install

without-debug:
	cd $(shell pwd)/../../../../ && ./configure --add-module=$(shell pwd) --without-mail_pop3_module --without-mail_smtp_module --without-mail_imap_module --without-http_uwsgi_module --without-http_scgi_module --with-pcre=$(shell pwd)/../../../../../../../pcre-8.33 --with-pcre-opt="-O2" --with-pcre-jit && make && make install

with-pcre-lib:
	cd $(shell pwd)/../../../../ && ./configure --add-module=$(shell pwd) --without-mail_pop3_module --without-mail_smtp_module --without-mail_imap_module --without-http_uwsgi_module --without-http_scgi_module --with-pcre --with-pcre-jit && make -j6 && make install
nginx:
	cd $(shell pwd)/../../../../ && make -j6&& make install

clean:
	cd $(shell pwd)/../../../../ && make clean

test:
	prove -r t/*.t

