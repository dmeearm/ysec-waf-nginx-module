with-debug:
	cd $(shell pwd)/../../../../ && ./configure --without-mail_pop3_module --without-mail_smtp_module --without-mail_imap_module --without-http_uwsgi_module --without-http_scgi_module --with-pcre=$(shell pwd)/../../../../../../../pcre-8.33 --with-pcre-opt="-g -O1" --with-pcre-jit --add-module=$(shell pwd) --with-debug && make -j6 && make install

without-debug:
	cd $(shell pwd)/../../../../ && ./configure --add-module=$(shell pwd) --without-mail_pop3_module --without-mail_smtp_module --without-mail_imap_module --without-http_uwsgi_module --without-http_scgi_module --with-pcre=$(shell pwd)/../../../../../../../pcre-8.33 --with-pcre-jit && make -j6 && make install

without-jit:
	cd $(shell pwd)/../../../../ && ./configure --add-module=$(shell pwd) --without-mail_pop3_module --without-mail_smtp_module --without-mail_imap_module --without-http_uwsgi_module --without-http_scgi_module --with-pcre=$(shell pwd)/../../../../../../../pcre-8.33 --with-pcre-opt="-g -O1" --with-debug && make -j6 && make install

with-pcre-lib:
	cd $(shell pwd)/../../../../ && ./configure --add-module=$(shell pwd) --without-mail_pop3_module --without-mail_smtp_module --without-mail_imap_module --without-http_uwsgi_module --without-http_scgi_module --with-pcre --with-pcre-jit --with-debug && make -j6 && make install

without-pcre-lib:
	cd $(shell pwd)/../../../../ && ./configure --add-module=$(shell pwd) --without-mail_pop3_module --without-mail_smtp_module --without-mail_imap_module --without-http_uwsgi_module --without-http_scgi_module --without-http_rewrite_module --with-debug && make -j6 && make install

nginx:
	cd $(shell pwd)/../../../../ && make && make install

clean:
	cd $(shell pwd)/../../../../ && make clean

test:
	prove -r t/*.t
