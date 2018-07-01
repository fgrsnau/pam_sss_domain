DESTDIR :=

pam_sss_domain.so: pam_sss_domain.c
	gcc -fPIC -shared -o $@ $^ -lpam

.PHONY: clean
clean:
	rm -f pam_sss_domain.so

.PHONY: install
install: pam_sss_domain.so
	install -m 0755 -d $(DESTDIR)/usr/lib/security
	install -m 0644 -t $(DESTDIR)/usr/lib/security pam_sss_domain.so
