pam_sss_domain.so: pam_sss_domain.c
	gcc -fPIC -shared -o $@ $^ -lpam

.PHONY: clean
clean:
	rm -f pam_sss_domain.so
