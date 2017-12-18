all-local: module

module: mod_authz_zakautho.c
		if test "$(srcdir)" != "."; then $(CP) $(srcdir)/mod_authz_zakautho.c .; fi
		$(APXS) -c `echo $(MOD_AUTHZ_ZAKAUTHO_CFLAGS) $(MOD_AUTHZ_ZAKAUTHO_LIBS) | sed 's/-pthread//g'` mod_authz_zakautho.c

install-exec-local: module
		mkdir -p "$(DESTDIR)`$(APXS) -q LIBEXECDIR`"
		$(APXS) -S LIBEXECDIR="$(DESTDIR)`$(APXS) -q LIBEXECDIR`" -i `echo $(MOD_AUTHZ_ZAKAUTHO_CFLAGS) $(MOD_AUTHZ_ZAKAUTHO_LIBS) | sed 's/-pthread//g'` -n authz_zakautho_module mod_authz_zakautho.la

install-exec-hook:
		test -z "$(STRIP)" || $(STRIP) $(DESTDIR)`$(APXS) -q LIBEXECDIR`/mod_authz_zakautho.so

CLEANFILES=         *.la *.lo *.o *.so *.slo .libs/*

EXTRA_DIST=         CHANGES LICENSE mod_authz_zakautho.c
