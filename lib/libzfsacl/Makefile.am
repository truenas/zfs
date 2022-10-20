dist_noinst_DATA += \
	%D%/sunacl.h \
	%D%/libzfsacl.h \
	%D%/libpyzfsacl.c \
	%D%/libsunacl.c \
	%D%/libzfsacl_impl_freebsd.c \
	%D%/libzfsacl_impl_linux.c

SUBSTFILES += %D%/setup.py

ALL_LOCAL += libzfsacl-all-local
libzfsacl-all-local: %D%/setup.py
	cd %D% && $(PYTHON) setup.py egg_info -e . build

INSTALL_DATA_HOOKS += libzfsacl-install-data-hook
libzfsacl-install-data-hook:
	cd %D% && $(PYTHON) setup.py egg_info -e . install \
	  --prefix $(prefix) \
	  --root $(DESTDIR)/ \
	  --install-lib $(pythonsitedir) \
	  --verbose

CLEAN_LOCAL += libzfsacl-clean-local
libzfsacl-clean-local:
	-$(RM) -r %D%/build/
