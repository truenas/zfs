SUBDIRS  = zfs zpool zdb zhack zinject zstream zstreamdump ztest
SUBDIRS += fsck_zfs vdev_id raidz_test zfs_ids_to_path

CPPCHECKDIRS  = zfs zpool zdb zhack zinject zstream ztest
CPPCHECKDIRS += raidz_test zfs_ids_to_path

if USING_PYTHON
SUBDIRS += arcstat arc_summary dbufstat
endif

if BUILD_LINUX
SUBDIRS += mount_zfs zed zgenhostid zvol_id zvol_wait
CPPCHECKDIRS += mount_zfs zed zgenhostid zvol_id
endif

if BUILD_FREEBSD
SUBDIRS += zfsd
CPPCHECKDIRS += zfsd
endif

PHONY = cppcheck
cppcheck: $(CPPCHECKDIRS)
	set -e ; for dir in $(CPPCHECKDIRS) ; do \
		$(MAKE) -C $$dir cppcheck ; \
	done
