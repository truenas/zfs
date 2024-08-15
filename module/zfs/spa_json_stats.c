/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://opensource.org/licenses/CDDL-1.0.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright (c) 2024, Klara Inc.
 */

#include <sys/zfs_context.h>
#include <sys/spa_impl.h>
#include <sys/vdev_impl.h>
#include <sys/spa.h>
#include <zfs_comutil.h>
#include <sys/spa_json_stats.h>
#include <sys/nvpair_impl.h>
#include <sys/vdev_draid.h>

#define	JSON_STATUS_VERSION	4

static const char *
vdev_state_string(vdev_state_t state, vdev_aux_t aux)
{
	const char *s;
	switch (state) {
	case VDEV_STATE_UNKNOWN:	s = "ONLINE";    break;
	case VDEV_STATE_CLOSED:		s = "CLOSED";	  break;
	case VDEV_STATE_OFFLINE:	s = "OFFLINE";    break;
	case VDEV_STATE_REMOVED:	s = "REMOVED";    break;
	case VDEV_STATE_CANT_OPEN:
		if (aux == VDEV_AUX_CORRUPT_DATA || aux == VDEV_AUX_BAD_LOG)
			s = "FAULTED";
		else if (aux == VDEV_AUX_SPLIT_POOL)
			s = "SPLIT";
		else
			s = "UNAVAIL";
		break;
	case VDEV_STATE_FAULTED:	s = "FAULTED";    break;
	case VDEV_STATE_DEGRADED:	s = "DEGRADED";   break;
	case VDEV_STATE_HEALTHY:	s = "ONLINE";    break;
	default:			s = "?";
	}
	return (s);
}

static void
vdev_name(vdev_t *vd, char *buf, int len)
{
	int nparity = vdev_get_nparity(vd);
	if (vd->vdev_ops == &vdev_draid_ops &&
	    vd->vdev_ops->vdev_op_config_generate != NULL) {
		vdev_draid_config_t *vdc = vd->vdev_tsd;
		(void) snprintf(buf, len, "%s%llu:%llud:%lluc:%llus-%llu",
		    VDEV_TYPE_DRAID, (u_longlong_t)nparity, (u_longlong_t)vdc->vdc_ndata,
		    (u_longlong_t)vd->vdev_children, (u_longlong_t)vdc->vdc_nspares, (u_longlong_t)vd->vdev_id);
	} else if (vd->vdev_ops == &vdev_raidz_ops && nparity > 0) {
		(void) snprintf(buf, len, "%s%llu-%llu",
		    VDEV_TYPE_RAIDZ, (u_longlong_t)nparity, (u_longlong_t)vd->vdev_id);
	} else if (vd->vdev_ops == &vdev_disk_ops) {
		if (vd->vdev_path)
			strlcpy(buf, vd->vdev_path, len);
	} else if (vd->vdev_ops == &vdev_file_ops) {
		if (vd->vdev_path)
			strlcpy(buf, vd->vdev_path, len);
	} else if (vd->vdev_ops == &vdev_root_ops) {
			strlcpy(buf, vd->vdev_spa->spa_name, len);
	} else {
		(void) snprintf(buf, len, "%s-%llu",
		    vd->vdev_ops->vdev_op_type, (u_longlong_t)vd->vdev_id);
	}
}

static void
vdev_to_nvlist(vdev_t *vd, pool_scan_stat_t *ps, nvlist_t *tree, const char *class)
{
	uint64_t n;
	vdev_t **a;
	const char *s;
	char vname[128];
	vdev_stat_t *vs = kmem_alloc(sizeof (*vs), KM_SLEEP);
	int vsc = sizeof(vdev_stat_t) / sizeof(uint64_t);

	vdev_get_stats(vd, vs);
	vdev_name(vd, vname, 128);
	fnvlist_add_string(tree, "name", vname);
	fnvlist_add_string(tree, "vdev_type", vd->vdev_ops->vdev_op_type);
	fnvlist_add_uint64(tree, "guid", vd->vdev_guid);
	if (vd->vdev_path != NULL)
		fnvlist_add_string(tree, "path", vd->vdev_path);
	if (vd->vdev_physpath != NULL)
		fnvlist_add_string(tree, "phys_path", vd->vdev_physpath);
	if (vd->vdev_devid != NULL)
		fnvlist_add_string(tree, "devid",  vd->vdev_devid);
	if (vd->vdev_enc_sysfs_path != NULL) {
		fnvlist_add_string(tree, "enc_sysfs_path",
		    vd->vdev_enc_sysfs_path);
	}
	if (vd->vdev_islog)
		fnvlist_add_string(tree, "class", "log");
	else if (class == NULL)
		fnvlist_add_string(tree, "class", "normal");
	else
		fnvlist_add_string(tree, "class", class);
	fnvlist_add_string(tree, "state",
	    vdev_state_string(vd->vdev_state, vs->vs_aux));

	if (vs->vs_alloc)
		fnvlist_add_uint64(tree, "alloc_space", vs->vs_alloc);
	if (vs->vs_space)
		fnvlist_add_uint64(tree, "total_space", vs->vs_space);
	if (vs->vs_dspace)
		fnvlist_add_uint64(tree, "def_space", vs->vs_dspace);
	if (vs->vs_rsize)
		fnvlist_add_uint64(tree, "rep_dev_size", vs->vs_rsize);
	if (vs->vs_esize)
		fnvlist_add_uint64(tree, "ex_dev_size", vs->vs_esize);
	if (vs->vs_self_healed)
		fnvlist_add_uint64(tree, "self_healed", vs->vs_self_healed);
	if (vd->vdev_psize)
		fnvlist_add_uint64(tree, "phys_space", vd->vdev_psize);

	fnvlist_add_uint64(tree, "read_errors", vs->vs_read_errors);
	fnvlist_add_uint64(tree, "write_errors", vs->vs_write_errors);
	fnvlist_add_uint64(tree, "checksum_errors", vs->vs_checksum_errors);
	if (vs->vs_scan_processed)
		fnvlist_add_uint64(tree, "scan_processed", vs->vs_scan_processed);
	if (vs->vs_checkpoint_space)
		fnvlist_add_uint64(tree, "checkpoint_space", vs->vs_checkpoint_space);
	if (vs->vs_resilver_deferred)
		fnvlist_add_uint64(tree, "resilver_deferred", vs->vs_resilver_deferred);

	if (vd->vdev_ops->vdev_op_leaf) {
		fnvlist_add_uint64(tree, "slow_ios",
		    vs->vs_slow_ios);
	}

	fnvlist_add_uint64(tree, "dio_verify_errors", vs->vs_dio_verify_errors);
	if (vs->vs_scan_removing)
		fnvlist_add_uint64(tree, "removing", vs->vs_scan_removing);
	else if (VDEV_STAT_VALID(vs_noalloc, vsc) && vs->vs_noalloc)
		fnvlist_add_uint64(tree, "noalloc", vs->vs_noalloc);

	if (vd->vdev_ops->vdev_op_leaf) {
		if (vs->vs_initialize_state) {
			s = "NONE";
			if (vs->vs_initialize_state == VDEV_INITIALIZE_ACTIVE)
				s = "ACTIVE";
			else if (vs->vs_initialize_state == VDEV_INITIALIZE_CANCELED)
				s = "CANCELED";
			else if (vs->vs_initialize_state == VDEV_INITIALIZE_SUSPENDED)
				s = "SUSPENDED";
			else if (vs->vs_initialize_state == VDEV_INITIALIZE_COMPLETE)
				s = "COMPLETE";
			fnvlist_add_string(tree, "init_state", s);
			fnvlist_add_uint64(tree, "initialized:",
				vs->vs_initialize_bytes_done);
			fnvlist_add_uint64(tree, "to_initialize",
				vs->vs_initialize_bytes_est);
			fnvlist_add_uint64(tree, "init_time",
				vs->vs_initialize_action_time);
			fnvlist_add_uint64(tree, "init_errors",
				vs->vs_initialize_errors);
		} else {
			fnvlist_add_string(tree, "init_state",
			    "UNINITIALIZED");
		}

		if (vs->vs_trim_notsup == 0) {
			if (vs->vs_trim_state) {
				s = "UNTRIMMED";
				if (vs->vs_trim_state == VDEV_TRIM_ACTIVE)
					s = "ACTIVE";
				else if (vs->vs_trim_state == VDEV_TRIM_CANCELED)
					s = "CANCELED";
				else if (vs->vs_trim_state == VDEV_TRIM_SUSPENDED)
					s = "SUSPENDED";
				else if (vs->vs_trim_state == VDEV_TRIM_COMPLETE)
					s = "COMPLETE";
				fnvlist_add_string(tree, "trim_state", s);
				fnvlist_add_uint64(tree, "trimmed",
					vs->vs_trim_bytes_done);
				fnvlist_add_uint64(tree, "to_trim",
					vs->vs_trim_bytes_est);
				fnvlist_add_uint64(tree, "trim_time",
					vs->vs_trim_action_time);
				fnvlist_add_uint64(tree, "trim_errors",
				    vs->vs_trim_errors);
			} else {
				fnvlist_add_string(tree, "trim_state",
				    "UNTRIMMED");
			}
		}
		fnvlist_add_uint64(tree, "trim_notsup", vs->vs_trim_notsup);
	}

	if (vd != vd->vdev_spa->spa_root_vdev) {
		n = vd->vdev_children;
		a = vd->vdev_child;
		if (n != 0) {
			nvlist_t *ch = fnvlist_alloc();
			for (uint64_t i = 0; i < n; ++i) {
				nvlist_t *x = fnvlist_alloc();
				vdev_to_nvlist(a[i], ps, x, class);
				if (!nvlist_empty(x)) {
					vdev_name(a[i], vname, 128);
					fnvlist_add_nvlist(ch, vname, x);
				}
				fnvlist_free(x);
			}
			if (!nvlist_empty(ch))
				fnvlist_add_nvlist(tree, "vdevs", ch);
			fnvlist_free(ch);
		}
	}
}

static void
iterate_vdevs(spa_t *spa, pool_scan_stat_t *ps, nvlist_t *nvl)
{
	char vname[128];
	vdev_t *v = spa->spa_root_vdev;
	nvlist_t *vt = fnvlist_alloc();
	nvlist_t *prv = fnvlist_alloc();
	nvlist_t *rv = fnvlist_alloc();
	nvlist_t *vdevs = fnvlist_alloc();

	if (v == NULL) {
		zfs_dbgmsg("error: NO ROOT VDEV");
		return;
	}
	vdev_to_nvlist(v, ps, prv, NULL);
	vdev_to_nvlist(*v->vdev_child, ps, rv, NULL);
	vdev_name(*v->vdev_child, vname, 128);
	fnvlist_add_nvlist(vdevs, vname, rv);
	fnvlist_add_nvlist(prv, "vdevs", vdevs);
	fnvlist_add_nvlist(vt, spa->spa_name, prv);
	fnvlist_free(rv);
	fnvlist_free(prv);
	fnvlist_free(vdevs);

	vdev_t **rchild = v->vdev_child;
	uint64_t nrchildren = v->vdev_children;
	const char *bias = NULL;
	for (uint64_t i = 0; i < nrchildren; i++) {
		if (rchild[i]->vdev_alloc_bias != VDEV_BIAS_NONE) {
			nvlist_t *b = fnvlist_alloc();
			nvlist_t *x = fnvlist_alloc();
			switch (rchild[i]->vdev_alloc_bias) {
			case VDEV_BIAS_LOG:
				bias = VDEV_ALLOC_BIAS_LOG;
				break;
			case VDEV_BIAS_SPECIAL:
				bias = VDEV_ALLOC_BIAS_SPECIAL;
				break;
			case VDEV_BIAS_DEDUP:
				bias = VDEV_ALLOC_BIAS_DEDUP;
				break;
			default:
				ASSERT3U(rchild[i]->vdev_alloc_bias, ==,
				    VDEV_BIAS_NONE);
			}
			vdev_to_nvlist(rchild[i], ps, x, bias);
			vdev_name(rchild[i], vname, 128);
			fnvlist_add_nvlist(b, vname, x);
			fnvlist_add_nvlist(vt, bias, b);
			fnvlist_free(x);
			fnvlist_free(b);
		}
	}

	int nl2cache = spa->spa_l2cache.sav_count;
	if (nl2cache != 0) {
		nvlist_t *l2 = fnvlist_alloc();
		for (int i = 0; i < nl2cache; i++) {
			v = spa->spa_l2cache.sav_vdevs[i];
			nvlist_t *l = fnvlist_alloc();
			vdev_to_nvlist(v, ps, l, "l2cache");
			vdev_name(v, vname, 128);
			fnvlist_add_nvlist(l2, vname, l);
			fnvlist_free(l);
		}
		fnvlist_add_nvlist(vt, ZPOOL_CONFIG_L2CACHE, l2);
		fnvlist_free(l2);
	}

	int nspares = spa->spa_spares.sav_count;
	if (nspares != 0) {
		nvlist_t *sp = fnvlist_alloc();
		for (int i = 0; i < nspares; i++) {
			v = spa->spa_spares.sav_vdevs[i];
			nvlist_t *s = fnvlist_alloc();
			vdev_to_nvlist(v, ps, s, "spare");
			vdev_name(v, vname, 128);
			fnvlist_add_nvlist(sp, vname, s);
			fnvlist_free(s);
		}
		fnvlist_add_nvlist(vt, ZPOOL_CONFIG_SPARES, sp);
		fnvlist_free(sp);
	}
	fnvlist_add_nvlist(nvl, "vdevs", vt);
	fnvlist_free(vt);
}

//static const char *
//pss_func_to_string(uint64_t n)
//{
//	const char *s = "?";
//	switch (n) {
//		case POOL_SCAN_NONE:		s = "NONE";	break;
//		case POOL_SCAN_SCRUB:		s = "SCRUB";	break;
//		case POOL_SCAN_RESILVER:	s = "RESILVER";	break;
//		case POOL_SCAN_FUNCS:		s = "?";
//	}
//	return (s);
//}
//
//static const char *pss_state_to_string(uint64_t n)
//{
//	const char *s = "?";
//	switch (n) {
//		case DSS_NONE:		s = "NONE";	break;
//		case DSS_SCANNING:	s = "SCANNING";	break;
//		case DSS_FINISHED:	s = "FINISHED";	break;
//		case DSS_CANCELED:	s = "CANCELED";	break;
//		case DSS_NUM_STATES:	s = "?";
//	}
//	return (s);
//}
//
//static int
//spa_props_json(spa_t *spa, nvlist_t **nvl)
//{
//	nvpair_t *curr = NULL, *item = NULL;
//	nvlist_t *prop;
//	data_type_t type;
//	char buf[256];
//	const char *name;
//	uint64_t src;
//
//	if (spa_prop_get(spa, nvl) != 0)
//		return (-1);
//
//	for (curr = nvlist_next_nvpair(*nvl, NULL); curr;
//	    curr = nvlist_next_nvpair(*nvl, curr)) {
//		if (nvpair_type(curr) == DATA_TYPE_NVLIST) {
//			prop = fnvpair_value_nvlist(curr);
//			for (item = nvlist_next_nvpair(prop, NULL); item;
//			    item = nvlist_next_nvpair(prop, item)) {
//				name = nvpair_name(item);
//				type = nvpair_type(item);
//				if ((strcmp(name, "source") == 0) &&
//				    (type == DATA_TYPE_UINT64)) {
//					src = fnvpair_value_uint64(item);
//					memset(buf, 0, 256);
//					if (src & ZPROP_SRC_NONE) {
//						if (buf[0] != '\0')
//							strcat(buf, "|");
//						strcat(buf, "ZPROP_SRC_NONE");
//					}
//					if (src & ZPROP_SRC_DEFAULT) {
//						if (buf[0] != '\0')
//							strcat(buf, "|");
//						strcat(buf,
//						    "ZPROP_SRC_DEFAULT");
//					}
//					if (src & ZPROP_SRC_TEMPORARY) {
//						if (buf[0] != '\0')
//							strcat(buf, "|");
//						strcat(buf,
//						    "ZPROP_SRC_TEMPORARY");
//					}
//					if (src & ZPROP_SRC_INHERITED) {
//						if (buf[0] != '\0')
//							strcat(buf, "|");
//						strcat(buf,
//						    "ZPROP_SRC_INHERITED");
//					}
//					if (src & ZPROP_SRC_RECEIVED) {
//						if (buf[0] != '\0')
//							strcat(buf, "|");
//						strcat(buf,
//						    "ZPROP_SRC_RECEIVED");
//					}
//					fnvlist_add_string(prop, "source", buf);
//				}
//			}
//		}
//	}
//	return (0);
//}

/*
 * Collect the spa status without any locking and return as a JSON string.
 *
 * Currently used by the 'zfs/<pool>/stats.json' kstat.
 */
int
spa_generate_json_stats(spa_t *spa, char *buf, size_t size)
{
	int error = 0;
//	int ps_error = 0;
//	char *curr = buf;
//	nvlist_t *spa_config, *spa_props = NULL, *scan_stats, *nvl;
//	uint64_t loadtimes[2];
//	pool_scan_stat_t ps;
//	int scl_config_lock;
//
//	nvl = fnvlist_alloc();
//	if (nvlist_dup(spa->spa_config, &spa_config, 0) != 0) {
//		zfs_dbgmsg("json_data: nvlist_dup failed");
//		return (0);
//	}
//	fnvlist_add_nvlist(spa_config, ZPOOL_CONFIG_LOAD_INFO,
//	    spa->spa_load_info);
//
//	scl_config_lock =
//	    spa_config_tryenter(spa, SCL_CONFIG, FTAG, RW_READER);
//
//	ps_error = spa_scan_get_stats(spa, &ps);
//	(void) ps_error;
//
//	if (spa_props_json(spa, &spa_props) == 0)
//		fnvlist_add_nvlist(spa_config, "spa_props", spa_props);
//
//	loadtimes[0] = spa->spa_loaded_ts.tv_sec;
//	loadtimes[1] = spa->spa_loaded_ts.tv_nsec;
//	fnvlist_add_uint64_array(spa_config, ZPOOL_CONFIG_LOADED_TIME,
//	    loadtimes, 2);
//	fnvlist_add_uint64(spa_config, ZPOOL_CONFIG_ERRCOUNT,
//	    spa_approx_errlog_size(spa));
//	fnvlist_add_boolean_value(spa_config, ZPOOL_CONFIG_SUSPENDED,
//	    spa_suspended(spa));
//	if (spa_suspended(spa)) {
//		const char *failmode;
//		switch (spa->spa_failmode) {
//		case ZIO_FAILURE_MODE_WAIT:
//			failmode = "wait";
//			break;
//		case ZIO_FAILURE_MODE_CONTINUE:
//			failmode = "continue";
//			break;
//		case ZIO_FAILURE_MODE_PANIC:
//			failmode = "panic";
//			break;
//		default:
//			failmode = "???";
//		}
//		fnvlist_add_string(spa_config, "failmode", failmode);
//		if (spa->spa_suspended != ZIO_SUSPEND_NONE) {
//			fnvlist_add_string(spa_config,
//			    ZPOOL_CONFIG_SUSPENDED_REASON,
//			    (spa->spa_suspended == ZIO_SUSPEND_MMP) ?
//			    "MMP" : "IO");
//		}
//	}
//
//	fnvlist_add_uint32(nvl, "status_json_version", JSON_STATUS_VERSION);
//	fnvlist_add_boolean_value(nvl, "scl_config_lock", scl_config_lock != 0);
//	fnvlist_add_uint32(nvl, "scan_error", ps_error);
//
//	scan_stats = fnvlist_alloc();
//	if (ps_error == 0) {
//		fnvlist_add_string(scan_stats, "func",
//		    pss_func_to_string(ps.pss_func));
//		fnvlist_add_string(scan_stats, "state",
//		    pss_state_to_string(ps.pss_state));
//		fnvlist_add_uint64(scan_stats, "start_time", ps.pss_start_time);
//		fnvlist_add_uint64(scan_stats, "end_time", ps.pss_end_time);
//		fnvlist_add_uint64(scan_stats, "to_examine", ps.pss_to_examine);
//		fnvlist_add_uint64(scan_stats, "examined", ps.pss_examined);
//		fnvlist_add_uint64(scan_stats, "processed", ps.pss_processed);
//		fnvlist_add_uint64(scan_stats, "errors", ps.pss_errors);
//		fnvlist_add_uint64(scan_stats, "pass_exam", ps.pss_pass_exam);
//		fnvlist_add_uint64(scan_stats, "pass_start", ps.pss_pass_start);
//		fnvlist_add_uint64(scan_stats, "pass_scrub_pause",
//		    ps.pss_pass_scrub_pause);
//		fnvlist_add_uint64(scan_stats, "pass_scrub_spent_paused",
//		    ps.pss_pass_scrub_spent_paused);
//		fnvlist_add_uint64(scan_stats, "pass_issued",
//		    ps.pss_pass_issued);
//		fnvlist_add_uint64(scan_stats, "issued", ps.pss_issued);
//	} else if (ps_error == ENOENT) {
//		fnvlist_add_string(scan_stats, "func", "NONE");
//		fnvlist_add_string(scan_stats, "state", "NONE");
//	} else {
//		fnvlist_add_string(scan_stats, "func", "NONE");
//		fnvlist_add_string(scan_stats, "state", "NONE");
//	}
//	fnvlist_add_nvlist(nvl, "scan_stats", scan_stats);
//	fnvlist_add_string(nvl, "state", spa_state_to_name(spa));
//
//	fnvlist_remove(spa_config, "state");
//	spa_add_spares(spa, spa_config);
//	spa_add_l2cache(spa, spa_config);
//	spa_add_feature_stats(spa, spa_config);
//
//	/* add spa_config to output nvlist */
//	fnvlist_merge(nvl, spa_config);
//	iterate_vdevs(spa, &ps, nvl);
//
//	if (scl_config_lock)
//		spa_config_exit(spa, SCL_CONFIG, FTAG);
//
//	error = nvlist_to_json(nvl, &curr, size);
//	nvlist_free(nvl);
//	nvlist_free(spa_config);
//	nvlist_free(spa_props);
//	nvlist_free(scan_stats);

	nvlist_t *nvl = fnvlist_alloc();
	nvlist_t *spa_config = spa->spa_config;
	pool_scan_stat_t ps;
	char *curr = buf;

	int scl_config_lock =
		    spa_config_tryenter(spa, SCL_CONFIG, FTAG, RW_READER);

	fnvlist_add_uint32(nvl, "status_json_version", JSON_STATUS_VERSION);
	fnvlist_add_boolean_value(nvl, "scl_config_lock", scl_config_lock != 0);
	fnvlist_add_string(nvl, "name", fnvlist_lookup_string(spa_config, "name"));
	fnvlist_add_string(nvl, "state", spa_state_to_name(spa));
	fnvlist_add_uint64(nvl, "pool_guid", fnvlist_lookup_uint64(spa_config, "pool_guid"));
	fnvlist_add_uint64(nvl, "txg", fnvlist_lookup_uint64(spa_config, "txg"));
	fnvlist_add_uint64(nvl, "spa_version", SPA_VERSION);
	fnvlist_add_uint64(nvl, "zpl_version", ZPL_VERSION);
	iterate_vdevs(spa, &ps, nvl);

	if (scl_config_lock)
		spa_config_exit(spa, SCL_CONFIG, FTAG);

	error = nvlist_to_json(nvl, &curr, size);
	nvlist_free(nvl);
	return (error);
}
