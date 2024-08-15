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
#include <sys/zfs_znode.h>
#include <sys/dmu_objset.h>

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

static const char *
vdev_bias_string(vdev_alloc_bias_t bias)
{
	const char *s;
	switch (bias) {
	case VDEV_BIAS_NONE:	s = "NONE";	break;
	case VDEV_BIAS_LOG:	s = VDEV_ALLOC_BIAS_LOG;	break;
	case VDEV_BIAS_SPECIAL:	s = VDEV_ALLOC_BIAS_SPECIAL;	break;
	case VDEV_BIAS_DEDUP:	s = VDEV_ALLOC_BIAS_DEDUP;	break;
	default:		s = "?";
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
fill_vdev(vdev_t *vd, vdev_aux_t aux, nvlist_t *tree, const char *class)
{
	char vname[128];
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

	if (vd->vdev_islog)
		fnvlist_add_string(tree, "class", "log");
	else if (class == NULL)
		fnvlist_add_string(tree, "class", "normal");
	else
		fnvlist_add_string(tree, "class", class);
	fnvlist_add_string(tree, "state",
	    vdev_state_string(vd->vdev_state, aux));
}

static void
vdev_to_nvlist(vdev_t *vd, nvlist_t *tree, const char *class)
{
	uint64_t n;
	vdev_t **a;
	const char *s;
	char vname[128];
	vdev_stat_t *vs = kmem_alloc(sizeof (*vs), KM_SLEEP);
	int vsc = sizeof(vdev_stat_t) / sizeof(uint64_t);

	vdev_get_stats(vd, vs);
	fill_vdev(vd, vs->vs_aux, tree, class);

	if (vd->vdev_enc_sysfs_path != NULL) {
		fnvlist_add_string(tree, "enc_sysfs_path",
		    vd->vdev_enc_sysfs_path);
	}
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

	n = vd->vdev_children;
	a = vd->vdev_child;
	if (n != 0) {
		nvlist_t *ch = fnvlist_alloc();
		for (uint64_t i = 0; i < n; ++i) {
			if (a[i]->vdev_alloc_bias == VDEV_BIAS_NONE) {
				nvlist_t *x = fnvlist_alloc();
				vdev_to_nvlist(a[i], x, class);
				if (!nvlist_empty(x)) {
					vdev_name(a[i], vname, 128);
					fnvlist_add_nvlist(ch, vname, x);
				}
				fnvlist_free(x);
			}
		}
		if (!nvlist_empty(ch))
			fnvlist_add_nvlist(tree, "vdevs", ch);
		fnvlist_free(ch);
	}
}

static void
iterate_vdevs(nvlist_t *nvl, spa_t *spa)
{
	char vname[128];
	vdev_t *v = spa->spa_root_vdev;
	nvlist_t *vt = fnvlist_alloc();
	nvlist_t *prv = fnvlist_alloc();

	if (v == NULL) {
		zfs_dbgmsg("error: NO ROOT VDEV");
		return;
	}
	vdev_to_nvlist(v, prv, NULL);
	fnvlist_add_nvlist(vt, spa->spa_name, prv);
	fnvlist_free(prv);

	vdev_t **rchild = v->vdev_child;
	uint64_t nrchildren = v->vdev_children;
	const char *bias = NULL;
	for (uint64_t i = 0; i < nrchildren; i++) {
		if (rchild[i]->vdev_alloc_bias != VDEV_BIAS_NONE) {
			nvlist_t *b = fnvlist_alloc();
			nvlist_t *x = fnvlist_alloc();
			bias = vdev_bias_string(rchild[i]->vdev_alloc_bias);
			vdev_to_nvlist(rchild[i], x, bias);
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
			vdev_to_nvlist(v, l, "l2cache");
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
			vdev_to_nvlist(v, s, "spare");
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

static const char *
pss_func_to_string(uint64_t n)
{
	const char *s = "?";
	switch (n) {
		case POOL_SCAN_NONE:		s = "NONE";	break;
		case POOL_SCAN_SCRUB:		s = "SCRUB";	break;
		case POOL_SCAN_RESILVER:	s = "RESILVER";	break;
		case POOL_SCAN_ERRORSCRUB:	s = "ERRORSCRUB";	break;
		case POOL_SCAN_FUNCS:		s = "?";
	}
	return (s);
}

static const char *pss_state_to_string(uint64_t n)
{
	const char *s = "?";
	switch (n) {
		case DSS_NONE:				s = "NONE";	break;
		case DSS_SCANNING:			s = "SCANNING";	break;
		case DSS_FINISHED:			s = "FINISHED";	break;
		case DSS_CANCELED:			s = "CANCELED";	break;
		case DSS_ERRORSCRUBBING:	s = "ERRORSCRUBING";	break;
		case DSS_NUM_STATES:		s = "?";
	}
	return (s);
}

static const char *vrs_state_to_string(uint64_t n)
{
	const char *s = "?";
	switch (n) {
		case VDEV_REBUILD_NONE:				s = "NONE";	break;
		case VDEV_REBUILD_ACTIVE:			s = "ACTIVE";	break;
		case VDEV_REBUILD_CANCELED:			s = "CANCELED";	break;
		case VDEV_REBUILD_COMPLETE:			s = "COMPLETE";	break;
	}
	return (s);
}

static void
scan_stats_nvlist(nvlist_t *nvl, spa_t *spa)
{
	pool_scan_stat_t ps;
	nvlist_t *scan = fnvlist_alloc();
	int ps_error = spa_scan_get_stats(spa, &ps);

	if (ps_error == 0) {
		fnvlist_add_string(scan, "function",
		    pss_func_to_string(ps.pss_func));
		fnvlist_add_string(scan, "state",
		    pss_state_to_string(ps.pss_state));
		fnvlist_add_uint64(scan, "start_time", ps.pss_start_time);
		fnvlist_add_uint64(scan, "end_time", ps.pss_end_time);
		fnvlist_add_uint64(scan, "to_examine", ps.pss_to_examine);
		fnvlist_add_uint64(scan, "examined", ps.pss_examined);
		fnvlist_add_uint64(scan, "skipped", ps.pss_skipped);
		fnvlist_add_uint64(scan, "processed", ps.pss_processed);
		fnvlist_add_uint64(scan, "errors", ps.pss_errors);
		fnvlist_add_uint64(scan, "bytes_per_scan", ps.pss_pass_exam);
		fnvlist_add_uint64(scan, "pass_start", ps.pss_pass_start);
		fnvlist_add_uint64(scan, "scrub_pause",
		    ps.pss_pass_scrub_pause);
		fnvlist_add_uint64(scan, "scrub_spent_paused",
		    ps.pss_pass_scrub_spent_paused);
		fnvlist_add_uint64(scan, "issued_bytes_per_scan",
		    ps.pss_pass_issued);
		fnvlist_add_uint64(scan, "issued", ps.pss_issued);

		if (ps.pss_error_scrub_func == POOL_SCAN_ERRORSCRUB &&
		    ps.pss_error_scrub_start > ps.pss_start_time) {
			fnvlist_add_string(scan, "err_scrub_func",
			    pss_func_to_string(ps.pss_error_scrub_func));
			fnvlist_add_string(scan, "err_scrub_state",
			    pss_state_to_string(ps.pss_error_scrub_state));
			fnvlist_add_uint64(scan, "err_scrub_start_time",
			    ps.pss_error_scrub_start);
			fnvlist_add_uint64(scan, "err_scrub_end_time",
			    ps.pss_error_scrub_end);
			fnvlist_add_uint64(scan, "err_scrub_examined",
			    ps.pss_error_scrub_examined);
			fnvlist_add_uint64(scan, "err_scrub_to_examine",
			    ps.pss_error_scrub_to_be_examined);
			fnvlist_add_uint64(scan, "err_scrub_pause",
			    ps.pss_pass_error_scrub_pause);
		}
	} else if (ps_error == ENOENT) {
		fnvlist_add_string(scan, "function", "NONE");
		fnvlist_add_string(scan, "state", "NONE");
	} else {
		zfs_dbgmsg("Invalid scan state.");
	}

	uint64_t children = spa->spa_root_vdev->vdev_children;
	if (children > 0) {
		vdev_rebuild_stat_t vrs;
		nvlist_t *reb = fnvlist_alloc();
		vdev_t **child = spa->spa_root_vdev->vdev_child;
		for (uint64_t i = 0; i < children; ++i)
		{
			if (!child[i]->vdev_ops->vdev_op_leaf) {
				if (vdev_rebuild_get_stats(child[i], &vrs) == 0) {
					vdev_stat_t vs;
					vdev_get_stats(child[i], &vs);
					if (vrs.vrs_state != VDEV_REBUILD_NONE) {
						nvlist_t *nv = fnvlist_alloc();
						char vname[128];
						vdev_name(child[i], vname, 128);
						fill_vdev(child[i], vs.vs_aux, nv,
						    vdev_bias_string(child[i]->vdev_alloc_bias));
						fnvlist_add_string(nv, "state",
							vrs_state_to_string(vrs.vrs_state));
						fnvlist_add_uint64(nv, "start_time",
							vrs.vrs_start_time);
						fnvlist_add_uint64(nv, "end_time",
							vrs.vrs_end_time);
						fnvlist_add_uint64(nv, "scan_time",
							vrs.vrs_scan_time_ms * 1000000);
						fnvlist_add_uint64(nv, "scanned",
							vrs.vrs_bytes_scanned);
						fnvlist_add_uint64(nv, "issued",
							vrs.vrs_bytes_issued);
						fnvlist_add_uint64(nv, "rebuilt",
							vrs.vrs_bytes_rebuilt);
						fnvlist_add_uint64(nv, "to_scan",
							vrs.vrs_bytes_est);
						fnvlist_add_uint64(nv, "errors",
							vrs.vrs_errors);
						fnvlist_add_uint64(nv, "pass_time",
							vrs.vrs_pass_time_ms * 1000000);
						fnvlist_add_uint64(nv, "pass_scanned",
							vrs.vrs_pass_bytes_scanned);
						fnvlist_add_uint64(nv, "pass_issued",
							vrs.vrs_pass_bytes_issued);
						fnvlist_add_uint64(nv, "pass_skipped",
							vrs.vrs_pass_bytes_skipped);
						fnvlist_add_nvlist(reb, vname, nv);
						fnvlist_free(nv);
					}
				}
			}
		}
		if (!nvlist_empty(reb))
			fnvlist_add_nvlist(scan, "rebuild_stats", reb);
		fnvlist_free(reb);
	}

	if (!nvlist_empty(scan))
		fnvlist_add_nvlist(nvl, "scan_stats", scan);
	fnvlist_free(scan);
}

static void
removal_stats_nvlist(nvlist_t *nvl, spa_t *spa)
{
	pool_removal_stat_t prs;
	if (spa_removal_get_stats(spa, &prs) == 0) {
		if (prs.prs_state != DSS_NONE) {
			vdev_t *rvdev = spa->spa_root_vdev->vdev_child[prs.prs_removing_vdev];
			vdev_stat_t vs;
			nvlist_t *nv = fnvlist_alloc();
			vdev_get_stats(rvdev, &vs);
			fill_vdev(rvdev, vs.vs_aux, nv, vdev_bias_string(rvdev->vdev_alloc_bias));
			fnvlist_add_string(nv, "state",
					pss_state_to_string(prs.prs_state));
			fnvlist_add_uint64(nv, "removing_vdev",
			    prs.prs_removing_vdev);
			fnvlist_add_uint64(nv, "start_time",
			    prs.prs_start_time);
			fnvlist_add_uint64(nv, "end_time", prs.prs_end_time);
			fnvlist_add_uint64(nv, "to_copy", prs.prs_to_copy);
			fnvlist_add_uint64(nv, "copied", prs.prs_copied);
			fnvlist_add_uint64(nv, "mapping_memory",
			    prs.prs_mapping_memory);
			fnvlist_add_nvlist(nvl, "removal_stats", nv);
			fnvlist_free(nv);
		}
	}
}

static void
checkpoint_stats_nvlist(nvlist_t *nvl, spa_t *spa)
{
	pool_checkpoint_stat_t pcs;
	if (spa_checkpoint_get_stats(spa, &pcs) == 0) {
		if (pcs.pcs_state != CS_NONE) {
			const char *state;
			nvlist_t *nv = fnvlist_alloc();
			if (pcs.pcs_state == CS_CHECKPOINT_EXISTS)
				state = "EXISTS";
			else if (pcs.pcs_state == CS_CHECKPOINT_DISCARDING)
				state = "DISCARDING";
			else
				state = "?";
			fnvlist_add_string(nv, "state", state);
			fnvlist_add_uint64(nv, "start_time",
			    pcs.pcs_start_time);
			fnvlist_add_uint64(nv, "space",
			    pcs.pcs_space);
			fnvlist_add_nvlist(nvl, "checkpoint_stats", nv);
			fnvlist_free(nv);
		}
	}
}

static void
raidz_expand_stats_nvlist(nvlist_t *nvl, spa_t *spa)
{
	pool_raidz_expand_stat_t pres;
	if (spa_raidz_expand_get_stats(spa, &pres) == 0) {
		if(pres.pres_state != DSS_NONE) {
			vdev_stat_t vs;
			vdev_t *evdev = spa->spa_root_vdev->vdev_child[pres.pres_expanding_vdev];
			nvlist_t *nv = fnvlist_alloc();
			vdev_get_stats(evdev, &vs);
			fill_vdev(evdev, vs.vs_aux, nv, vdev_bias_string(evdev->vdev_alloc_bias));
			fnvlist_add_string(nv, "state",
			    pss_state_to_string(pres.pres_state));
			fnvlist_add_uint64(nv, "expanding_vdev",
			    pres.pres_expanding_vdev);
			fnvlist_add_uint64(nv, "start_time", pres.pres_start_time);
			fnvlist_add_uint64(nv, "end_time", pres.pres_end_time);
			fnvlist_add_uint64(nv, "to_reflow", pres.pres_to_reflow);
			fnvlist_add_uint64(nv, "reflowed", pres.pres_reflowed);
			fnvlist_add_uint64(nv, "waiting_for_resilver",
			    pres.pres_waiting_for_resilver);
			fnvlist_add_nvlist(nvl, "raidz_expand_stats", nv);
			fnvlist_free(nv);
		}
	}
}

static void
ddt_stats_nvlist(ddt_stat_t *dds, nvlist_t *nvl)
{
	fnvlist_add_uint64(nvl, "blocks", dds->dds_blocks);
	fnvlist_add_uint64(nvl, "logical_size", dds->dds_lsize);
	fnvlist_add_uint64(nvl, "physical_size", dds->dds_psize);
	fnvlist_add_uint64(nvl, "deflated_size", dds->dds_dsize);
	fnvlist_add_uint64(nvl, "ref_blocks", dds->dds_ref_blocks);
	fnvlist_add_uint64(nvl, "ref_lsize", dds->dds_ref_lsize);
	fnvlist_add_uint64(nvl, "ref_psize", dds->dds_ref_psize);
	fnvlist_add_uint64(nvl, "ref_dsize", dds->dds_ref_dsize);
}

static void
dedup_stats_nvlist(nvlist_t *nvl, spa_t *spa)
{
	ddt_histogram_t *ddh;
	ddt_stat_t *dds;
	ddt_object_t *ddo;
	nvlist_t *ddt_stat, *ddt_obj, *dedup;

	dedup = fnvlist_alloc();
	ddt_obj = fnvlist_alloc();

	ddo = kmem_zalloc(sizeof (ddt_object_t), KM_SLEEP);
	ddt_get_dedup_object_stats(spa, ddo);
	fnvlist_add_uint64(dedup, "obj_count", ddo->ddo_count);
	if (ddo->ddo_count == 0) {
		fnvlist_add_nvlist(dedup, ZPOOL_CONFIG_DDT_OBJ_STATS,
		    ddt_obj);
		fnvlist_add_nvlist(nvl, "dedup_stats", dedup);
		kmem_free(ddo, sizeof (ddt_object_t));
		fnvlist_free(ddt_obj);
		fnvlist_free(dedup);
		return;
	} else {
		uint64_t cspace_prop;
		fnvlist_add_uint64(dedup, "dspace", ddo->ddo_dspace);
		fnvlist_add_uint64(dedup, "mspace", ddo->ddo_mspace);
		if (ddt_get_pool_dedup_cached(spa, &cspace_prop) == 0)
			cspace_prop = MIN(cspace_prop, ddo->ddo_mspace);
		else
			cspace_prop = ddo->ddo_mspace;
		fnvlist_add_uint64(dedup, "cspace", cspace_prop);
	}
	kmem_free(ddo, sizeof (ddt_object_t));

	ddt_stat = fnvlist_alloc();
	dds = kmem_zalloc(sizeof (ddt_stat_t), KM_SLEEP);
	ddt_get_dedup_stats(spa, dds);
	nvlist_t *total = fnvlist_alloc();
	if (dds->dds_blocks == 0)
		fnvlist_add_string(total, "blocks", "0");
	else
		ddt_stats_nvlist(dds, total);
	fnvlist_add_nvlist(ddt_stat, "total", total);
	fnvlist_free(total);
	kmem_free(dds, sizeof (ddt_stat_t));

	ddh = kmem_zalloc(sizeof (ddt_histogram_t), KM_SLEEP);
	ddt_get_dedup_histogram(spa, ddh);
	nvlist_t *hist = fnvlist_alloc();
	nvlist_t *entry = NULL;
	char buf[16];
	for (int h = 0; h < 64; h++) {
		if (ddh->ddh_stat[h].dds_blocks != 0) {
			entry = fnvlist_alloc();
			ddt_stats_nvlist(&ddh->ddh_stat[h], entry);
			snprintf(buf, 16, "%d", h);
			fnvlist_add_nvlist(hist, buf, entry);
			fnvlist_free(entry);
		}
	}
	if (!nvlist_empty(hist))
		fnvlist_add_nvlist(ddt_stat, "histogram", hist);
	fnvlist_free(hist);
	kmem_free(ddh, sizeof (ddt_histogram_t));

	if (!nvlist_empty(ddt_obj)) {
		fnvlist_add_nvlist(dedup, "ddt_object_stats",
		    ddt_obj);
	}
	fnvlist_free(ddt_obj);
	if (!nvlist_empty(ddt_stat)) {
		fnvlist_add_nvlist(dedup, "ddt_stats", ddt_stat);
	}
	fnvlist_free(ddt_stat);
	if (!nvlist_empty(dedup))
		fnvlist_add_nvlist(nvl, "dedup_stats", dedup);
	fnvlist_free(dedup);
}

static void
objs_to_files(nvlist_t *nvl, spa_t *spa, zbookmark_phys_t *zb, uint64_t zblen)
{
	objset_t *os;
	size_t len = MAXPATHLEN * 2;
	char dsname = kmem_zalloc(ZFS_MAX_DATASET_NAME_LEN, KM_SLEEP);
	char *fpath = kmem_zalloc(len, KM_SLEEP);
	int error;

	char **errl = (char **)kmem_zalloc(
	    zblen * sizeof (char *), KM_SLEEP);

	for (uint64_t i = 0; i < zblen; ++i) {
		uint64_t dsobj, obj;
		dsobj = zb[i].zb_objset;
		obj = zb[i].zb_object;
		errl[i] = kmem_zalloc(len, KM_SLEEP);

		if (dsobj == 0) {
			(void) snprintf(errl[i], len, "<metadata>:<0x%llx>",
			    (longlong_t)obj);
			continue;
		}

		if (dsl_dsobj_to_dsname(spa->spa_name, dsobj, dsname) != 0) {
			(void) snprintf(errl[i++], len, "<0x%llx>:<0x%llx>",
			    (longlong_t)dsobj, (longlong_t)obj);
			continue;
		}

		if ((error = dmu_objset_hold_flags(dsname, B_TRUE,
		    FTAG, &os)) != 0)
			continue;
		if (dmu_objset_type(os) != DMU_OST_ZFS) {
			dmu_objset_rele_flags(os, B_TRUE, FTAG);
			continue;
		}
		error = zfs_obj_to_path(os, obj, fpath, sizeof (fpath));
		dmu_objset_rele_flags(os, B_TRUE, FTAG);

		if (error == 0) {
			(void) snprintf(errl[i], len, "%s:%s", dsname, fpath);
		} else {
			(void) snprintf(errl[i], len, "%s:<0x%llx>", dsname,
			    (longlong_t)obj);
		}
	}

	fnvlist_add_string_array(nvl, "errlist", (const char **)errl, zblen);
	for (int i = 0; i < zblen; ++i)
		kmem_free(errl[i], len);
	kmem_free(dsname, ZFS_MAX_DATASET_NAME_LEN);
	kmem_free(fpath, len);
	kmem_free(errl, zblen * sizeof (char *));
}

static void
errors_nvlist(nvlist_t *nvl, spa_t *spa)
{
	uint64_t buflen = 10000; /* approx. 1MB of RAM */
	zbookmark_phys_t *buf;
	uint64_t size;
	int error;

	uint64_t err_count = spa_approx_errlog_size(spa);
	fnvlist_add_uint64(nvl, "error_count", err_count);
	if (err_count == 0)
		return;

	for (;;) {
		buf = kmem_zalloc(buflen * sizeof (zbookmark_phys_t), KM_SLEEP);
		size = buflen;
		error = spa_get_errlog(spa, (void *)(uintptr_t)buf, &size, COPY_TO_KERNEL);
		if (error != 0) {
			kmem_free(buf, buflen);
			if (error == ENOMEM)
				buflen *= 2;
			else
				return;
		} else
			break;
	}
	uint64_t zblen = buflen - size;
	zbookmark_phys_t *zb = buf + size;
	objs_to_files(nvl, spa, zb, zblen);
	kmem_free(buf, buflen);
	return;
}

/*
 * Collect the spa status without any locking and return as a JSON string.
 *
 * Currently used by the 'zfs/<pool>/stats.json' kstat.
 */
int
spa_generate_json_stats(spa_t *spa, char *buf, size_t size)
{
	int error = 0;
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
	scan_stats_nvlist(nvl, spa);
	removal_stats_nvlist(nvl, spa);
	checkpoint_stats_nvlist(nvl, spa);
	raidz_expand_stats_nvlist(nvl, spa);
	iterate_vdevs(nvl, spa);
	dedup_stats_nvlist(nvl, spa);
	errors_nvlist(nvl, spa);

	if (scl_config_lock)
		spa_config_exit(spa, SCL_CONFIG, FTAG);

	error = nvlist_to_json(nvl, &curr, size);
	nvlist_free(nvl);
	return (error);
}
