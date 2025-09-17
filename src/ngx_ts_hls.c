
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_ts_hls.h"


static void ngx_ts_hls_cleanup(void *data);
static ngx_int_t ngx_ts_hls_handler(ngx_ts_handler_data_t *hd);
static ngx_int_t ngx_ts_hls_pat_handler(ngx_ts_hls_t *hls);
static ngx_int_t ngx_ts_hls_pes_handler(ngx_ts_hls_t *hls,
    ngx_ts_program_t *prog, ngx_ts_es_t *es, ngx_chain_t *bufs);
static void ngx_ts_hls_update_bandwidth(ngx_ts_hls_t *hls,
    ngx_ts_hls_variant_t *var, ngx_chain_t *bufs, uint64_t dts);
static ngx_int_t ngx_ts_hls_close_segment(ngx_ts_hls_t *hls,
    ngx_ts_hls_variant_t *var, ngx_ts_es_t *es);
static ngx_int_t ngx_ts_hls_update_playlist(ngx_ts_hls_t *hls,
    ngx_ts_hls_variant_t *var);
static ngx_int_t ngx_ts_hls_update_master_playlist(ngx_ts_hls_t *hls);
static ngx_int_t ngx_ts_hls_write_file(u_char *path, u_char *tmp_path,
    u_char *data, size_t len, ngx_log_t *log);
static ngx_int_t ngx_ts_hls_open_segment(ngx_ts_hls_t *hls,
    ngx_ts_hls_variant_t *var);

static ngx_msec_t ngx_ts_hls_file_manager(void *data);
static ngx_int_t ngx_ts_hls_manage_file(ngx_tree_ctx_t *ctx, ngx_str_t *path);
static ngx_int_t ngx_ts_hls_manage_directory(ngx_tree_ctx_t *ctx,
    ngx_str_t *path);
static ngx_int_t ngx_ts_hls_delete_directory(ngx_tree_ctx_t *ctx,
    ngx_str_t *path);
static ngx_int_t ngx_ts_hls_delete_file(ngx_tree_ctx_t *ctx, ngx_str_t *path);
static ngx_int_t ngx_ts_hls_restore_playlist(ngx_ts_hls_t *hls,
    ngx_ts_hls_variant_t *var);


ngx_ts_hls_t *
ngx_ts_hls_create(ngx_ts_hls_conf_t *conf, ngx_ts_stream_t *ts, ngx_str_t *name)
{
    ngx_ts_hls_t        *hls;
    ngx_pool_cleanup_t  *cln;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ts->log, 0, "ts hls create");

    hls = ngx_pcalloc(ts->pool, sizeof(ngx_ts_hls_t));
    if (hls == NULL) {
        return NULL;
    }

    hls->conf = conf;
    hls->ts = ts;

    /* Store stream name for single-variant HLS naming */
    hls->name.len = name->len;
    hls->name.data = ngx_pnalloc(ts->pool, name->len + 1);
    if (hls->name.data == NULL) {
        return NULL;
    }
    ngx_memcpy(hls->name.data, name->data, name->len);
    hls->name.data[name->len] = '\0';

    /* Set base directory path (no subdirectory for single-variant mode) */
    hls->path.len = conf->path->name.len;
    hls->path.data = ngx_pnalloc(ts->pool, hls->path.len + 1);
    if (hls->path.data == NULL) {
        return NULL;
    }
    ngx_memcpy(hls->path.data, conf->path->name.data, conf->path->name.len);
    hls->path.data[hls->path.len] = '\0';

    cln = ngx_pool_cleanup_add(ts->pool, 0);
    if (cln == NULL) {
        return NULL;
    }

    cln->handler = ngx_ts_hls_cleanup;
    cln->data = hls;

    if (ngx_ts_add_handler(ts, ngx_ts_hls_handler, hls) != NGX_OK) {
        return NULL;
    }

    return hls;
}


static void
ngx_ts_hls_cleanup(void *data)
{
    ngx_ts_hls_t *hls = data;

    int64_t                d, maxd;
    ngx_uint_t             n, i;
    ngx_ts_es_t           *es;
    ngx_ts_stream_t       *ts;
    ngx_ts_hls_segment_t  *seg;
    ngx_ts_hls_variant_t  *var;

    /* Only set done=1 if continuous mode is disabled */
    if (!hls->conf->continuous) {
        hls->done = 1;
    }

    ts = hls->ts;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ts->log, 0, "ts hls cleanup");

    for (n = 0; n < hls->nvars; n++) {
        var = &hls->vars[n];

        if (var->file.fd != NGX_INVALID_FILE) {
            if (ngx_close_file(var->file.fd) == NGX_FILE_ERROR) {
                ngx_log_error(NGX_LOG_ALERT, ts->log, ngx_errno,
                              ngx_close_file_n " \"%s\" failed",
                              var->file.name.data);
            }

            var->file.fd = NGX_INVALID_FILE;
        }

        maxd = 0;

        for (i = 0; i < var->prog->nes; i++) {
            es = &var->prog->es[i];

            d = es->dts - var->seg_dts;
            if (maxd < d) {
                maxd = d;
            }
        }

        seg = &var->segs[var->seg % var->nsegs];
        seg->id = var->seg++;
        seg->duration = maxd;

        (void) ngx_ts_hls_update_playlist(hls, var);
    }
}


static ngx_int_t
ngx_ts_hls_handler(ngx_ts_handler_data_t *hd)
{
    ngx_ts_hls_t *hls = hd->data;

    switch (hd->event) {

    case NGX_TS_PAT:
        return ngx_ts_hls_pat_handler(hls);

    case NGX_TS_PES:
        return ngx_ts_hls_pes_handler(hls, hd->prog, hd->es, hd->bufs);

    default:
        return NGX_OK;
    }
}


static ngx_int_t
ngx_ts_hls_pat_handler(ngx_ts_hls_t *hls)
{
    size_t                 len;
    u_char                *p;
    ngx_ts_stream_t       *ts;
    ngx_ts_program_t      *prog;
    ngx_ts_hls_variant_t  *var;

    if (hls->vars) {
        return NGX_OK;
    }

    ts = hls->ts;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ts->log, 0, "ts hls pat");

    /* Single-variant mode: use only the first program */
    if (ts->nprogs == 0) {
        return NGX_ERROR;
    }

    hls->nvars = 1;
    hls->vars = ngx_pcalloc(ts->pool, sizeof(ngx_ts_hls_variant_t));
    if (hls->vars == NULL) {
        return NGX_ERROR;
    }

    prog = &ts->progs[0];  /* Use first program only */
    var = &hls->vars[0];

    var->prog = prog;
    var->file.fd = NGX_INVALID_FILE;
    var->file.log = ts->log;
    var->last_seg_end_dts = 0;  /* Initialize for discontinuity detection */

    var->nsegs = hls->conf->nsegs;
    var->segs = ngx_pcalloc(ts->pool,
                           sizeof(ngx_ts_hls_segment_t) * hls->conf->nsegs);
    if (var->segs == NULL) {
        return NGX_ERROR;
    }

    /* Segment path: {stream_name}-{seg}.ts */
    len = hls->path.len + 1 + hls->name.len + 1 + NGX_INT_T_LEN + sizeof(".ts");
    p = ngx_pnalloc(ts->pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    var->path.data = p;
    p = ngx_sprintf(p, "%V/%V-", &hls->path, &hls->name);
    var->path.len = p - var->path.data;

    /* Playlist path: {stream_name}.m3u8 */
    len = hls->path.len + 1 + hls->name.len + sizeof(".m3u8");
    var->m3u8_path = ngx_pnalloc(ts->pool, len);
    if (var->m3u8_path == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(var->m3u8_path, "%V/%V.m3u8%Z", &hls->path, &hls->name);

    /* Playlist temp path: {stream_name}.m3u8.tmp */
    len += sizeof(".tmp") - 1;
    var->m3u8_tmp_path = ngx_pnalloc(ts->pool, len);
    if (var->m3u8_tmp_path == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(var->m3u8_tmp_path, "%s.tmp%Z", var->m3u8_path);

    /* Restore playlist state for continuous mode */
    if (hls->conf->continuous) {
        if (ngx_ts_hls_restore_playlist(hls, var) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_ts_hls_pes_handler(ngx_ts_hls_t *hls, ngx_ts_program_t *prog,
    ngx_ts_es_t *es, ngx_chain_t *bufs)
{
    ngx_uint_t             n;
    ngx_chain_t           *out;
    ngx_ts_stream_t       *ts;
    ngx_ts_hls_variant_t  *var;

    if (!es->ptsf) {
        return NGX_OK;
    }

    ts = hls->ts;

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, ts->log, 0, "ts hls pes pid:%ud",
                   (unsigned) es->pid);

    for (n = 0; n < hls->nvars; n++) {
        var = &hls->vars[n];
        if (prog == var->prog) {
            goto found;
        }
    }

    ngx_log_error(NGX_LOG_ERR, ts->log, 0, "TS program not found");

    return NGX_ERROR;

found:

    ngx_ts_hls_update_bandwidth(hls, var, bufs, es->pts);

    if (ngx_ts_hls_close_segment(hls, var, es) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_ts_hls_open_segment(hls, var) != NGX_OK) {
        return NGX_ERROR;
    }

    out = ngx_ts_write_pes(ts, prog, es, bufs);
    if (out == NULL) {
        return NGX_ERROR;
    }

    if (ngx_write_chain_to_file(&var->file, out, var->file.offset, ts->pool)
        == NGX_ERROR)
    {
        return NGX_ERROR;
    }

    ngx_ts_free_chain(ts, &out);

    return NGX_OK;
}

static void
ngx_ts_hls_update_bandwidth(ngx_ts_hls_t *hls, ngx_ts_hls_variant_t *var,
    ngx_chain_t *bufs, uint64_t dts)
{
    int64_t  d, analyze;

    if (var->bandwidth) {
        return;
    }

    if (var->bandwidth_bytes == 0) {
        var->bandwidth_dts = dts;
    }

    while (bufs) {
        var->bandwidth_bytes += bufs->buf->last - bufs->buf->pos;
        bufs = bufs->next;
    }

    d = dts - var->bandwidth_dts;
    analyze = (int64_t) hls->conf->analyze * 90;

    if (d >= analyze) {
        var->bandwidth = var->bandwidth_bytes * 8 * 90000 / d;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, hls->ts->log, 0,
                   "ts hls bandwidth:%ui, pid:%ud",
                   var->bandwidth, (unsigned) var->prog->pid);
}


static ngx_int_t
ngx_ts_hls_close_segment(ngx_ts_hls_t *hls, ngx_ts_hls_variant_t *var,
    ngx_ts_es_t *es)
{
    off_t                  max_size;
    int64_t                d, min_seg, max_seg;
    ngx_ts_stream_t       *ts;
    ngx_ts_hls_segment_t  *seg;

    ts = hls->ts;

    if (var->file.fd == NGX_INVALID_FILE) {
        var->seg_dts = es->dts;
        return NGX_OK;
    }

    d = es->dts - var->seg_dts;

    min_seg = (int64_t) hls->conf->min_seg * 90;
    max_seg = (int64_t) hls->conf->max_seg * 90;
    max_size = hls->conf->max_size;

    if (d < min_seg
        || (d < max_seg && es->video && !es->rand)
        || (d < max_seg && !es->video && var->prog->video))
    {
        if (max_size == 0 || var->file.offset < max_size) {
            return NGX_OK;
        }

        ngx_log_error(NGX_LOG_WARN, ts->log, 0,
                      "closing HLS segment \"%s\" on size limit",
                      var->file.name.data);
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, ts->log, 0,
                   "ts hls close segment \"%s\"", var->file.name.data);

    var->seg_dts = es->dts;

    seg = &var->segs[var->seg % var->nsegs];
    seg->id = var->seg++;
    seg->duration = d;
    seg->size = var->file.offset;

    /* Detect discontinuity for continuous mode */
    seg->discont = 0;
    if (hls->conf->continuous) {
        /* Method 1: Check if this is the first segment after a restart (from playlist restore) */
        if (hls->discont_from > 0 && seg->id == hls->discont_from) {
            seg->discont = 1;
            hls->discont_from = 0;  /* Reset after use */
            ngx_log_debug1(NGX_LOG_DEBUG_CORE, ts->log, 0,
                           "ts hls discontinuity at segment %ui (from restore)", seg->id);
        }
        /* Method 2: Detect timing gaps for fast restarts */
        else if (var->last_seg_end_dts > 0) {
            int64_t gap = var->seg_dts - var->last_seg_end_dts;
            /* Detect discontinuity if gap > 2 seconds or negative (clock reset) */
            if (gap > 180000 || gap < -90000) {  /* 90kHz timescale: 2s = 180000, 1s = 90000 */
                seg->discont = 1;
                ngx_log_debug3(NGX_LOG_DEBUG_CORE, ts->log, 0,
                               "ts hls discontinuity at segment %ui (timing gap: %L, threshold: 180000)",
                               seg->id, gap, 180000);
            }
        }

        /* Update last segment end time for next discontinuity detection */
        var->last_seg_end_dts = var->seg_dts + d;
    }

    if (ngx_close_file(var->file.fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, ts->log, ngx_errno,
                      ngx_close_file_n " \"%s\" failed", var->file.name.data);
    }

    ngx_memzero(&var->file, sizeof(ngx_file_t));

    var->file.fd = NGX_INVALID_FILE;
    var->file.log = ts->log;

    if (ngx_ts_hls_update_playlist(hls, var) != NGX_OK) {
        return NGX_ERROR;
    }

    return ngx_ts_hls_update_master_playlist(hls);
}


static ngx_int_t
ngx_ts_hls_update_playlist(ngx_ts_hls_t *hls, ngx_ts_hls_variant_t *var)
{
    size_t                 len;
    u_char                *p, *data;
    uint64_t               maxd;
    ngx_int_t              rc;
    ngx_uint_t             i, ms, td;
    ngx_ts_stream_t       *ts;
    ngx_ts_hls_segment_t  *seg;

    ts = hls->ts;

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, ts->log, 0,
                   "ts hls update playlist \"%s\"", var->m3u8_path);

    len = sizeof("#EXTM3U\n"
                 "#EXT-X-VERSION:3\n"
                 "#EXT-X-MEDIA-SEQUENCE:\n"
                 "#EXT-X-TARGETDURATION:\n\n") - 1
          + 2 * NGX_INT_T_LEN;

    maxd = 0;

    for (i = 0; i < var->nsegs; i++) {
        seg = &var->segs[(var->seg + i) % var->nsegs];

        if (seg->duration) {
            if (maxd < seg->duration) {
                maxd = seg->duration;
            }

            len += sizeof("#EXTINF:.xxx,\n"
                          ".ts\n") - 1
                   + 2 * NGX_INT_T_LEN;

            if (hls->nvars > 1) {
                len += NGX_INT_T_LEN + 1;
            }
        }
    }

    /* Never add EXT-X-ENDLIST for nginx-rtmp-module compatibility */

    data = ngx_alloc(len, ts->log);
    if (data == NULL) {
        return NGX_ERROR;
    }

    p = data;

    ms = var->seg <= var->nsegs ? 0 : var->seg - var->nsegs;
    td = (hls->conf->max_seg + 999) / 1000;

    p = ngx_sprintf(p, "#EXTM3U\n"
                       "#EXT-X-VERSION:3\n"
                       "#EXT-X-MEDIA-SEQUENCE:%ui\n"
                       "#EXT-X-TARGETDURATION:%ui\n\n", ms, td);

    for (i = 0; i < var->nsegs; i++) {
        seg = &var->segs[(var->seg + i) % var->nsegs];

        if (seg->duration) {
            /* Add discontinuity tag BEFORE this segment if it has the discontinuity flag */
            if (seg->discont) {
                p = ngx_sprintf(p, "#EXT-X-DISCONTINUITY\n");
            }

            p = ngx_sprintf(p, "#EXTINF:%.3f,\n", seg->duration / 90000.);

            /* Single-variant mode: {stream_name}-{seg}.ts */
            p = ngx_sprintf(p, "%V-%ui.ts\n", &hls->name, seg->id);
        }
    }

    /* Never add EXT-X-ENDLIST for nginx-rtmp-module compatibility */

    rc = ngx_ts_hls_write_file(var->m3u8_path, var->m3u8_tmp_path, data,
                               p - data, ts->log);

    ngx_free(data);

    return rc;
}


static ngx_int_t
ngx_ts_hls_update_master_playlist(ngx_ts_hls_t *hls)
{
    size_t                 len;
    u_char                *p, *data;
    ngx_int_t              rc;
    ngx_uint_t             n;
    ngx_ts_stream_t       *ts;
    ngx_ts_hls_variant_t  *var;

    /* TODO touch file if it exists*/

    if (hls->nvars == 1) {
        return NGX_OK;
    }

    ts = hls->ts;

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, ts->log, 0,
                   "ts hls update master playlist \"%s\"", hls->m3u8_path);

    len = sizeof("#EXTM3U\n") - 1;

    for (n = 0; n < hls->nvars; n++) {
        var = &hls->vars[n];

        if (var->bandwidth == 0) {
            ngx_log_debug0(NGX_LOG_DEBUG_CORE, ts->log, 0,
                           "ts hls bandwidth not available");
            return NGX_OK;
        }

        len += sizeof("#EXT-X-STREAM-INF:BANDWIDTH=\n") - 1 + NGX_INT_T_LEN
               + NGX_INT_T_LEN + sizeof(".m3u8\n") - 1;
    }

    data = ngx_alloc(len, ts->log);
    if (data == NULL) {
        return NGX_ERROR;
    }

    p = data;

    p = ngx_cpymem(p, "#EXTM3U\n", sizeof("#EXTM3U\n") - 1);

    for (n = 0; n < hls->nvars; n++) {
        var = &hls->vars[n];

        p = ngx_sprintf(p, "#EXT-X-STREAM-INF:BANDWIDTH=%ui\n%ui.m3u8\n",
                        var->bandwidth, (ngx_uint_t) var->prog->number);
    }

    rc = ngx_ts_hls_write_file(hls->m3u8_path, hls->m3u8_tmp_path, data,
                               p - data, ts->log);

    ngx_free(data);

    return rc;
}


static ngx_int_t
ngx_ts_hls_write_file(u_char *path, u_char *tmp_path, u_char *data, size_t len,
    ngx_log_t *log)
{
    ssize_t    n;
    ngx_fd_t   fd;
    ngx_err_t  err;

    fd = ngx_open_file(tmp_path,
                       NGX_FILE_WRONLY,
                       NGX_FILE_TRUNCATE,
                       NGX_FILE_DEFAULT_ACCESS);

    if (fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                      ngx_open_file_n " \"%s\" failed", tmp_path);
        return NGX_ERROR;
    }

    n = ngx_write_fd(fd, data, len);

    err = ngx_errno;

    if (ngx_close_file(fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                      ngx_close_file_n " \"%s\" failed", tmp_path);
        return NGX_ERROR;
    }

    if (n < 0) {
        ngx_log_error(NGX_LOG_ALERT, log, err,
                      ngx_write_fd_n " to \"%s\" failed", tmp_path);
        return NGX_ERROR;
    }

    if ((size_t) n != len) {
        ngx_log_error(NGX_LOG_ALERT, log, 0,
                      "incomplete write to \"%s\"", tmp_path);
        return NGX_ERROR;
    }

    if (ngx_rename_file(tmp_path, path) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                      ngx_rename_file_n " \"%s\" to \"%s\" failed",
                      tmp_path, path);
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_ts_hls_open_segment(ngx_ts_hls_t *hls, ngx_ts_hls_variant_t *var)
{
    size_t            n;
    ngx_err_t         err;
    ngx_str_t        *path;
    ngx_uint_t        try;
    ngx_chain_t      *out, **ll;
    ngx_ts_stream_t  *ts;

    if (var->file.fd != NGX_INVALID_FILE) {
        return NGX_OK;
    }

    ts = hls->ts;

    path = &var->path;

    /* Generate segment name: {stream_name}-{seg}.ts */
    n = ngx_sprintf(path->data + path->len, "%ui.ts%Z", var->seg) - path->data
        - 1;

    var->file.name.data = path->data;
    var->file.name.len = n;

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, ts->log, 0,
                   "ts hls open segment \"%s\"", var->file.name.data);

    for (try = 0; /* void */; try++) {
        var->file.fd = ngx_open_file(path->data,
                                     NGX_FILE_WRONLY,
                                     NGX_FILE_TRUNCATE,
                                     NGX_FILE_DEFAULT_ACCESS);

        if (var->file.fd != NGX_INVALID_FILE) {
            break;
        }

        err = ngx_errno;

        if (try || (err != NGX_ENOENT && err != NGX_ENOTDIR)) {
            ngx_log_error(NGX_LOG_EMERG, ts->log, err,
                          ngx_open_file_n " \"%s\" failed", path->data);
            return NGX_ERROR;
        }

        /* XXX dir access mode */
        if (ngx_create_dir(hls->path.data, 0700) == NGX_FILE_ERROR) {
            err = ngx_errno;

            if (err != NGX_EEXIST) {
                ngx_log_error(NGX_LOG_CRIT, ts->log, err,
                              ngx_create_dir_n " \"%s\" failed",
                              hls->path.data);
                return NGX_ERROR;
            }
        }
    }

    if (var->prologue == NULL) {
        out = ngx_ts_write_pat(ts, var->prog);
        if (out == NULL) {
            return NGX_ERROR;
        }

        for (ll = &out; *ll; ll = &(*ll)->next);

        *ll = ngx_ts_write_pmt(ts, var->prog);
        if (*ll == NULL) {
            return NGX_ERROR;
        }

        var->prologue = out;
    }

    if (ngx_write_chain_to_file(&var->file, var->prologue, 0, ts->pool)
        == NGX_ERROR)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_msec_t
ngx_ts_hls_file_manager(void *data)
{
    ngx_ts_hls_conf_t *hls = data;

    ngx_tree_ctx_t  tree;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                  "ts hls file manager");

    tree.init_handler = NULL;
    tree.file_handler = ngx_ts_hls_manage_file;
    tree.pre_tree_handler = ngx_ts_hls_manage_directory;
    tree.post_tree_handler = ngx_ts_hls_delete_directory;
    tree.spec_handler = ngx_ts_hls_delete_file;
    tree.data = hls;
    tree.alloc = 0;
    tree.log = ngx_cycle->log;

    (void) ngx_walk_tree(&tree, &hls->path->name);

    return hls->max_seg * hls->nsegs;
}


static ngx_int_t
ngx_ts_hls_manage_file(ngx_tree_ctx_t *ctx, ngx_str_t *path)
{
    ngx_ts_hls_conf_t *hls = ctx->data;

    time_t  age, max_age;

    age = ngx_time() - ctx->mtime;

    max_age = 0;

    if (path->len >= 5
        && ngx_memcmp(path->data + path->len - 5, ".m3u8", 5) == 0)
    {
        max_age = hls->max_seg * hls->nsegs / 1000;
    }

    if (path->len >= 3
        && ngx_memcmp(path->data + path->len - 3, ".ts", 3) == 0)
    {
        max_age = hls->max_seg * hls->nsegs / 500;
    }

    if (path->len >= 4
        && ngx_memcmp(path->data + path->len - 4, ".tmp", 3) == 0)
    {
        max_age = 10;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_CORE, ctx->log, 0,
                   "ts hls file \"%s\", age:%T, max_age:%T",
                   path->data, age, max_age);

    if (age < max_age) {
        return NGX_OK;
    }

    return ngx_ts_hls_delete_file(ctx, path);
}


static ngx_int_t
ngx_ts_hls_manage_directory(ngx_tree_ctx_t *ctx, ngx_str_t *path)
{
    return NGX_OK;
}


static ngx_int_t
ngx_ts_hls_delete_directory(ngx_tree_ctx_t *ctx, ngx_str_t *path)
{
    ngx_log_debug1(NGX_LOG_DEBUG_CORE, ctx->log, 0,
                   "ts hls delete dir: \"%s\"", path->data);

    /* non-empty directory will not be removed anyway */

    /* TODO count files instead */

    (void) ngx_delete_dir(path->data);

    return NGX_OK;
}


static ngx_int_t
ngx_ts_hls_delete_file(ngx_tree_ctx_t *ctx, ngx_str_t *path)
{
    ngx_log_debug1(NGX_LOG_DEBUG_CORE, ctx->log, 0,
                   "ts hls file delete: \"%s\"", path->data);

    if (ngx_delete_file(path->data) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_CRIT, ctx->log, ngx_errno,
                      ngx_delete_file_n " \"%s\" failed", path->data);
    }

    return NGX_OK;
}


char *
ngx_ts_hls_set_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char  *p = conf;

    ssize_t             max_size;
    ngx_str_t          *value, s, ss, path;
    ngx_int_t           v;
    ngx_uint_t          i, nsegs, clean;
    ngx_msec_t          min_seg, max_seg, analyze;
    ngx_ts_hls_conf_t  *hls, **field;

    field = (ngx_ts_hls_conf_t **) (p + cmd->offset);

    if (*field != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    ngx_str_null(&path);

    min_seg = 5000;
    max_seg = 10000;
    analyze = 0;
    max_size = 16 * 1024 * 1024;
    nsegs = 6;
    clean = 1;

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "path=", 5) == 0) {

            path.len = value[i].len - 5;
            path.data = value[i].data + 5;

            if (path.data[path.len - 1] == '/') {
                path.len--;
            }

            if (ngx_conf_full_name(cf->cycle, &path, 0) != NGX_OK) {
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "segment=", 8) == 0) {

            s.len = value[i].len - 8;
            s.data = value[i].data + 8;

            ss.data = (u_char *) ngx_strchr(s.data, ':');

            if (ss.data) {
                ss.len = s.data + s.len - ss.data - 1;
                s.len = ss.data - s.data;
                ss.data++;
            }

            min_seg = ngx_parse_time(&s, 0);
            if (min_seg == (ngx_msec_t) NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid segment duration value \"%V\"",
                                   &value[i]);
                return NGX_CONF_ERROR;
            }

            if (ss.data) {
                max_seg = ngx_parse_time(&ss, 0);
                if (max_seg == (ngx_msec_t) NGX_ERROR) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "invalid segment duration value \"%V\"",
                                       &value[i]);
                    return NGX_CONF_ERROR;
                }

            } else {
                max_seg = min_seg * 2;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "analyze=", 8) == 0) {

            s.len = value[i].len - 8;
            s.data = value[i].data + 8;

            analyze = ngx_parse_time(&s, 0);
            if (analyze == (ngx_msec_t) NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid analyze duration value \"%V\"",
                                   &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "max_size=", 9) == 0) {

            s.len = value[i].len - 9;
            s.data = value[i].data + 9;

            max_size = ngx_parse_size(&s);
            if (max_size == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid max segment size value \"%V\"",
                                   &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "segments=", 9) == 0) {

            v = ngx_atoi(value[i].data + 9, value[i].len - 9);
            if (v == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid segments number value \"%V\"",
                                   &value[i]);
                return NGX_CONF_ERROR;
            }

            nsegs = v;

            continue;
        }

        if (ngx_strcmp(value[i].data, "noclean") == 0) {
            clean = 0;
            continue;
        }

        if (ngx_strcmp(value[i].data, "continuous") == 0) {
            /* continuous is enabled by default, this is for compatibility */
            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }

    if (path.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" must have \"path\" parameter", &cmd->name);
        return NGX_CONF_ERROR;
    }

    hls = ngx_pcalloc(cf->pool, sizeof(ngx_ts_hls_conf_t));
    if (hls == NULL) {
        return NGX_CONF_ERROR;
    }

    hls->path = ngx_pcalloc(cf->pool, sizeof(ngx_path_t));
    if (hls->path == NULL) {
        return NGX_CONF_ERROR;
    }

    hls->path->name = path;

    hls->min_seg = min_seg;
    hls->max_seg = max_seg;
    hls->analyze = analyze ? analyze : min_seg;
    hls->max_size = max_size;
    hls->nsegs = nsegs;
    hls->continuous = 1;  /* enabled by default for nginx-rtmp-module compatibility */

    if (clean) {
        hls->path->manager = ngx_ts_hls_file_manager;
    }

    hls->path->data = hls;
    hls->path->conf_file = cf->conf_file->file.name.data;
    hls->path->line = cf->conf_file->line;

    if (ngx_add_path(cf, &hls->path) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    *field = hls;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_ts_hls_restore_playlist(ngx_ts_hls_t *hls, ngx_ts_hls_variant_t *var)
{
    ngx_fd_t        fd;
    ssize_t         n;
    u_char         *p, *last, *line_start;
    u_char          buffer[4096];
    ngx_uint_t      max_seg_id = 0;
    ngx_ts_stream_t *ts;

    ts = hls->ts;

    /* Try to open existing playlist */
    fd = ngx_open_file(var->m3u8_path, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (fd == NGX_INVALID_FILE) {
        /* No existing playlist, start fresh */
        hls->discont_from = 0;
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, ts->log, 0,
                   "ts hls restoring playlist \"%s\"", var->m3u8_path);

    n = ngx_read_fd(fd, buffer, sizeof(buffer) - 1);
    ngx_close_file(fd);

    if (n <= 0) {
        hls->discont_from = 0;
        return NGX_OK;
    }

    buffer[n] = '\0';
    p = buffer;
    last = buffer + n;

    /* Parse playlist to find the highest segment ID */
    while (p < last) {
        line_start = p;

        /* Find end of line */
        while (p < last && *p != '\n' && *p != '\r') {
            p++;
        }

        /* Check if this line contains a segment reference */
        if (p > line_start && *(p-3) == '.' && *(p-2) == 't' && *(p-1) == 's') {
            u_char *seg_start = p - 1;
            ngx_uint_t seg_id;

            /* Find the segment ID by looking backwards for the dash */
            while (seg_start > line_start && *seg_start != '-') {
                seg_start--;
            }

            if (*seg_start == '-') {
                seg_id = ngx_atoi(seg_start + 1, p - seg_start - 4); /* -1 for dash, -3 for .ts */
                if (seg_id != NGX_ERROR && (ngx_uint_t)seg_id > max_seg_id) {
                    max_seg_id = (ngx_uint_t)seg_id;
                }
            }
        }

        /* Skip to next line */
        while (p < last && (*p == '\n' || *p == '\r')) {
            p++;
        }
    }

    if (max_seg_id > 0) {
        /* Set the next segment ID to continue from where we left off */
        var->seg = max_seg_id + 1;
        hls->discont_from = var->seg;

        /* Reset timing state - will be set properly when first segment after restart is processed */
        var->last_seg_end_dts = 0;

        ngx_log_debug2(NGX_LOG_DEBUG_CORE, ts->log, 0,
                       "ts hls restored: next_seg=%ui, discont_from=%ui",
                       var->seg, hls->discont_from);
    } else {
        hls->discont_from = 0;
        var->last_seg_end_dts = 0;
    }

    return NGX_OK;
}
