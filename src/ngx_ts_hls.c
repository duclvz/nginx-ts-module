
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

static ngx_int_t ngx_ts_hls_restore(ngx_ts_hls_t *hls, ngx_ts_hls_variant_t *var);

static ngx_msec_t ngx_ts_hls_file_manager(void *data);
static ngx_int_t ngx_ts_hls_manage_file(ngx_tree_ctx_t *ctx, ngx_str_t *path);
static ngx_int_t ngx_ts_hls_manage_directory(ngx_tree_ctx_t *ctx,
    ngx_str_t *path);
static ngx_int_t ngx_ts_hls_delete_directory(ngx_tree_ctx_t *ctx,
    ngx_str_t *path);
static ngx_int_t ngx_ts_hls_delete_file(ngx_tree_ctx_t *ctx, ngx_str_t *path);


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

    /* store stream name for single-variant naming */
    hls->name = *name;

    /* base path only (no per-stream subdirectory) */
    hls->path.len = conf->path->name.len;
    hls->path.data = ngx_pnalloc(ts->pool, hls->path.len + 1);
    if (hls->path.data == NULL) {
        return NULL;
    }

    ngx_sprintf(hls->path.data, "%V%Z", &conf->path->name);

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

    hls->done = 1;

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
    ngx_uint_t             n;
    ngx_ts_stream_t       *ts;
    ngx_ts_program_t      *prog, *chosen;
    ngx_ts_hls_variant_t  *var;

    if (hls->vars) {
        return NGX_OK;
    }

    ts = hls->ts;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ts->log, 0, "ts hls pat");

    /* single-variant mode */
    hls->nvars = 1;
    hls->vars = ngx_pcalloc(ts->pool, sizeof(ngx_ts_hls_variant_t));
    if (hls->vars == NULL) {
        return NGX_ERROR;
    }

    /* choose program: prefer one with video, otherwise first */
    chosen = NULL;
    for (n = 0; n < ts->nprogs; n++) {
        prog = &ts->progs[n];
        if (chosen == NULL) {
            chosen = prog;
        }
        if (prog->video) {
            chosen = prog;
            break;
        }
    }
    if (chosen == NULL && ts->nprogs) {
        chosen = &ts->progs[0];
    }

    var = &hls->vars[0];
    var->prog = chosen;
    var->file.fd = NGX_INVALID_FILE;
    var->file.log = ts->log;

    var->nsegs = hls->conf->nsegs;
    var->segs = ngx_pcalloc(ts->pool,
                            sizeof(ngx_ts_hls_segment_t) * hls->conf->nsegs);
    if (var->segs == NULL) {
        return NGX_ERROR;
    }

    /* {path}/{name}-{id}.ts prefix */
    len = hls->path.len + 1 + hls->name.len + 1 + NGX_INT_T_LEN + sizeof(".ts");
    p = ngx_pnalloc(ts->pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }
    var->path.data = p;
    p = ngx_sprintf(p, "%V/%V-", &hls->path, &hls->name);
    var->path.len = p - var->path.data;

    /* {path}/{name}.m3u8 and tmp */
    len = hls->path.len + 1 + hls->name.len + sizeof(".m3u8");
    var->m3u8_path = ngx_pnalloc(ts->pool, len);
    if (var->m3u8_path == NULL) {
        return NGX_ERROR;
    }
    ngx_sprintf(var->m3u8_path, "%V/%V.m3u8%Z", &hls->path, &hls->name);

    len += sizeof(".tmp") - 1;
    var->m3u8_tmp_path = ngx_pnalloc(ts->pool, len);
    if (var->m3u8_tmp_path == NULL) {
        return NGX_ERROR;
    }
    ngx_sprintf(var->m3u8_tmp_path, "%s.tmp%Z", var->m3u8_path);

    /* continuous mode: restore prior playlist; if exists, mark resumed */
    var->resumed = (ngx_ts_hls_restore(hls, var) == NGX_OK);

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
    seg->discont = (var->resumed != 0);
    var->resumed = 0;

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

    return NGX_OK;
}


static ngx_int_t
ngx_ts_hls_update_playlist(ngx_ts_hls_t *hls, ngx_ts_hls_variant_t *var)
{
    size_t                 len;
    u_char                *p, *data;
    ngx_int_t              rc;
    ngx_uint_t             i, ms, td;
    ngx_ts_stream_t       *ts;
    ngx_ts_hls_segment_t  *seg;

    ts = hls->ts;

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, ts->log, 0,
                   "ts hls update playlist \"%s\"", var->m3u8_path);

    /* header */
    len = sizeof("#EXTM3U\n"
                 "#EXT-X-VERSION:3\n"
                 "#EXT-X-MEDIA-SEQUENCE:\n"
                 "#EXT-X-TARGETDURATION:\n\n") - 1
          + 2 * NGX_INT_T_LEN;

    td = (ngx_uint_t) (hls->conf->min_seg / 1000);
    ms = var->seg;

    for (i = 0; i < var->nsegs; i++) {
        seg = &var->segs[(var->seg + i) % var->nsegs];

        if (seg->duration) {
            double dsec = seg->duration / 90000.0;

            /* set media sequence to the first present segment id */
            if (ms == var->seg) {
                ms = seg->id;
            }

            if (dsec > (double) td) {
                ngx_uint_t r = (ngx_uint_t) (dsec + 0.5);
                if (r > td) {
                    td = r;
                }
            }

            len += sizeof("#EXTINF:.xxx,\n") - 1
                   + hls->name.len + 1 /* '-' */
                   + NGX_INT_T_LEN
                   + sizeof(".ts\n") - 1;

            if (seg->discont) {
                len += sizeof("#EXT-X-DISCONTINUITY\n") - 1;
            }
        }
    }

    data = ngx_alloc(len, ts->log);
    if (data == NULL) {
        return NGX_ERROR;
    }

    p = data;

    p = ngx_sprintf(p, "#EXTM3U\n"
                       "#EXT-X-VERSION:3\n"
                       "#EXT-X-MEDIA-SEQUENCE:%ui\n"
                       "#EXT-X-TARGETDURATION:%ui\n\n",
                       ms, td);

    for (i = 0; i < var->nsegs; i++) {
        seg = &var->segs[(var->seg + i) % var->nsegs];

        if (seg->duration) {
            if (seg->discont) {
                p = ngx_cpymem(p, "#EXT-X-DISCONTINUITY\n",
                               sizeof("#EXT-X-DISCONTINUITY\n") - 1);
            }

            p = ngx_sprintf(p, "#EXTINF:%.3f,\n", seg->duration / 90000.);

            p = ngx_sprintf(p, "%V-%ui.ts\n", &hls->name, seg->id);
        }
    }

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

static ngx_int_t
ngx_ts_hls_restore(ngx_ts_hls_t *hls, ngx_ts_hls_variant_t *var)
{
    ngx_file_t        file;
    ssize_t           ret;
    off_t             offset;
    u_char           *p, *end, *last, *next, c;
    double            duration;
    ngx_int_t         discont;
    ngx_uint_t        mseq_set;
    uint64_t          id, mag;
    u_char            buf[4096];

    ngx_memzero(&file, sizeof(file));

    file.log = hls->ts->log;
    file.fd = ngx_open_file(var->m3u8_path, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (file.fd == NGX_INVALID_FILE) {
        return NGX_DECLINED;
    }
    /* Fast restore: parse only media sequence from the head, keep logic simple */
    ret = ngx_read_file(&file, buf, 2048, 0);
    if (ret > 0) {
        p = buf;
        end = buf + ret;
        for ( ;; ) {
            last = ngx_strlchr(p, end, '\n');
            if (last == NULL) {
                break;
            }
            if (p != last && last[-1] == '\r') {
                last--;
            }
            if ((size_t)(last - p) > sizeof("#EXT-X-MEDIA-SEQUENCE:") - 1
                && ngx_memcmp(p, "#EXT-X-MEDIA-SEQUENCE:",
                              sizeof("#EXT-X-MEDIA-SEQUENCE:") - 1) == 0)
            {
                var->seg = (ngx_uint_t) ngx_atoi(p + sizeof("#EXT-X-MEDIA-SEQUENCE:") - 1,
                                                 last - p - (sizeof("#EXT-X-MEDIA-SEQUENCE:") - 1));
                break;
            }
            p = last + 1;
        }
    }

    goto done;


    offset = 0;
    duration = 0;
    discont = 0;
    mseq_set = 0;

    for ( ;; ) {
        ret = ngx_read_file(&file, buf, sizeof(buf), offset);
        if (ret <= 0) {
            break;
        }

        p = buf;
        end = buf + ret;

        for ( ;; ) {
            last = ngx_strlchr(p, end, '\n');

            if (last == NULL) {
                if (p == buf) {
                    goto done;
                }
                break;
            }

            next = last + 1;
            offset += (next - p);

            if (p != last && last[-1] == '\r') {
                last--;
            }

            if ((size_t)(last - p) > sizeof("#EXT-X-MEDIA-SEQUENCE:") - 1
                && ngx_memcmp(p, "#EXT-X-MEDIA-SEQUENCE:",
                              sizeof("#EXT-X-MEDIA-SEQUENCE:") - 1) == 0)
            {
                var->seg = (ngx_uint_t) ngx_atoi(p + sizeof("#EXT-X-MEDIA-SEQUENCE:") - 1,
                                                 last - p - (sizeof("#EXT-X-MEDIA-SEQUENCE:") - 1));
                mseq_set = 1;
            }

            if ((size_t)(last - p) >= sizeof("#EXT-X-DISCONTINUITY") - 1
                && ngx_memcmp(p, "#EXT-X-DISCONTINUITY",
                              sizeof("#EXT-X-DISCONTINUITY") - 1) == 0)
            {
                discont = 1;
            }

            if ((size_t)(last - p) > sizeof("#EXTINF:") - 1
                && ngx_memcmp(p, "#EXTINF:", sizeof("#EXTINF:") - 1) == 0)
            {
                duration = strtod((const char *) (p + sizeof("#EXTINF:") - 1), NULL);
            }

            /* find '.ts' at the end */
            if (last - p >= 3 && last[-3] == '.' && last[-2] == 't' && last[-1] == 's') {
                /* parse trailing digits before .ts */
                id = 0;
                mag = 1;
                for (c = *(last - 4); ; ) {
                    u_char *pa = last - 4;
                    for ( ; pa >= p; pa--) {
                        if (*pa < '0' || *pa > '9') {
                            break;
                        }
                        id += (*pa - '0') * mag;
                        mag *= 10;
                    }
                    break;
                }

                ngx_ts_hls_segment_t *s = &var->segs[var->seg % var->nsegs];
                ngx_memzero(s, sizeof(*s));
                s->id = (ngx_uint_t) id;
                s->duration = (uint64_t) (duration * 90000. + 0.5);
                s->size = 0;
                s->discont = discont ? 1 : 0;

                var->seg++;
                discont = 0;
                duration = 0;
            }

            p = next;
        }
    }

    done:
    ngx_close_file(file.fd);

    /* if there was no media sequence in file but segments parsed, adjust seg */
    (void) mseq_set;

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
