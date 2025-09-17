
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_ts_stream.h"


#ifndef _NGX_TS_HLS_H_INCLUDED_
#define _NGX_TS_HLS_H_INCLUDED_


typedef struct {
    ngx_path_t            *path;
    ngx_msec_t             min_seg;
    ngx_msec_t             max_seg;
    ngx_msec_t             analyze;
    size_t                 max_size;
    ngx_uint_t             nsegs;
    ngx_flag_t             continuous; /* hls_continuous behavior */
} ngx_ts_hls_conf_t;


typedef struct {
    ngx_uint_t             id;
    uint64_t               duration;
    off_t                  size;
} ngx_ts_hls_segment_t;


typedef struct {
    ngx_file_t             file;
    ngx_chain_t           *prologue;

    ngx_uint_t             bandwidth;
    ngx_uint_t             bandwidth_bytes;
    uint64_t               bandwidth_dts;

    ngx_ts_hls_segment_t  *segs;
    ngx_uint_t             nsegs;
    ngx_uint_t             seg;
    uint64_t               seg_dts;

    ngx_uint_t             discont_from;  /* first new segment id after restart */

    u_char                *m3u8_path;
    u_char                *m3u8_tmp_path;
    ngx_str_t              path;      /* prefix: <dir>/<name>- */

    ngx_ts_program_t      *prog;
} ngx_ts_hls_variant_t;


typedef struct {
    ngx_ts_stream_t       *ts;
    ngx_ts_hls_conf_t     *conf;

    ngx_str_t              name;  /* stream name */

    u_char                *m3u8_path;
    u_char                *m3u8_tmp_path;
    ngx_str_t              path;  /* dir: <base> */

    ngx_ts_hls_variant_t   var;   /* single-variant only */

    ngx_uint_t             done;  /* unsigned  done:1; */
} ngx_ts_hls_t;


ngx_ts_hls_t *ngx_ts_hls_create(ngx_ts_hls_conf_t *conf, ngx_ts_stream_t *ts,
    ngx_str_t *name);
char *ngx_ts_hls_set_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


#endif /* _NGX_TS_HLS_H_INCLUDED_ */
