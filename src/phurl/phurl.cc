//: ----------------------------------------------------------------------------
//: Copyright (C) 2016 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    main.cc
//: \details: TODO
//: \author:  Reed P. Morrison
//: \date:    02/07/2014
//:
//:   Licensed under the Apache License, Version 2.0 (the "License");
//:   you may not use this file except in compliance with the License.
//:   You may obtain a copy of the License at
//:
//:       http://www.apache.org/licenses/LICENSE-2.0
//:
//:   Unless required by applicable law or agreed to in writing, software
//:   distributed under the License is distributed on an "AS IS" BASIS,
//:   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//:   See the License for the specific language governing permissions and
//:   limitations under the License.
//:
//: ----------------------------------------------------------------------------

//: ----------------------------------------------------------------------------
//: Includes
//: ----------------------------------------------------------------------------
#include "ndebug.h"
#include "tls_util.h"
#include "cb.h"
#include "nconn.h"
#include "nconn_tcp.h"
#include "nconn_tls.h"
#include "nresolver.h"

#include "hlx/atomic.h"
#include "hlx/resp.h"
#include "hlx/status.h"
#include "hlx/stat.h"
#include "hlx/trace.h"
#include "hlx/string_util.h"
#include "hlx/subr.h"
#include "hlx/evr.h"
#include "hlx/nbq.h"

#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/prettywriter.h"

#include <string.h>

// getrlimit
#include <sys/time.h>
#include <sys/resource.h>

// signal
#include <signal.h>

#include <list>
#include <set>
#include <algorithm>
#include <unordered_set>

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <pthread.h>
#include <unistd.h>
#include <getopt.h> // For getopt_long
#include <termios.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>

#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif
#include <inttypes.h>

// Profiler
#ifdef ENABLE_PROFILER
#include <gperftools/profiler.h>
#include <gperftools/heap-profiler.h>
#endif

// TLS
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

// Get resource limits
#include <sys/resource.h>

//: ----------------------------------------------------------------------------
//: Constants
//: ----------------------------------------------------------------------------
#define NB_ENABLE  1
#define NB_DISABLE 0

#define MAX_READLINE_SIZE 1024

//: ----------------------------------------------------------------------------
//: Enums
//: ----------------------------------------------------------------------------
// ---------------------------------------
// Output types
// ---------------------------------------
typedef enum {
        OUTPUT_LINE_DELIMITED,
        OUTPUT_JSON
} output_type_t;

// ---------------------------------------
// Output types
// ---------------------------------------
typedef enum {
        PART_HOST = 1,
        PART_SERVER = 1 << 1,
        PART_STATUS_CODE = 1 << 2,
        PART_HEADERS = 1 << 3,
        PART_BODY = 1 << 4
} output_part_t;

//: ----------------------------------------------------------------------------
//: Macros
//: ----------------------------------------------------------------------------
#define UNUSED(x) ( (void)(x) )
#define ARESP(_str) l_responses_str += _str

//: ----------------------------------------------------------------------------
//: Types
//: ----------------------------------------------------------------------------
typedef std::map <std::string, uint32_t> summary_map_t;
// Summary info
typedef struct summary_info_struct {
        uint32_t m_success;
        uint32_t m_cancelled;
        uint32_t m_error_addr;
        uint32_t m_error_addr_timeout;
        uint32_t m_error_conn;
        uint32_t m_error_unknown;
        uint32_t m_tls_error_hostname;
        uint32_t m_tls_error_self_signed;
        uint32_t m_tls_error_expired;
        uint32_t m_tls_error_issuer;
        uint32_t m_tls_error_other;
        summary_map_t m_tls_protocols;
        summary_map_t m_tls_ciphers;
        summary_info_struct():
                m_success(),
                m_cancelled(),
                m_error_addr(),
                m_error_addr_timeout(),
                m_error_conn(),
                m_error_unknown(),
                m_tls_error_hostname(),
                m_tls_error_self_signed(),
                m_tls_error_expired(),
                m_tls_error_issuer(),
                m_tls_error_other(),
                m_tls_protocols(),
                m_tls_ciphers()
        {};
} summary_info_t;

typedef struct tls_info_struct {
        const char *m_tls_info_cipher_str;
        const char *m_tls_info_protocol_str;
        tls_info_struct():
                m_tls_info_cipher_str(NULL),
                m_tls_info_protocol_str(NULL)
        {}
} tls_info_t;

// Host
typedef struct host_struct {
        std::string m_host;
        std::string m_hostname;
        std::string m_id;
        std::string m_where;
        std::string m_url;
        uint16_t m_port;
        host_struct():
                m_host(),
                m_hostname(),
                m_id(),
                m_where(),
                m_url(),
                m_port(0)
        {};
} phurl_host_t;
typedef std::list <phurl_host_t> phurl_host_list_t;
typedef std::map <std::string, tls_info_t> tls_info_map_t;
class t_phurl;
typedef std::list <t_phurl *> t_phurl_list_t;

#if 0
//typedef std::list <phurl_resp_t *> phurl_resp_list_t;
typedef std::list <ns_hlx::phurl_u *> phurl_h_resp_list_t;
typedef std::set <uint64_t> phurl_uid_set_t;
#endif

#if 0
class broadcast_h;
#endif

//: ----------------------------------------------------------------------------
//: Settings
//: ----------------------------------------------------------------------------
#if 0
typedef struct settings_struct
{
        bool m_verbose;
        bool m_color;
        bool m_quiet;
        bool m_show_stats;
        bool m_show_summary;
#if 0
        ns_hlx::srvr *m_srvr;
        broadcast_h *m_broadcast_h;
        phurl_h_resp_list_t m_phr_list;
#endif
        phurl_host_list_t *m_host_list;
        uint32_t m_total_reqs;
        uint32_t m_timeout_ms;
        float m_completion_ratio;

        // Results
        pthread_mutex_t m_mutex;
        summary_info_t m_summary_info;
        tls_info_map_t m_tls_info_map;

        // ---------------------------------
        // Defaults...
        // ---------------------------------
        settings_struct(void) :
                m_verbose(false),
                m_color(false),
                m_quiet(false),
                m_show_stats(false),
                m_show_summary(false),
#if 0
                m_srvr(NULL),
                m_broadcast_h(NULL),
                m_phr_list(),
#endif
                m_host_list(NULL),
                m_total_reqs(0),
                m_timeout_ms(0),
                m_completion_ratio(100.0),
                m_mutex(),
                m_summary_info(),
                m_tls_info_map()
        {
                pthread_mutex_init(&m_mutex, NULL);
        }

private:
        // Disallow copy/assign
        settings_struct& operator=(const settings_struct &);
        settings_struct(const settings_struct &);

} settings_struct_t;
#endif

//: ----------------------------------------------------------------------------
//: Globals
//: ----------------------------------------------------------------------------
static bool g_test_finished = false;
static bool g_cancelled = false;
static t_phurl_list_t g_t_phurl_list;

//: ----------------------------------------------------------------------------
//: Prototypes
//: ----------------------------------------------------------------------------
void display_status_line(void);
void display_summary(void);
std::string dump_all_responses(output_type_t a_output_type, int a_part_map);
int32_t read_file(const char *a_file, char **a_buf, uint32_t *a_len);

//: ----------------------------------------------------------------------------
//: t_hurl
//: ----------------------------------------------------------------------------
class t_phurl
{
public:
        // -------------------------------------------------
        // Types
        // -------------------------------------------------

        // -------------------------------------------------
        // Public methods
        // -------------------------------------------------
        t_phurl(uint32_t a_max_parallel,
                int32_t a_num_to_request):
                m_stopped(true),
                m_t_run_thread(),
                m_num_in_progress(0),
                m_orphan_in_q(NULL),
                m_orphan_out_q(NULL),
                m_evr_loop(NULL),
                m_is_initd(false),
                m_num_parallel_max(a_max_parallel)
        {
                m_orphan_in_q = new ns_hlx::nbq(4096);
                m_orphan_out_q = new ns_hlx::nbq(4096);
        }
        ~t_phurl()
        {
                if(m_orphan_in_q)
                {
                        delete m_orphan_in_q;
                        m_orphan_in_q = NULL;
                }
                if(m_orphan_out_q)
                {
                        delete m_orphan_out_q;
                        m_orphan_out_q = NULL;
                }
        }
        int32_t init(void)
        {
                if(m_is_initd) return HLX_STATUS_OK;
                // TODO -make loop configurable
#if defined(__linux__)
                m_evr_loop = new ns_hlx::evr_loop(ns_hlx::EVR_LOOP_EPOLL, 512);
#elif defined(__FreeBSD__) || defined(__APPLE__)
                m_evr_loop = new ns_hlx::evr_loop(ns_hlx::EVR_LOOP_SELECT, 512);
#else
                m_evr_loop = new ns_hlx::evr_loop(ns_hlx::EVR_LOOP_SELECT, 512);
#endif
                if(!m_evr_loop)
                {
                        TRC_ERROR("m_evr_loop == NULL");
                        return HLX_STATUS_ERROR;
                }
                m_is_initd = true;
                return HLX_STATUS_OK;
        }
        int run(void) {
                int32_t l_pthread_error = 0;
                l_pthread_error = pthread_create(&m_t_run_thread, NULL, t_run_static, this);
                if (l_pthread_error != 0) {
                        return HLX_STATUS_ERROR;
                }
                return HLX_STATUS_OK;
        };
        void *t_run(void *a_nothing);
        int32_t subr_try_start(void);
        void stop(void) {
                m_stopped = true;
                m_evr_loop->signal();
        }
        bool is_running(void) { return !m_stopped; }
        int32_t cancel_timer(void *a_timer) {
                if(!m_evr_loop) return HLX_STATUS_ERROR;
                if(!a_timer) return HLX_STATUS_OK;
                ns_hlx::evr_timer_t *l_t = static_cast<ns_hlx::evr_timer_t *>(a_timer);
                return m_evr_loop->cancel_timer(l_t);
        }
        //int32_t cleanup_session(session *a_ses, ns_hlx::nconn *a_nconn);
        void add_stat_to_agg(const ns_hlx::conn_stat_t &a_conn_stat, uint16_t a_status_code);

        // -------------------------------------------------
        // Public members
        // -------------------------------------------------
        sig_atomic_t m_stopped;
        pthread_t m_t_run_thread;
        uint32_t m_num_in_progress;
        ns_hlx::nbq *m_orphan_in_q;
        ns_hlx::nbq *m_orphan_out_q;
private:
        // -------------------------------------------------
        // Private methods
        // -------------------------------------------------
        // Disallow copy/assign
        t_phurl& operator=(const t_phurl &);
        t_phurl(const t_phurl &);

        //Helper for pthreads
        static void *t_run_static(void *a_context)
        {
                return reinterpret_cast<t_phurl *>(a_context)->t_run(NULL);
        }
        ns_hlx::nconn *create_new_nconn(void);
        int32_t subr_start(void);
        int32_t subr_dequeue(void);
        // -------------------------------------------------
        // Private members
        // -------------------------------------------------
        ns_hlx::evr_loop *m_evr_loop;
        bool m_is_initd;
        uint32_t m_num_parallel_max;

};

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
ns_hlx::uint64_atomic_t g_cur_subr_uid = 0;
static inline uint64_t get_next_subr_uuid(void)
{
        return ++g_cur_subr_uid;
}

//: ----------------------------------------------------------------------------
//: session
//: ----------------------------------------------------------------------------
class session {

public:
        // -------------------------------------------------
        // Public members
        // -------------------------------------------------
        ns_hlx::nconn *m_nconn;
        t_phurl *m_t_phurl;
        ns_hlx::evr_timer_t *m_timer_obj;
        ns_hlx::resp *m_resp;
        ns_hlx::nbq *m_in_q;
        ns_hlx::nbq *m_out_q;
        bool m_in_q_detached;
        ns_hlx::subr *m_subr;
        uint64_t m_idx;
        // -------------------------------------------------
        // Public Static (class) methods
        // -------------------------------------------------
        static int32_t evr_fd_readable_cb(void *a_data) {return run_state_machine(a_data, ns_hlx::EVR_MODE_READ);}
        static int32_t evr_fd_writeable_cb(void *a_data){return run_state_machine(a_data, ns_hlx::EVR_MODE_WRITE);}
        static int32_t evr_fd_error_cb(void *a_data) {return run_state_machine(a_data, ns_hlx::EVR_MODE_ERROR);}
        static int32_t evr_fd_timeout_cb(void *a_ctx, void *a_data){return run_state_machine(a_data, ns_hlx::EVR_MODE_TIMEOUT);}
        // -------------------------------------------------
        // Public methods
        // -------------------------------------------------
        session(void):
                m_nconn(NULL),
                m_t_phurl(NULL),
                m_timer_obj(NULL),
                m_resp(NULL),
                m_in_q(NULL),
                m_out_q(NULL),
                m_in_q_detached(false),
                m_subr(NULL),
                m_idx(0),
                m_timeout_ms(10000)
        {}
        int32_t cancel_timer(void *a_timer);
        int32_t teardown(ns_hlx::http_status_t a_status);
        int32_t subr_error(ns_hlx::http_status_t a_status);
        uint64_t get_idx(void) {return m_idx;}
        void set_idx(uint64_t a_idx) {m_idx = a_idx;}
        void clear(void);
        uint32_t get_timeout_ms(void);
        void set_timeout_ms(uint32_t a_t_ms);

        // -------------------------------------------------
        // Public members
        // -------------------------------------------------
        uint32_t m_timeout_ms;

private:
        // -------------------------------------------------
        // Private methods
        // -------------------------------------------------
        // Disallow copy/assign
        session& operator=(const session &);
        session(const session &);
        bool subr_complete(void);
        void subr_log_status(uint16_t a_status = 0);

        // -------------------------------------------------
        // Private Static (class) methods
        // -------------------------------------------------
        static int32_t run_state_machine(void *a_data, ns_hlx::evr_mode_t a_conn_mode);
};

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
void *t_phurl::t_run(void *a_nothing)
{
        int32_t l_s;
        l_s = init();
        if(l_s != HLX_STATUS_OK)
        {
                NDBG_PRINT("Error performing init.\n");
                return NULL;
        }
        m_stopped = false;

        l_s = subr_dequeue();
        // TODO check return status???
        // -------------------------------------------------
        // Run server
        // -------------------------------------------------
        while(!m_stopped)
        {
                //NDBG_PRINT("Running.\n");
                l_s = m_evr_loop->run();
                if(l_s != HLX_STATUS_OK)
                {
                        // TODO log run failure???
                }
                // Subrequests
                l_s = subr_dequeue();
                if(l_s != HLX_STATUS_OK)
                {
                        //NDBG_PRINT("Error performing subr_try_deq.\n");
                        //return NULL;
                }
        }
        //NDBG_PRINT("Stopped...\n");
        m_stopped = true;
        return NULL;
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t t_phurl::subr_dequeue(void)
{
#if 0
        uint32_t l_dq = 0;
        while(!g_test_finished &&
              !m_stopped &&
              (m_num_in_progress < m_num_parallel_max) &&
              ((m_num_to_request < 0) || ((uint32_t)m_num_to_request > m_stat.m_upsv_reqs)))
        {
                int32_t l_s;
                l_s = subr_start();
                if(l_s != HLX_STATUS_OK)
                {
                        // Log error
                        NDBG_PRINT("%sERROR DEQUEUEING%s\n", ANSI_COLOR_FG_RED, ANSI_COLOR_OFF);
                }
                else
                {
                      ++m_num_in_progress;
                }
                ++l_dq;
        }
        //NDBG_PRINT("%sDEQUEUEd%s: %u progress/max %u/%u\n",
        //                ANSI_COLOR_FG_BLUE, ANSI_COLOR_OFF,
        //                l_dq,
        //                m_num_in_progress, m_num_parallel_max);
#endif
        return HLX_STATUS_OK;
}

//: ----------------------------------------------------------------------------
//: Handler
//: ----------------------------------------------------------------------------
#if 0
class broadcast_h: public ns_hlx::phurl_h
{
public:
        int32_t do_get_bc(ns_hlx::srvr *a_srvr,
                          ns_hlx::t_srvr *a_t_srvr,
                          const phurl_host_list_t &a_host_list,
                          ns_hlx::phurl_u *a_phr);
        int32_t create_resp(ns_hlx::subr &a_subr,
                            ns_hlx::phurl_u *l_fanout_resp);
        static int32_t s_completion_cb(ns_hlx::subr &a_subr,
                                       ns_hlx::nconn &a_nconn,
                                       ns_hlx::resp &a_resp);
        static int32_t s_error_cb(ns_hlx::subr &a_subr,
                                  ns_hlx::nconn *a_nconn,
                                  ns_hlx::http_status_t a_status,
                                  const char *a_error_str);
        static int32_t s_create_resp(ns_hlx::phurl_u *a_phr);
};
#endif

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
#if 0
int32_t broadcast_h::do_get_bc(ns_hlx::srvr *a_srvr,
                               ns_hlx::t_srvr *a_t_srvr,
                               const phurl_host_list_t &a_host_list,
                               ns_hlx::phurl_u *a_phr)
{
        if(!a_srvr)
        {
                return HLX_STATUS_ERROR;
        }
        // Create request state if not already made
        a_phr->m_phurl_h = this;
        a_phr->m_create_resp_cb = broadcast_h::s_create_resp;
        for(phurl_host_list_t::const_iterator i_host = a_host_list.begin(); i_host != a_host_list.end(); ++i_host)
        {
                // Make subr
                ns_hlx::subr *l_subr = new ns_hlx::subr(m_subr_template);
                l_subr->set_uid(a_srvr->get_next_subr_uuid());
                l_subr->set_host(i_host->m_host);
                if(!i_host->m_hostname.empty())
                {
                        l_subr->set_hostname(i_host->m_hostname);
                }
                if(!i_host->m_id.empty())
                {
                        l_subr->set_id(i_host->m_id);
                }
                if(!i_host->m_where.empty())
                {
                        l_subr->set_where(i_host->m_where);
                }
                if(i_host->m_port != 0)
                {
                        l_subr->set_port(i_host->m_port);
                }
                l_subr->reset_label();
                l_subr->set_data(a_phr);

                // Add to pending map
                a_phr->m_pending_subr_uid_map[l_subr->get_uid()] = l_subr;

                int32_t l_status = 0;
                l_status = add_subr_t_srvr(a_t_srvr, *l_subr);
                if(l_status != HLX_STATUS_OK)
                {
                        //("Error: performing add_subreq.\n");
                        return HLX_STATUS_ERROR;
                }
        }
        a_phr->m_size = a_phr->m_pending_subr_uid_map.size();
        a_phr->m_completion_ratio = g_settings->m_completion_ratio;
        a_phr->m_timeout_ms = g_settings->m_timeout_ms;
        if(a_phr->m_timeout_ms)
        {
                if(!a_t_srvr)
                {
                        return HLX_STATUS_ERROR;
                }
                //printf("Add timeout: %u\n", m_timeout_ms);
                int32_t l_status;
                l_status = add_timer(a_t_srvr, a_phr->m_timeout_ms, ns_hlx::phurl_u::s_timeout_cb, a_phr, &(a_phr->m_timer));
                if(l_status != HLX_STATUS_OK)
                {
                        return HLX_STATUS_ERROR;
                }
        }
        return HLX_STATUS_OK;
}
#endif

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
#if 0
int32_t broadcast_h::create_resp(ns_hlx::subr &a_subr, ns_hlx::phurl_u *a_fanout_resp)
{
        //printf("%s.%s.%d: %sDONE%s\n",__FILE__,__FUNCTION__,__LINE__, ANSI_COLOR_FG_GREEN, ANSI_COLOR_OFF);
        return HLX_STATUS_OK;
}
#endif

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
#if 0
int32_t broadcast_h::s_completion_cb(ns_hlx::subr &a_subr, ns_hlx::nconn &a_nconn, ns_hlx::resp &a_resp)
{
        ns_hlx::phurl_u *l_phr = static_cast<ns_hlx::phurl_u *>(a_subr.get_data());
        if(!l_phr)
        {
                return HLX_STATUS_ERROR;
        }
        ns_hlx::hlx_resp *l_resp = new ns_hlx::hlx_resp();
        l_resp->m_resp = &a_resp;
        l_resp->m_subr = &a_subr;
        l_phr->m_resp_list.push_back(l_resp);
        settings_struct_t *l_s = static_cast<settings_struct_t *>(l_phr->m_data);
        if(l_s) pthread_mutex_lock(&(l_s->m_mutex));
        if(l_s)
        {
                ++(l_s->m_summary_info.m_success);
                SSL *l_SSL = ns_hlx::nconn_get_SSL(a_nconn);
                if(l_SSL)
                {
                        int32_t l_protocol_num = ns_hlx::get_tls_info_protocol_num(l_SSL);
                        tls_info_t l_ti;
                        l_ti.m_tls_info_cipher_str = ns_hlx::get_tls_info_cipher_str(l_SSL);
                        l_ti.m_tls_info_protocol_str = ns_hlx::get_tls_info_protocol_str(l_protocol_num);
                        l_s->m_tls_info_map[a_subr.get_host()] = l_ti;
                        ++(l_s->m_summary_info.m_tls_ciphers[l_ti.m_tls_info_cipher_str]);
                        ++(l_s->m_summary_info.m_tls_protocols[l_ti.m_tls_info_protocol_str]);
#if 0
                        SSL_SESSION *m_tls_session = SSL_get_session(m_tls);
                        SSL_SESSION_print_fp(stdout, m_tls_session);
                        X509* l_cert = NULL;
                        l_cert = SSL_get_peer_certificate(m_tls);
                        if(NULL == l_cert)
                        {
                                NDBG_PRINT("SSL_get_peer_certificate error.  tls: %p\n", m_tls);
                                return NC_STATUS_ERROR;
                        }
                        X509_print_fp(stdout, l_cert);
#endif
                }
        }
        l_phr->m_pending_subr_uid_map.erase(a_subr.get_uid());
        if(l_s) pthread_mutex_unlock(&(l_s->m_mutex));
        return s_done_check(a_subr, l_phr);
}
#endif

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
#if 0
int32_t broadcast_h::s_error_cb(ns_hlx::subr &a_subr,
                                ns_hlx::nconn *a_nconn,
                                ns_hlx::http_status_t a_status,
                                const char *a_error_str)
{
        //printf("%s.%s.%d: subr_host: %s\n",__FILE__,__FUNCTION__,__LINE__,a_subr.get_host().c_str());
        ns_hlx::phurl_u *l_phr = static_cast<ns_hlx::phurl_u *>(a_subr.get_data());
        if(!l_phr)
        {
                //printf("%s.%s.%d: l_phr == NULL\n",__FILE__,__FUNCTION__,__LINE__);
                return HLX_STATUS_ERROR;
        }
        ns_hlx::hlx_resp *l_resp = new ns_hlx::hlx_resp();
        l_resp->m_resp = NULL;
        l_resp->m_subr = &a_subr;
        l_resp->m_error_str = a_error_str;
        settings_struct_t *l_s = static_cast<settings_struct_t *>(l_phr->m_data);
        if(l_s) pthread_mutex_lock(&(l_s->m_mutex));
        if(!a_nconn && a_status == ns_hlx::HTTP_STATUS_BAD_GATEWAY)
        {
                ++(l_s->m_summary_info.m_error_addr);
        }
        if(a_nconn)
        {
                ns_hlx::conn_status_t l_conn_status = ns_hlx::nconn_get_status(*a_nconn);
                //printf("%s.%s.%d: host:          %s\n",__FILE__,__FUNCTION__,__LINE__,a_subr.get_host().c_str());
                //printf("%s.%s.%d: m_error_str:   %s\n",__FILE__,__FUNCTION__,__LINE__,l_resp->m_error_str.c_str());
                //printf("%s.%s.%d: l_conn_status: %d\n",__FILE__,__FUNCTION__,__LINE__,l_conn_status);
                if(l_s)
                {
                        switch(l_conn_status)
                        {
                        case ns_hlx::CONN_STATUS_CANCELLED:
                        {
                                ++(l_s->m_summary_info.m_cancelled);
                                break;
                        }
                        case ns_hlx::CONN_STATUS_ERROR_ADDR_LOOKUP_FAILURE:
                        {
                                ++(l_s->m_summary_info.m_error_addr);
                                break;
                        }
                        case ns_hlx::CONN_STATUS_ERROR_ADDR_LOOKUP_TIMEOUT:
                        {
                                ++(l_s->m_summary_info.m_error_addr_timeout);
                                break;
                        }
                        case ns_hlx::CONN_STATUS_ERROR_CONNECT_TLS:
                        {
                                ++(l_s->m_summary_info.m_error_conn);
                                // Get last error
                                if(a_nconn)
                                {
                                        SSL *l_tls = ns_hlx::nconn_get_SSL(*a_nconn);
                                        long l_tls_vr = SSL_get_verify_result(l_tls);
                                        if ((l_tls_vr == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) ||
                                            (l_tls_vr == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN))
                                        {
                                                ++(l_s->m_summary_info.m_tls_error_self_signed);
                                        }
                                        else if(l_tls_vr == X509_V_ERR_CERT_HAS_EXPIRED)
                                        {
                                                ++(l_s->m_summary_info.m_tls_error_expired);
                                        }
                                        else if((l_tls_vr == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT) ||
                                                (l_tls_vr == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY))
                                        {
                                                ++(l_s->m_summary_info.m_tls_error_issuer);
                                        }
                                        else
                                        {
                                                //long l_err = ns_hlx::nconn_get_last_SSL_err(a_nconn);
                                                //printf("ERRORXXXX: %ld\n", l_err);
                                                //printf("ERRORXXXX: %s\n", ERR_error_string(l_err,NULL));
                                                //printf("ERRORXXXX: %s\n", l_resp->m_error_str.c_str());
                                                ++(l_s->m_summary_info.m_tls_error_other);
                                        }
                                }
                                break;

                        }
                        case ns_hlx::CONN_STATUS_ERROR_CONNECT_TLS_HOST:
                        {
                                ++(l_s->m_summary_info.m_error_conn);
                                ++(l_s->m_summary_info.m_tls_error_hostname);
                                break;
                        }
                        default:
                        {
                                //printf("CONN STATUS: %d\n", l_conn_status);
                                ++(l_s->m_summary_info.m_error_conn);
                                ++(l_s->m_summary_info.m_error_unknown);
                                break;
                        }
                        }
                }
        }
        l_phr->m_resp_list.push_back(l_resp);
        l_phr->m_pending_subr_uid_map.erase(a_subr.get_uid());
        if(l_s) pthread_mutex_unlock(&(l_s->m_mutex));
        return s_done_check(a_subr, l_phr);
}
#endif

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
#if 0
int32_t broadcast_h::s_create_resp(ns_hlx::phurl_u *a_phr)
{
        return 0;
}
#endif

//: ----------------------------------------------------------------------------
//: \details: Signal handler
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
void sig_handler(int signo)
{
        if (signo == SIGINT)
        {
                // Kill program
                g_test_finished = true;
                g_cancelled = true;
#if 0
                g_settings->m_srvr->stop();
#endif
        }
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int kbhit()
{
        struct timeval l_tv;
        fd_set l_fds;
        l_tv.tv_sec = 0;
        l_tv.tv_usec = 0;
        FD_ZERO(&l_fds);
        FD_SET(STDIN_FILENO, &l_fds);
        //STDIN_FILENO is 0
        select(STDIN_FILENO + 1, &l_fds, NULL, NULL, &l_tv);
        return FD_ISSET(STDIN_FILENO, &l_fds);
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
void nonblock(int state)
{
        struct termios ttystate;
        //get the terminal state
        tcgetattr(STDIN_FILENO, &ttystate);
        if (state == NB_ENABLE)
        {
                //turn off canonical mode
                ttystate.c_lflag &= ~ICANON;
                //minimum of number input read.
                ttystate.c_cc[VMIN] = 1;
        } else if (state == NB_DISABLE)
        {
                //turn on canonical mode
                ttystate.c_lflag |= ICANON;
        }
        //set the terminal attributes.
        tcsetattr(STDIN_FILENO, TCSANOW, &ttystate);
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int command_exec(void)
{
        int i = 0;
        char l_cmd = ' ';
        //bool l_sent_stop = false;
        //bool l_first_time = true;
        nonblock(NB_ENABLE);

#if 0
        if(!a_settings.m_host_list)
        {
                return -1;
        }
#endif

        // Split host list between threads...
#if 0
        ns_hlx::srvr::t_srvr_list_t &l_t_srvr_list = a_settings.m_srvr->get_t_srvr_list();
        size_t l_num_per = a_settings.m_host_list->size() / l_t_srvr_list.size();
        phurl_host_list_t::iterator i_h = a_settings.m_host_list->begin();
        for(ns_hlx::srvr::t_srvr_list_t::iterator i_t = l_t_srvr_list.begin();
            (i_t != l_t_srvr_list.end()) && (i_h != a_settings.m_host_list->end());
            ++i_t)
        {
                phurl_host_list_t l_host_list;
                for(size_t i_h_i = 0;
                    (i_h_i < l_num_per) && (i_h != a_settings.m_host_list->end());
                    ++i_h_i, ++i_h)
                {
                        //printf("%s.%s.%d: PUSHING: host: %s\n", __FILE__,__FUNCTION__,__LINE__,i_h->m_host.c_str());
                        l_host_list.push_back(*i_h);
                }
                ns_hlx::clnt_session *l_cs = new ns_hlx::clnt_session();
                ns_hlx::phurl_u *l_phr = new ns_hlx::phurl_u(*l_cs);
                l_phr->m_delete = false;
                l_phr->m_data = &a_settings;
                a_settings.m_phr_list.push_back(l_phr);
                int l_status;
                l_status = a_settings.m_broadcast_h->do_get_bc(a_settings.m_srvr,
                                                               *i_t,
                                                               l_host_list,
                                                               l_phr);
                if(HLX_STATUS_OK != l_status)
                {
                        return -1;
                }
        }
        a_settings.m_total_reqs = a_settings.m_host_list->size();
#endif

#if 0
        // run...
        int l_status;
        l_status = a_settings.m_srvr->run();
        if(HLX_STATUS_OK != l_status)
        {
                return -1;
        }
#endif

        //printf("Adding subr\n\n");

        g_test_finished = false;
        // ---------------------------------------
        //   Loop forever until user quits
        // ---------------------------------------
        while (!g_test_finished)
        {
                i = kbhit();
                if (i != 0)
                {
                        l_cmd = fgetc(stdin);

                        switch (l_cmd)
                        {
                        // -------------------------------------------
                        // Quit
                        // -only works when not reading from stdin
                        // -------------------------------------------
                        case 'q':
                        {
                                g_test_finished = true;
#if 0
                                a_settings.m_srvr->stop();
#endif
                                //l_sent_stop = true;
                                break;
                        }
                        // -------------------------------------------
                        // Default
                        // -------------------------------------------
                        default:
                        {
                                break;
                        }
                        }
                }

                // TODO add define...
                usleep(500000);

#if 0
                if(a_settings.m_show_stats)
                {
                        display_status_line(a_settings);
                }
#endif

                if(!g_test_finished)
                {
                        g_test_finished = true;
#if 0
                        pthread_mutex_lock(&(a_settings.m_mutex));
                        for(phurl_h_resp_list_t::iterator i_p = a_settings.m_phr_list.begin();
                            i_p != a_settings.m_phr_list.end();
                            ++i_p)
                        {
                                if(!(*i_p)) { continue; }
                                //printf("%s.%s.%d: left: %lu\n", __FILE__,__FUNCTION__,__LINE__, (*i_p)->m_pending_subr_uid_map.size());
                                if((*i_p)->m_pending_subr_uid_map.size())
                                {
                                        g_test_finished = false;
                                        break;
                                }
                        }
                        pthread_mutex_unlock(&(a_settings.m_mutex));
#endif
                }
                //if (!a_settings.m_srvr->is_running())
                //{
                //        //printf("IS NOT RUNNING.\n");
                //        g_test_finished = true;
                //}
        }
        //printf("%s.%s.%d: STOP\n", __FILE__,__FUNCTION__,__LINE__);
#if 0
        a_settings.m_srvr->stop();
        a_settings.m_srvr->wait_till_stopped();
        // One more status for the lovers
        if(a_settings.m_show_stats)
        {
                display_status_line(a_settings);
        }
#endif
        nonblock(NB_DISABLE);
        return 0;
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t add_line(FILE *a_file_ptr, phurl_host_list_t &a_host_list)
{
        char l_readline[MAX_READLINE_SIZE];
        while(fgets(l_readline, sizeof(l_readline), a_file_ptr))
        {
                size_t l_readline_len = strnlen(l_readline, MAX_READLINE_SIZE);
                if(MAX_READLINE_SIZE == l_readline_len)
                {
                        // line was truncated
                        // Bail out -reject lines longer than limit
                        // -host names ought not be too long
                        printf("Error: hostnames must be shorter than %d chars\n", MAX_READLINE_SIZE);
                        return HLX_STATUS_ERROR;
                }
                // read full line
                // Nuke endline
                l_readline[l_readline_len - 1] = '\0';
                std::string l_string(l_readline);
                l_string.erase( std::remove_if( l_string.begin(), l_string.end(), ::isspace ), l_string.end() );
                phurl_host_t l_host;
                l_host.m_host = l_string;
                if(!l_string.empty())
                        a_host_list.push_back(l_host);
                //printf("READLINE: %s\n", l_readline);
        }
        return HLX_STATUS_OK;
}

//: ----------------------------------------------------------------------------
//: \details: Print the version.
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
void print_version(FILE* a_stream, int a_exit_code)
{

        // print out the version information
        fprintf(a_stream, "phurl HTTP Parallel Curl.\n");
        fprintf(a_stream, "Copyright (C) 2016 Verizon Digital Media.\n");
        fprintf(a_stream, "               Version: %s\n", HLX_VERSION);
        exit(a_exit_code);
}

//: ----------------------------------------------------------------------------
//: \details: Print the command line help.
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
void print_usage(FILE* a_stream, int a_exit_code)
{
        fprintf(a_stream, "Usage: phurl -u [http[s]://]hostname[:port]/path [options]\n");
        fprintf(a_stream, "Options are:\n");
        fprintf(a_stream, "  -h, --help           Display this help and exit.\n");
        fprintf(a_stream, "  -V, --version        Display the version number and exit.\n");
        fprintf(a_stream, "  \n");
        fprintf(a_stream, "URL Options -or without parameter\n");
        fprintf(a_stream, "  -u, --url            URL -REQUIRED (unless running cli: see --cli option).\n");
        fprintf(a_stream, "  -d, --data           HTTP body data -supports curl style @ file specifier\n");
        fprintf(a_stream, "  \n");
        fprintf(a_stream, "Hostname Input Options -also STDIN:\n");
        fprintf(a_stream, "  -f, --host_file      Host name file.\n");
        fprintf(a_stream, "  -J, --host_json      Host listing json format.\n");
        fprintf(a_stream, "  -x, --execute        Script to execute to get host names.\n");
        fprintf(a_stream, "  \n");
        fprintf(a_stream, "Settings:\n");
        fprintf(a_stream, "  -p, --parallel       Num parallel.\n");
        fprintf(a_stream, "  -t, --threads        Number of parallel threads.\n");
        fprintf(a_stream, "  -H, --header         Request headers -can add multiple ie -H<> -H<>...\n");
        fprintf(a_stream, "  -X, --verb           Request command -HTTP verb to use -GET/PUT/etc\n");
        fprintf(a_stream, "  -T, --timeout        Timeout (seconds).\n");
        fprintf(a_stream, "  -n, --no_async_dns   Use getaddrinfo to resolve.\n");
        fprintf(a_stream, "  -k, --no_cache       Don't use addr info cache.\n");
        fprintf(a_stream, "  -A, --ai_cache       Path to Address Info Cache (DNS lookup cache).\n");
        fprintf(a_stream, "  -C, --connect_only   Only connect -do not send request.\n");
        fprintf(a_stream, "  -Q, --complete_time  Cancel requests after N seconds.\n");
        fprintf(a_stream, "  -W, --complete_ratio Cancel requests after %% complete (0.0-->100.0).\n");
        fprintf(a_stream, "  \n");
        fprintf(a_stream, "TLS Settings:\n");
        fprintf(a_stream, "  -y, --cipher         Cipher --see \"openssl ciphers\" for list.\n");
        fprintf(a_stream, "  -O, --tls_options    SSL Options string.\n");
        fprintf(a_stream, "  -K, --tls_verify     Verify server certificate.\n");
        fprintf(a_stream, "  -N, --tls_sni        Use SSL SNI.\n");
        fprintf(a_stream, "  -B, --tls_self_ok    Allow self-signed certificates.\n");
        fprintf(a_stream, "  -M, --tls_no_host    Skip host name checking.\n");
        fprintf(a_stream, "  -F, --tls_ca_file    SSL CA File.\n");
        fprintf(a_stream, "  -L, --tls_ca_path    SSL CA Path.\n");
        fprintf(a_stream, "  \n");
        fprintf(a_stream, "Print Options:\n");
        fprintf(a_stream, "  -v, --verbose        Verbose logging\n");
        fprintf(a_stream, "  -c, --no_color       Turn off colors\n");
        fprintf(a_stream, "  -q, --quiet          Suppress output\n");
        fprintf(a_stream, "  -s, --show_progress  Show progress\n");
        fprintf(a_stream, "  -m, --show_summary   Show summary output\n");
        fprintf(a_stream, "  \n");
        fprintf(a_stream, "Output Options: -defaults to line delimited\n");
        fprintf(a_stream, "  -o, --output         File to write output to. Defaults to stdout\n");
        fprintf(a_stream, "  -l, --line_delimited Output <HOST> <RESPONSE BODY> per line\n");
        fprintf(a_stream, "  -j, --json           JSON { <HOST>: \"body\": <RESPONSE> ...\n");
        fprintf(a_stream, "  -P, --pretty         Pretty output\n");
        fprintf(a_stream, "  \n");
#ifdef ENABLE_PROFILER
        fprintf(a_stream, "Debug Options:\n");
        fprintf(a_stream, "  -G, --gprofile       Google profiler output file\n");
#endif
        fprintf(a_stream, "  \n");
        fprintf(a_stream, "Note: If running large jobs consider enabling tcp_tw_reuse -eg:\n");
        fprintf(a_stream, "echo 1 > /proc/sys/net/ipv4/tcp_tw_reuse\n");
        fprintf(a_stream, "\n");
        exit(a_exit_code);
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int main(int argc, char** argv)
{
#if 0
        ns_hlx::srvr *l_srvr = new ns_hlx::srvr();

        // For sighandler
        settings_struct_t l_settings;
        l_settings.m_srvr = l_srvr;
        g_settings = &l_settings;
#endif

        // Suppress errors
        ns_hlx::trc_log_level_set(ns_hlx::TRC_LOG_LEVEL_NONE);

#if 0
        l_srvr->set_collect_stats(false);
        l_srvr->set_dns_use_ai_cache(true);
        l_srvr->set_update_stats_ms(500);
#endif

        if(isatty(fileno(stdout)))
        {
#if 0
                l_settings.m_color = true;
                l_srvr->set_rqst_resp_logging_color(true);
#endif
        }

        // -------------------------------------------------
        // Subrequest settings
        // -------------------------------------------------
#if 0
        broadcast_h *l_broadcast_h = new broadcast_h();
        l_settings.m_broadcast_h = l_broadcast_h;
#endif

        phurl_host_list_t *l_host_list = new phurl_host_list_t();
#if 0
        l_settings.m_host_list = l_host_list;
#endif

        ns_hlx::subr *l_subr = new ns_hlx::subr();
        l_subr->set_save(true);
        l_subr->set_detach_resp(true);

        // Setup default headers before the user
        l_subr->set_header("User-Agent", "Verizon Digital Media Parallel Curl phurl ");
#if 0
        l_subr->set_completion_cb(broadcast_h::s_completion_cb);
        l_subr->set_error_cb(broadcast_h::s_error_cb);
#endif
        //l_subr->set_keepalive(true);

        // -------------------------------------------
        // Get args...
        // -------------------------------------------
        char l_opt;
        std::string l_arg;
        int l_option_index = 0;
        struct option l_long_options[] =
                {
                { "help",           0, 0, 'h' },
                { "version",        0, 0, 'V' },
                { "url",            1, 0, 'u' },
                { "data",           1, 0, 'd' },
                { "host_file",      1, 0, 'f' },
                { "host_file_json", 1, 0, 'J' },
                { "execute",        1, 0, 'x' },
                { "parallel",       1, 0, 'p' },
                { "threads",        1, 0, 't' },
                { "header",         1, 0, 'H' },
                { "verb",           1, 0, 'X' },
                { "timeout",        1, 0, 'T' },
                { "no_async_dns",   1, 0, 'n' },
                { "no_cache",       0, 0, 'k' },
                { "ai_cache",       1, 0, 'A' },
                { "connect_only",   0, 0, 'C' },
                { "complete_time",  1, 0, 'Q' },
                { "complete_ratio", 1, 0, 'W' },
                { "cipher",         1, 0, 'y' },
                { "tls_options",    1, 0, 'O' },
                { "tls_verify",     0, 0, 'K' },
                { "tls_sni",        0, 0, 'N' },
                { "tls_self_ok",    0, 0, 'B' },
                { "tls_no_host",    0, 0, 'M' },
                { "tls_ca_file",    1, 0, 'F' },
                { "tls_ca_path",    1, 0, 'L' },
                { "verbose",        0, 0, 'v' },
                { "no_color",       0, 0, 'c' },
                { "quiet",          0, 0, 'q' },
                { "show_progress",  0, 0, 's' },
                { "show_summary",   0, 0, 'm' },
                { "output",         1, 0, 'o' },
                { "line_delimited", 0, 0, 'l' },
                { "json",           0, 0, 'j' },
                { "pretty",         0, 0, 'P' },
#ifdef ENABLE_PROFILER
                { "gprofile",       1, 0, 'G' },
#endif
                // list sentinel
                { 0, 0, 0, 0 }
        };
#ifdef ENABLE_PROFILER
        std::string l_gprof_file;
#endif
        std::string l_execute_line;
        std::string l_host_file_str;
        std::string l_host_file_json_str;
        std::string l_url;
        std::string l_ai_cache;
        std::string l_output_file = "";
        int l_max_threads = 1;
        int l_num_parallel = 1;

        // Defaults
        output_type_t l_output_mode = OUTPUT_JSON;
        int l_output_part = PART_HOST |
                            PART_SERVER |
                            PART_STATUS_CODE |
                            PART_HEADERS |
                            PART_BODY;
        bool l_output_pretty = false;


        // TODO REMOVE
        (void)l_output_pretty;
        (void)l_output_part;
        (void)l_output_mode;

        // -------------------------------------------
        // Assume unspecified arg url...
        // TODO Unsure if good way to allow unspecified
        // arg...
        // -------------------------------------------
        bool is_opt = false;
        for(int i_arg = 1; i_arg < argc; ++i_arg) {

                if(argv[i_arg][0] == '-') {
                        // next arg is for the option
                        is_opt = true;
                }
                else if(argv[i_arg][0] != '-' && is_opt == false) {
                        // Stuff in url field...
                        l_url = std::string(argv[i_arg]);
                        //if(l_settings.m_verbose)
                        //{
                        //      printf("Found unspecified argument: %s --assuming url...\n", l_url.c_str());
                        //}
                        break;
                } else {
                        // reset option flag
                        is_opt = false;
                }
        }

        // -------------------------------------------------
        // Args...
        // -------------------------------------------------
#ifdef ENABLE_PROFILER
        char l_short_arg_list[] = "hVvu:d:f:J:x:y:O:KNBMF:L:p:t:H:X:T:nkA:CQ:W:Rcqsmo:ljPG:";
#else
        char l_short_arg_list[] = "hVvu:d:f:J:x:y:O:KNBMF:L:p:t:H:X:T:nkA:CQ:W:Rcqsmo:ljP";
#endif
        while ((l_opt = getopt_long_only(argc, argv, l_short_arg_list, l_long_options, &l_option_index)) != -1 && ((unsigned char)l_opt != 255))
        {

                if (optarg)
                {
                        l_arg = std::string(optarg);
                }
                else
                {
                        l_arg.clear();
                }
                //printf("arg[%c=%d]: %s\n", l_opt, l_option_index, l_arg.c_str());

                switch (l_opt)
                {
                // ---------------------------------------
                // Help
                // ---------------------------------------
                case 'h':
                {
                        print_usage(stdout, 0);
                        break;
                }
                // ---------------------------------------
                // Version
                // ---------------------------------------
                case 'V':
                {
                        print_version(stdout, 0);
                        break;
                }
                // ---------------------------------------
                // URL
                // ---------------------------------------
                case 'u':
                {
                        l_url = l_arg;
                        break;
                }
                // ---------------------------------------
                // Data
                // ---------------------------------------
                case 'd':
                {
                        // TODO Size limits???
                        int32_t l_status;
                        // If a_data starts with @ assume file
                        if(l_arg[0] == '@')
                        {
                                char *l_buf;
                                uint32_t l_len;
                                l_status = read_file(l_arg.data() + 1, &(l_buf), &(l_len));
                                if(l_status != 0)
                                {
                                        printf("Error reading body data from file: %s\n", l_arg.c_str() + 1);
                                        return -1;
                                }
                                l_subr->set_body_data(l_buf, l_len);
                        }
                        else
                        {
                                char *l_buf;
                                uint32_t l_len;
                                l_len = l_arg.length() + 1;
                                l_buf = (char *)malloc(sizeof(char)*l_len);
                                l_subr->set_body_data(l_buf, l_len);
                        }

                        // Add content length
                        char l_len_str[64];
                        sprintf(l_len_str, "%u", l_subr->get_body_len());
                        l_subr->set_header("Content-Length", l_len_str);
                        break;
                }
                // ---------------------------------------
                // Host file
                // ---------------------------------------
                case 'f':
                {
                        l_host_file_str = l_arg;
                        break;
                }
                // ---------------------------------------
                // Host file JSON
                // ---------------------------------------
                case 'J':
                {
                        l_host_file_json_str = l_arg;
                        break;
                }
                // ---------------------------------------
                // Execute line
                // ---------------------------------------
                case 'x':
                {
                        l_execute_line = l_arg;
                        break;
                }
                // ---------------------------------------
                // cipher
                // ---------------------------------------
                case 'y':
                {
#if 0
                        l_srvr->set_tls_client_ctx_cipher_list(l_arg);
#endif
                        break;
                }
                // ---------------------------------------
                // tls options
                // ---------------------------------------
                case 'O':
                {
#if 0
                        int32_t l_status;
                        l_status = l_srvr->set_tls_client_ctx_options(l_arg);
                        if(l_status != HLX_STATUS_OK)
                        {
                                return HLX_STATUS_ERROR;
                        }
#endif
                        break;
                }
                // ---------------------------------------
                // tls verify
                // ---------------------------------------
                case 'K':
                {
                        l_subr->set_tls_verify(true);
                        break;
                }
                // ---------------------------------------
                // tls sni
                // ---------------------------------------
                case 'N':
                {
                        l_subr->set_tls_sni(true);
                        break;
                }
                // ---------------------------------------
                // tls self signed
                // ---------------------------------------
                case 'B':
                {
                        l_subr->set_tls_self_ok(true);
                        break;
                }
                // ---------------------------------------
                // tls skip host check
                // ---------------------------------------
                case 'M':
                {
                        l_subr->set_tls_no_host_check(true);
                        break;
                }
                // ---------------------------------------
                // tls ca file
                // ---------------------------------------
                case 'F':
                {
#if 0
                        l_srvr->set_tls_client_ctx_ca_file(l_arg);
#endif
                        break;
                }
                // ---------------------------------------
                // tls ca path
                // ---------------------------------------
                case 'L':
                {
#if 0
                        l_srvr->set_tls_client_ctx_ca_path(l_arg);
#endif
                        break;
                }
                // ---------------------------------------
                // parallel
                // ---------------------------------------
                case 'p':
                {
                        //printf("arg: --parallel: %s\n", optarg);
                        //l_settings.m_start_type = START_PARALLEL;
                        l_num_parallel = atoi(optarg);
                        if (l_num_parallel < 1)
                        {
                                printf("Error parallel must be at least 1\n");
                                return -1;
                        }
#if 0
                        l_srvr->set_num_parallel(l_num_parallel);
#endif
                        break;
                }
                // ---------------------------------------
                // num threads
                // ---------------------------------------
                case 't':
                {
                        //printf("arg: --threads: %s\n", l_arg.c_str());
                        l_max_threads = atoi(optarg);
                        if (l_max_threads < 0)
                        {
                                printf("Error num-threads must be 0 or greater\n");
                                return -1;
                        }
#if 0
                        l_srvr->set_num_threads(l_max_threads);
#endif
                        break;
                }
                // ---------------------------------------
                // Header
                // ---------------------------------------
                case 'H':
                {
                        int32_t l_status;
                        std::string l_key;
                        std::string l_val;
                        l_status = ns_hlx::break_header_string(l_arg, l_key, l_val);
                        if (l_status != 0)
                        {
                                printf("Error breaking header string: %s -not in <HEADER>:<VAL> format?\n", l_arg.c_str());
                                return -1;
                        }
                        l_status = l_subr->set_header(l_key, l_val);
                        if (l_status != 0)
                        {
                                printf("Error performing set_header: %s\n", l_arg.c_str());
                                return -1;
                        }
                        break;
                }
                // ---------------------------------------
                // Verb
                // ---------------------------------------
                case 'X':
                {
                        if(l_arg.length() > 64)
                        {
                                printf("Error verb string: %s too large try < 64 chars\n", l_arg.c_str());
                                return -1;
                        }
                        l_subr->set_verb(l_arg);
                        break;
                }
                // ---------------------------------------
                // Timeout
                // ---------------------------------------
                case 'T':
                {
                        int l_timeout_s = -1;
                        //printf("arg: --threads: %s\n", l_arg.c_str());
                        l_timeout_s = atoi(optarg);
                        if (l_timeout_s < 1)
                        {
                                printf("Error connection timeout must be > 0\n");
                                return -1;
                        }
                        l_subr->set_timeout_ms(l_timeout_s*1000);
                        break;
                }
                // ---------------------------------------
                // No async dns
                // ---------------------------------------
                case 'n':
                {
#if 0
                        l_srvr->set_dns_use_sync(true);
#endif
                        break;
                }
                // ---------------------------------------
                // I'm poor -I aint got no cache!
                // ---------------------------------------
                case 'k':
                {
#if 0
                        l_srvr->set_dns_use_ai_cache(false);
#endif
                        break;
                }
                // ---------------------------------------
                // Address Info cache
                // ---------------------------------------
                case 'A':
                {
#if 0
                        l_srvr->set_dns_ai_cache_file(l_arg);
#endif
                        break;
                }
                // ---------------------------------------
                // connect only
                // ---------------------------------------
                case 'C':
                {
                        l_subr->set_connect_only(true);
                        break;
                }
                // ---------------------------------------
                // completion time
                // ---------------------------------------
                case 'Q':
                {
                        // Set complete time in ms seconds
#if 0
                        int l_completion_time_s = atoi(optarg);
                        // TODO Check value...
                        l_settings.m_timeout_ms = l_completion_time_s*1000;
#endif
                        break;
                }
                // ---------------------------------------
                // completion ratio
                // ---------------------------------------
                case 'W':
                {
                        double l_ratio = atof(optarg);
                        if((l_ratio < 0.0) || (l_ratio > 100.0))
                        {
                                printf("Error: completion ratio must be > 0.0 and < 100.0\n");
                                return -1;
                        }
#if 0
                        l_settings.m_completion_ratio = (float)l_ratio;
#endif
                        break;
                }
                // ---------------------------------------
                // verbose
                // ---------------------------------------
                case 'v':
                {
#if 0
                        l_settings.m_verbose = true;
                        l_srvr->set_rqst_resp_logging(true);
#endif
                        break;
                }
                // ---------------------------------------
                // color
                // ---------------------------------------
                case 'c':
                {
#if 0
                        l_settings.m_color = false;
                        l_srvr->set_rqst_resp_logging_color(false);
#endif
                        break;
                }
                // ---------------------------------------
                // quiet
                // ---------------------------------------
                case 'q':
                {
#if 0
                        l_settings.m_quiet = true;
#endif
                        break;
                }
                // ---------------------------------------
                // show progress
                // ---------------------------------------
                case 's':
                {
#if 0
                        l_settings.m_show_stats = true;
#endif
                        break;
                }
                // ---------------------------------------
                // show progress
                // ---------------------------------------
                case 'm':
                {
#if 0
                        l_settings.m_show_summary = true;
#endif
                        break;
                }
                // ---------------------------------------
                // output file
                // ---------------------------------------
                case 'o':
                {
                        l_output_file = l_arg;
                        break;
                }
                // ---------------------------------------
                // line delimited
                // ---------------------------------------
                case 'l':
                {
                        l_output_mode = OUTPUT_LINE_DELIMITED;
                        break;
                }
                // ---------------------------------------
                // json output
                // ---------------------------------------
                case 'j':
                {
                        l_output_mode = OUTPUT_JSON;
                        break;
                }
                // ---------------------------------------
                // pretty output
                // ---------------------------------------
                case 'P':
                {
                        l_output_pretty = true;
                        break;
                }
#ifdef ENABLE_PROFILER
                // ---------------------------------------
                // Google Profiler Output File
                // ---------------------------------------
                case 'G':
                {
                        l_gprof_file = l_arg;
                        break;
                }
#endif
                // What???
                case '?':
                {
                        // Required argument was missing
                        // '?' is provided when the 3rd arg to getopt_long does not begin with a ':', and is preceeded
                        // by an automatic error message.
                        fprintf(stdout, "  Exiting.\n");
                        print_usage(stdout, -1);
                        break;
                }
                // Huh???
                default:
                {
                        fprintf(stdout, "Unrecognized option.\n");
                        print_usage(stdout, -1);
                        break;
                }
                }
        }

        // Check for required url argument
        if(l_url.empty())
        {
                fprintf(stdout, "No URL specified.\n");
                print_usage(stdout, -1);
        }
        // else set url
        if(!l_url.empty())
        {
                l_subr->init_with_url(l_url);
        }

        // -------------------------------------------------
        // Get resource limits
        // -------------------------------------------------
        int32_t l_s;
        struct rlimit l_rlim;
        errno = 0;
        l_s = getrlimit(RLIMIT_NOFILE, &l_rlim);
        if(l_s != 0)
        {
                fprintf(stdout, "Error performing getrlimit. Reason: %s\n", strerror(errno));
                return HLX_STATUS_ERROR;
        }
        if(l_rlim.rlim_cur < (uint64_t)(l_max_threads*l_num_parallel))
        {
                fprintf(stdout, "Error threads[%d]*parallelism[%d] > process fd resource limit[%u]\n",
                                l_max_threads, l_num_parallel, (uint32_t)l_rlim.rlim_cur);
                return HLX_STATUS_ERROR;
        }

        // -------------------------------------------------
        // Host list processing
        // -------------------------------------------------
        // Read from command
        if(!l_execute_line.empty())
        {
                FILE *fp;
                int32_t l_status = HLX_STATUS_OK;

                fp = popen(l_execute_line.c_str(), "r");
                // Error executing...
                if (fp == NULL)
                {
                }

                l_status = add_line(fp, *l_host_list);
                if(HLX_STATUS_OK != l_status)
                {
                        return HLX_STATUS_ERROR;
                }

                l_status = pclose(fp);
                // Error reported by pclose()
                if (l_status == -1)
                {
                        printf("Error: performing pclose\n");
                        return HLX_STATUS_ERROR;
                }
                // Use macros described under wait() to inspect `status' in order
                // to determine success/failure of command executed by popen()
                else
                {
                }
        }
        // Read from file
        else if(!l_host_file_str.empty())
        {
                FILE * l_file;
                int32_t l_status = HLX_STATUS_OK;

                l_file = fopen(l_host_file_str.c_str(),"r");
                if (NULL == l_file)
                {
                        printf("Error opening file: %s.  Reason: %s\n", l_host_file_str.c_str(), strerror(errno));
                        return HLX_STATUS_ERROR;
                }

                l_status = add_line(l_file, *l_host_list);
                if(HLX_STATUS_OK != l_status)
                {
                        return HLX_STATUS_ERROR;
                }

                //printf("ADD_FILE: DONE: %s\n", a_url_file.c_str());

                l_status = fclose(l_file);
                if (0 != l_status)
                {
                        printf("Error performing fclose.  Reason: %s\n", strerror(errno));
                        return HLX_STATUS_ERROR;
                }
        }
        else if(!l_host_file_json_str.empty())
        {
                // TODO Create a function to do all this mess
                // ---------------------------------------
                // Check is a file
                // TODO
                // ---------------------------------------
                struct stat l_stat;
                int32_t l_status = HLX_STATUS_OK;
                l_status = stat(l_host_file_json_str.c_str(), &l_stat);
                if(l_status != 0)
                {
                        printf("Error performing stat on file: %s.  Reason: %s\n", l_host_file_json_str.c_str(), strerror(errno));
                        return HLX_STATUS_ERROR;
                }

                // Check if is regular file
                if(!(l_stat.st_mode & S_IFREG))
                {
                        printf("Error opening file: %s.  Reason: is NOT a regular file\n", l_host_file_json_str.c_str());
                        return HLX_STATUS_ERROR;
                }

                // ---------------------------------------
                // Open file...
                // ---------------------------------------
                FILE * l_file;
                l_file = fopen(l_host_file_json_str.c_str(),"r");
                if (NULL == l_file)
                {
                        printf("Error opening file: %s.  Reason: %s\n", l_host_file_json_str.c_str(), strerror(errno));
                        return HLX_STATUS_ERROR;
                }

                // ---------------------------------------
                // Read in file...
                // ---------------------------------------
                int32_t l_size = l_stat.st_size;
                int32_t l_read_size;
                char *l_buf = (char *)malloc(sizeof(char)*l_size);
                l_read_size = fread(l_buf, 1, l_size, l_file);
                if(l_read_size != l_size)
                {
                        printf("Error performing fread.  Reason: %s [%d:%d]\n",
                                        strerror(errno), l_read_size, l_size);
                        return HLX_STATUS_ERROR;
                }
                std::string l_buf_str;
                l_buf_str.assign(l_buf, l_size);
                if(l_buf)
                {
                        free(l_buf);
                        l_buf = NULL;
                }


                // NOTE: rapidjson assert's on errors -interestingly
                rapidjson::Document l_doc;
                l_doc.Parse(l_buf_str.c_str());
                if(!l_doc.IsArray())
                {
                        printf("Error reading json from file: %s.  Reason: data is not an array\n",
                                        l_host_file_json_str.c_str());
                        return HLX_STATUS_ERROR;
                }

                // rapidjson uses SizeType instead of size_t.
                for(rapidjson::SizeType i_record = 0; i_record < l_doc.Size(); ++i_record)
                {
                        if(!l_doc[i_record].IsObject())
                        {
                                printf("Error reading json from file: %s.  Reason: array member not an object\n",
                                                l_host_file_json_str.c_str());
                                return HLX_STATUS_ERROR;
                        }
                        phurl_host_t l_host;
                        // "host" : "coolhost.com:443",
                        // "hostname" : "coolhost.com",
                        // "id" : "DE4D",
                        // "where" : "my_house"
                        if(l_doc[i_record].HasMember("host")) l_host.m_host = l_doc[i_record]["host"].GetString();
                        //else l_host.m_host = "NO_HOST";
                        if(l_doc[i_record].HasMember("hostname")) l_host.m_hostname = l_doc[i_record]["hostname"].GetString();
                        //else l_host.m_hostname = "NO_HOSTNAME";
                        if(l_doc[i_record].HasMember("id")) l_host.m_id = l_doc[i_record]["id"].GetString();
                        //else l_host.m_id = "NO_ID";
                        if(l_doc[i_record].HasMember("where")) l_host.m_where = l_doc[i_record]["where"].GetString();
                        //else l_host.m_where = "NO_WHERE";
                        if(l_doc[i_record].HasMember("port")) l_host.m_port = l_doc[i_record]["port"].GetUint();
                        else l_host.m_port = 80;
                        l_host_list->push_back(l_host);
                }

                // ---------------------------------------
                // Close file...
                // ---------------------------------------
                l_status = fclose(l_file);
                if (HLX_STATUS_OK != l_status)
                {
                        printf("Error performing fclose.  Reason: %s\n", strerror(errno));
                        return HLX_STATUS_ERROR;
                }
        }
        // Read from stdin
        else
        {
                int32_t l_status = HLX_STATUS_OK;
                l_status = add_line(stdin, *l_host_list);
                if(HLX_STATUS_OK != l_status)
                {
                        return HLX_STATUS_ERROR;
                }
        }

#if 0
        if(l_settings.m_verbose)
        {
                printf("Showing hostname list:\n");
                for(phurl_host_list_t::iterator i_host = l_host_list->begin(); i_host != l_host_list->end(); ++i_host)
                {
                        printf("%s\n", i_host->m_host.c_str());
                }
        }
#endif

        // -------------------------------------------
        // Sigint handler
        // -------------------------------------------
        if (signal(SIGINT, sig_handler) == SIG_ERR)
        {
                printf("Error: can't catch SIGINT\n");
                return -1;
        }

        // -------------------------------------------
        // create subrequests
        // -------------------------------------------
        ns_hlx::subr_list_t l_subr_list;
        for(phurl_host_list_t::iterator i_host = l_host_list->begin();
            i_host != l_host_list->end();
            ++i_host)
        {
                ns_hlx::subr *i_subr = new ns_hlx::subr(*l_subr);
                i_subr->set_uid(get_next_subr_uuid());
                i_subr->set_host(i_host->m_host);
                if(!i_host->m_hostname.empty())
                {
                        i_subr->set_hostname(i_host->m_hostname);
                }
                if(!i_host->m_id.empty())
                {
                        i_subr->set_id(i_host->m_id);
                }
                if(!i_host->m_where.empty())
                {
                        i_subr->set_where(i_host->m_where);
                }
                if(i_host->m_port != 0)
                {
                        i_subr->set_port(i_host->m_port);
                }
                i_subr->reset_label();
#if 0
                l_subr->set_data(a_phr);

                // Add to pending map
                a_phr->m_pending_subr_uid_map[l_subr->get_uid()] = l_subr;

                int32_t l_status = 0;
                l_status = add_subr_t_srvr(a_t_srvr, *l_subr);
                if(l_status != HLX_STATUS_OK)
                {
                        //("Error: performing add_subreq.\n");
                        return HLX_STATUS_ERROR;
                }
#endif
                l_subr_list.push_back(i_subr);
        }

        // -------------------------------------------
        // resolve
        // -------------------------------------------
        printf("Resolving %lu addresses\n", l_host_list->size());
        ns_hlx::nresolver l_resolver;

#if 0
        // Init resolver with cache
        int32_t l_s;
        l_s = m_nresolver->init(m_dns_use_ai_cache, m_dns_ai_cache_file);
        if(HLX_STATUS_OK != l_s)
        {
                NDBG_PRINT("Error performing resolver init with ai_cache: %s\n",
                           m_dns_ai_cache_file.c_str());
                return HLX_STATUS_ERROR;
        }
#endif

        uint64_t l_num = 0;
        uint64_t l_len = l_subr_list.size();
        for(ns_hlx::subr_list_t::iterator i_s = l_subr_list.begin();
            i_s != l_subr_list.end() && !g_test_finished;
            ++i_s)
        {
                ++l_num;
                printf("Resolving: %12lu / %12lu\n", l_num, l_len);
                // Try fast
                ns_hlx::host_info l_host_info;
                l_s = l_resolver.lookup_tryfast((*i_s)->get_host(),
                                                (*i_s)->get_port(),
                                                 l_host_info);
                if(l_s != HLX_STATUS_OK)
                {

#if 0
#ifndef ASYNC_DNS_SUPPORT
#define ASYNC_DNS_SUPPORT 1
#endif
#ifdef ASYNC_DNS_SUPPORT
                        if(!m_t_conf->m_srvr->get_dns_use_sync())
                        {
                                // TODO check !NULL
                                // If try fast fails lookup async
                                if(!m_adns_ctx)
                                {
                                        m_adns_ctx = l_nresolver->get_new_adns_ctx(m_evr_loop, adns_resolved_cb);
                                        if(!m_adns_ctx)
                                        {
                                                TRC_ERROR("performing get_new_adns_ctx\n");
                                                return HLX_STATUS_ERROR;
                                        }
                                }
                                //m_stat.m_subr_pending_resolv_map[a_subr.get_label()] = &a_subr;
                                ++(m_stat.m_dns_resolve_req);
                                //NDBG_PRINT("%sl_subr label%s: %s --HOST: %s\n", ANSI_COLOR_BG_RED, ANSI_COLOR_OFF, a_subr.get_label().c_str(), a_subr.get_host().c_str());
                                void *l_job_handle = NULL;
                                l_status = l_nresolver->lookup_async(m_adns_ctx,
                                                                     a_subr.get_host(),
                                                                     a_subr.get_port(),
                                                                     &a_subr,
                                                                     &l_job_handle);
                                if(l_status != HLX_STATUS_OK)
                                {
                                        return HLX_STATUS_ERROR;
                                }
                                if(l_job_handle)
                                {
                                        a_subr.set_lookup_job(l_job_handle);
                                }
                                return STATUS_QUEUED_ASYNC_DNS;
                        }
                        else
                        {
#endif
#endif
                        // sync dns
                        l_s = l_resolver.lookup_sync((*i_s)->get_host(), (*i_s)->get_port(), l_host_info);
                        if(l_s != HLX_STATUS_OK)
                        {
                                //NDBG_PRINT("Error: performing lookup_sync\n");
                                //++m_stat.m_upsv_errors;
                                //subr::error_cb_t l_error_cb = a_subr.get_error_cb();
                                //if(l_error_cb)
                                //{
                                //        l_error_cb(a_subr, NULL, HTTP_STATUS_BAD_GATEWAY, "address lookup failure");
                                //        // TODO check status
                                //}
                                //return HLX_STATUS_ERROR;
                        }
                        else
                        {
                                //++(m_stat.m_dns_resolved);
                        }
#if 0
#ifdef ASYNC_DNS_SUPPORT
                        }
#endif
#endif
                }
        }
        printf("Done Resolving %lu addresses\n", l_host_list->size());

        // -------------------------------------------
        // Init
        // -------------------------------------------
#if 0
        for(uint32_t i_t = 0; i_t < g_num_threads; ++i_t)
        {
                // Calculate num to request
                int32_t l_num_to_request = -1;
                if(g_num_to_request > 0)
                {
                        // first thread gets remainder
                        l_num_to_request = g_num_to_request / g_num_threads;
                        if(i_t == 0)
                        {
                                l_num_to_request += g_num_to_request % g_num_threads;
                        }
                }
                t_hurl *l_t_hurl = new t_hurl(*l_subr, g_num_parallel, l_num_to_request);
                g_t_hurl_list.push_back(l_t_hurl);
                l_t_hurl->init();
                // TODO Check status
        }
#endif

        // -------------------------------------------
        // Run
        // -------------------------------------------
        //g_start_time_ms = ns_hlx::get_time_ms();;
        for(t_phurl_list_t::iterator i_t = g_t_phurl_list.begin();
            i_t != g_t_phurl_list.end();
            ++i_t)
        {
                (*i_t)->run();
                // TODO Check status
        }

        // -------------------------------------------
        // Setup to run -but don't start
        // -------------------------------------------
#if 0
        int32_t l_status = 0;
        l_status = l_srvr->init_run();
        if(HLX_STATUS_OK != l_status)
        {
                printf("Error: performing hlx::init_run\n");
                return -1;
        }
#endif

#ifdef ENABLE_PROFILER
        // Start Profiler
        if (!l_gprof_file.empty())
        {
                ProfilerStart(l_gprof_file.c_str());
        }
#endif
        // -------------------------------------------
        // Run command exec
        // -------------------------------------------
        command_exec();
        // TODO Check status...

#ifdef ENABLE_PROFILER
        if (!l_gprof_file.empty())
        {
                ProfilerStop();
        }
#endif

        //uint64_t l_end_time_ms = get_time_ms() - l_start_time_ms;

        // -------------------------------------------
        // Results...
        // -------------------------------------------
#if 0
        if(!g_cancelled && !l_settings.m_quiet)
        {
                bool l_use_color = l_settings.m_color;
                if(!l_output_file.empty()) l_use_color = false;
                // TODO REMOVE...
                UNUSED(l_use_color);
                std::string l_responses_str;
                l_responses_str = dump_all_responses(l_settings,
                                                     l_settings.m_phr_list,
                                                     l_use_color, l_output_pretty,
                                                     l_output_mode, l_output_part);
                if(l_output_file.empty())
                {
                        printf("%s\n", l_responses_str.c_str());
                }
                else
                {
                        int32_t l_num_bytes_written = 0;
                        int32_t l_status = 0;
                        // Open
                        FILE *l_file_ptr = fopen(l_output_file.c_str(), "w+");
                        if(l_file_ptr == NULL)
                        {
                                printf("Error performing fopen. Reason: %s\n", strerror(errno));
                                return HLX_STATUS_ERROR;
                        }

                        // Write
                        l_num_bytes_written = fwrite(l_responses_str.c_str(), 1, l_responses_str.length(), l_file_ptr);
                        if(l_num_bytes_written != (int32_t)l_responses_str.length())
                        {
                                printf("Error performing fwrite. Reason: %s\n", strerror(errno));
                                fclose(l_file_ptr);
                                return HLX_STATUS_ERROR;
                        }

                        // Close
                        l_status = fclose(l_file_ptr);
                        if(l_status != 0)
                        {
                                printf("Error performing fclose. Reason: %s\n", strerror(errno));
                                return HLX_STATUS_ERROR;
                        }
                }
        }
#endif

        // -------------------------------------------
        // Summary...
        // -------------------------------------------
#if 0
        if(l_settings.m_show_summary)
        {
                display_summary(l_settings, l_host_list->size());
        }
#endif

        // -------------------------------------------
        // Cleanup...
        // -------------------------------------------
        if(l_host_list)
        {
                delete l_host_list;
                l_host_list = NULL;
        }

#if 0
        if(l_broadcast_h)
        {
                delete l_broadcast_h;
                l_broadcast_h = NULL;
        }
#endif

        // TODO Fix deallocation
#if 0
        for(phurl_h_resp_list_t::iterator i_hr = l_settings.m_phr_list.begin();
            i_hr != l_settings.m_phr_list.end();
            ++i_hr)
        {
                if(*i_hr)
                {
                        delete *i_hr;
                        *i_hr = NULL;
                }
        }
#endif

#if 0
        if(l_srvr)
        {
                delete l_srvr;
                l_srvr = NULL;
        }
#endif

        return 0;
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
void display_summary(void)
{
        std::string l_header_str = "";
        std::string l_protocol_str = "";
        std::string l_cipher_str = "";
        std::string l_off_color = "";

#if 0
        if(a_settings.m_color)
        {
                l_header_str = ANSI_COLOR_FG_CYAN;
                l_protocol_str = ANSI_COLOR_FG_GREEN;
                l_cipher_str = ANSI_COLOR_FG_YELLOW;
                l_off_color = ANSI_COLOR_OFF;
        }

        summary_info_t &l_summary_info = a_settings.m_summary_info;
        printf("****************** %sSUMMARY%s ****************** \n", l_header_str.c_str(), l_off_color.c_str());
        printf("| total hosts:                     %u\n",a_num_hosts);
        printf("| success:                         %u\n",l_summary_info.m_success);
        printf("| cancelled:                       %u\n",l_summary_info.m_cancelled);
        printf("| error address lookup:            %u\n",l_summary_info.m_error_addr);
        printf("| error address timeout:           %u\n",l_summary_info.m_error_addr_timeout);
        printf("| error connectivity:              %u\n",l_summary_info.m_error_conn);
        printf("| error unknown:                   %u\n",l_summary_info.m_error_unknown);
        printf("| tls error cert hostname          %u\n",l_summary_info.m_tls_error_hostname);
        printf("| tls error cert self-signed       %u\n",l_summary_info.m_tls_error_self_signed);
        printf("| tls error cert expired           %u\n",l_summary_info.m_tls_error_expired);
        printf("| tls error cert issuer            %u\n",l_summary_info.m_tls_error_issuer);
        printf("| tls error other                  %u\n",l_summary_info.m_tls_error_other);

        // Sort
        typedef std::map<uint32_t, std::string> _sorted_map_t;
        _sorted_map_t l_sorted_map;
        printf("+--------------- %sSSL PROTOCOLS%s -------------- \n", l_protocol_str.c_str(), l_off_color.c_str());
        l_sorted_map.clear();
        for(summary_map_t::iterator i_s = l_summary_info.m_tls_protocols.begin(); i_s != l_summary_info.m_tls_protocols.end(); ++i_s)
        l_sorted_map[i_s->second] = i_s->first;
        for(_sorted_map_t::reverse_iterator i_s = l_sorted_map.rbegin(); i_s != l_sorted_map.rend(); ++i_s)
        printf("| %-32s %u\n", i_s->second.c_str(), i_s->first);
        printf("+--------------- %sSSL CIPHERS%s ---------------- \n", l_cipher_str.c_str(), l_off_color.c_str());
        l_sorted_map.clear();
        for(summary_map_t::iterator i_s = l_summary_info.m_tls_ciphers.begin(); i_s != l_summary_info.m_tls_ciphers.end(); ++i_s)
        l_sorted_map[i_s->second] = i_s->first;
        for(_sorted_map_t::reverse_iterator i_s = l_sorted_map.rbegin(); i_s != l_sorted_map.rend(); ++i_s)
        printf("| %-32s %u\n", i_s->second.c_str(), i_s->first);
#endif
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
void display_status_line(void)
{
#if 0
        // -------------------------------------------------
        // Get results from clients
        // -------------------------------------------------
        // Get stats
        ns_hlx::t_stat_cntr_t l_total;
        ns_hlx::t_stat_calc_t l_total_calc;
        ns_hlx::t_stat_cntr_list_t l_thread;
        a_settings.m_srvr->get_stat(l_total, l_total_calc, l_thread);

        uint32_t l_num_done = l_total.m_upsv_reqs;
        uint32_t l_num_resolve_active = l_total.m_dns_resolve_active;
        uint32_t l_num_resolve_req = l_total.m_dns_resolve_req;
        uint32_t l_num_resolved = l_total.m_dns_resolved;
        uint32_t l_num_get = l_total.m_upsv_conn_started;
        uint32_t l_num_rx = a_settings.m_total_reqs;
        uint32_t l_num_error = l_total.m_upsv_errors;
        if(a_settings.m_color)
        {
                printf("Done: %s%8u%s Reqd: %s%8u%s Rslvd: %s%8u%s Rslv_Actv: %s%8u%s Rslv_Req %s%8u%s Total: %s%8u%s Error: %s%8u%s\n",
                                ANSI_COLOR_FG_GREEN, l_num_done, ANSI_COLOR_OFF,
                                ANSI_COLOR_FG_YELLOW, l_num_get, ANSI_COLOR_OFF,
                                ANSI_COLOR_FG_MAGENTA, l_num_resolved, ANSI_COLOR_OFF,
                                ANSI_COLOR_FG_WHITE, l_num_resolve_active, ANSI_COLOR_OFF,
                                ANSI_COLOR_FG_CYAN, l_num_resolve_req, ANSI_COLOR_OFF,
                                ANSI_COLOR_FG_BLUE, l_num_rx, ANSI_COLOR_OFF,
                                ANSI_COLOR_FG_RED, l_num_error, ANSI_COLOR_OFF);
        }
        else
        {
                printf("Done: %8u Reqd: %8u Rslvd: %8u Rslv_Actv: %8u Rslv_Req %8u Total: %8u Error: %8u\n",
                                l_num_done, l_num_get, l_num_resolved, l_num_resolve_active, l_num_resolve_req, l_num_rx, l_num_error);
        }
#endif
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t read_file(const char *a_file, char **a_buf, uint32_t *a_len)
{
        // Check is a file
        struct stat l_stat;
        int32_t l_status = HLX_STATUS_OK;
        l_status = stat(a_file, &l_stat);
        if(l_status != 0)
        {
                printf("Error performing stat on file: %s.  Reason: %s\n", a_file, strerror(errno));
                return -1;
        }

        // Check if is regular file
        if(!(l_stat.st_mode & S_IFREG))
        {
                printf("Error opening file: %s.  Reason: is NOT a regular file\n", a_file);
                return -1;
        }

        // Open file...
        FILE * l_file;
        l_file = fopen(a_file,"r");
        if (NULL == l_file)
        {
                printf("Error opening file: %s.  Reason: %s\n", a_file, strerror(errno));
                return -1;
        }

        // Read in file...
        int32_t l_size = l_stat.st_size;
        *a_buf = (char *)malloc(sizeof(char)*l_size);
        *a_len = l_size;
        int32_t l_read_size;
        l_read_size = fread(*a_buf, 1, l_size, l_file);
        if(l_read_size != l_size)
        {
                printf("Error performing fread.  Reason: %s [%d:%d]\n",
                                strerror(errno), l_read_size, l_size);
                return -1;
        }

        // Close file...
        l_status = fclose(l_file);
        if (HLX_STATUS_OK != l_status)
        {
                printf("Error performing fclose.  Reason: %s\n", strerror(errno));
                return -1;
        }
        return 0;
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
std::string dump_all_responses_line_dl(void)
{
        std::string l_responses_str = "";
#if 0
        std::string l_host_color = "";
        std::string l_server_color = "";
        std::string l_id_color = "";
        std::string l_status_color = "";
        std::string l_header_color = "";
        std::string l_body_color = "";
        std::string l_off_color = "";
        char l_buf[1024*1024];
        if(a_color)
        {
                l_host_color = ANSI_COLOR_FG_BLUE;
                l_server_color = ANSI_COLOR_FG_RED;
                l_id_color = ANSI_COLOR_FG_CYAN;
                l_status_color = ANSI_COLOR_FG_MAGENTA;
                l_header_color = ANSI_COLOR_FG_GREEN;
                l_body_color = ANSI_COLOR_FG_YELLOW;
                l_off_color = ANSI_COLOR_OFF;
        }

        for(phurl_h_resp_list_t::const_iterator i_hr = a_resp_list.begin();
            i_hr != a_resp_list.end();
            ++i_hr)
        {
                for(ns_hlx::hlx_resp_list_t::const_iterator i_rx = (*i_hr)->m_resp_list.begin();
                    i_rx != (*i_hr)->m_resp_list.end();
                    ++i_rx)
                {
                        ns_hlx::subr *l_subr = (*i_rx)->m_subr;
                        ns_hlx::resp *l_resp = (*i_rx)->m_resp;
                        if(!l_subr)
                        {
                                continue;
                        }

                        bool l_fbf = false;
                        // Host
                        if(a_part_map & PART_HOST)
                        {
                                sprintf(l_buf, "\"%shost%s\": \"%s\"",
                                                l_host_color.c_str(), l_off_color.c_str(),
                                                l_subr->get_host().c_str());
                                ARESP(l_buf);
                                l_fbf = true;
                        }

                        // Server
                        if(a_part_map & PART_SERVER)
                        {

                                if(l_fbf) {ARESP(", "); l_fbf = false;}
                                sprintf(l_buf, "\"%sserver%s\": \"%s:%d\"",
                                                l_server_color.c_str(), l_server_color.c_str(),
                                                l_subr->get_host().c_str(),
                                                l_subr->get_port()
                                                );
                                ARESP(l_buf);
                                l_fbf = true;

                                if(!l_subr->get_id().empty())
                                {
                                        if(l_fbf) {ARESP(", "); l_fbf = false;}
                                        sprintf(l_buf, "\"%sid%s\": \"%s\"",
                                                        l_id_color.c_str(), l_id_color.c_str(),
                                                        l_subr->get_id().c_str()
                                                        );
                                        ARESP(l_buf);
                                        l_fbf = true;
                                }

                                if(!l_subr->get_where().empty())
                                {
                                        if(l_fbf) {ARESP(", "); l_fbf = false;}
                                        sprintf(l_buf, "\"%swhere%s\": \"%s\"",
                                                        l_id_color.c_str(), l_id_color.c_str(),
                                                        l_subr->get_where().c_str()
                                                        );
                                        ARESP(l_buf);
                                        l_fbf = true;
                                }


                                l_fbf = true;
                        }

                        if(!l_resp)
                        {
                                ARESP("\n");
                                continue;
                        }
                        // Status Code
                        if(a_part_map & PART_STATUS_CODE)
                        {
                                if(l_fbf) {ARESP(", "); l_fbf = false;}
                                const char *l_status_val_color = "";
                                if(a_color)
                                {
                                        if(l_resp->get_status() == 200) l_status_val_color = ANSI_COLOR_FG_GREEN;
                                        else l_status_val_color = ANSI_COLOR_FG_RED;
                                }
                                sprintf(l_buf, "\"%sstatus-code%s\": %s%d%s",
                                                l_status_color.c_str(), l_off_color.c_str(),
                                                l_status_val_color, l_resp->get_status(), l_off_color.c_str());
                                ARESP(l_buf);
                                l_fbf = true;
                        }

                        // Headers
                        // TODO -only in json mode for now
                        if(a_part_map & PART_HEADERS)
                        {
                                // nuthin
                        }

                        // Body
                        if(a_part_map & PART_BODY)
                        {
                                if(l_fbf) {ARESP(", "); l_fbf = false;}
                                //NDBG_PRINT("RESPONSE SIZE: %ld\n", (*i_rx)->m_response_body.length());
                                const char *l_body_buf = l_resp->get_body_data();
                                uint64_t l_body_len = l_resp->get_body_len();
                                if(l_body_len)
                                {
                                        sprintf(l_buf, "\"%sbody%s\": %s",
                                                        l_body_color.c_str(), l_off_color.c_str(),
                                                        l_body_buf);
                                }
                                else
                                {
                                        sprintf(l_buf, "\"%sbody%s\": \"NO_RESPONSE\"",
                                                        l_body_color.c_str(), l_off_color.c_str());
                                }
                                ARESP(l_buf);
                                l_fbf = true;
                        }
                        ARESP("\n");
                }
        }
#endif
        return l_responses_str;
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
#define JS_ADD_MEMBER(_key, _val)\
l_obj.AddMember(_key,\
                rapidjson::Value(_val, l_js_allocator).Move(),\
                l_js_allocator)

std::string dump_all_responses_json(void)
{
#if 0
        rapidjson::Document l_js_doc;
        l_js_doc.SetObject();
        rapidjson::Value l_js_array(rapidjson::kArrayType);
        rapidjson::Document::AllocatorType& l_js_allocator = l_js_doc.GetAllocator();

        for(phurl_h_resp_list_t::const_iterator i_hr = a_resp_list.begin();
            i_hr != a_resp_list.end();
            ++i_hr)
        {
                for(ns_hlx::hlx_resp_list_t::const_iterator i_rx = (*i_hr)->m_resp_list.begin();
                    i_rx != (*i_hr)->m_resp_list.end();
                    ++i_rx)
                {
                        ns_hlx::subr *l_subr = (*i_rx)->m_subr;
                        ns_hlx::resp *l_resp = (*i_rx)->m_resp;
                        if(!l_subr)
                        {
                                continue;
                        }

                        rapidjson::Value l_obj;
                        l_obj.SetObject();

                        // Host
                        if(a_part_map & PART_HOST)
                        {
                                JS_ADD_MEMBER("host", l_subr->get_host().c_str());
                        }

                        // Server
                        if(a_part_map & PART_SERVER)
                        {
                                char l_server_buf[1024];
                                sprintf(l_server_buf, "%s:%d",
                                                l_subr->get_host().c_str(),
                                                l_subr->get_port());
                                JS_ADD_MEMBER("server", l_server_buf);

                                if(!l_subr->get_id().empty())
                                {
                                        JS_ADD_MEMBER("id", l_subr->get_id().c_str());
                                }
                                if(!l_subr->get_where().empty())
                                {
                                        JS_ADD_MEMBER("where", l_subr->get_where().c_str());
                                }
                                if(l_subr->get_port() != 0)
                                {
                                        l_obj.AddMember("port", l_subr->get_port(), l_js_allocator);
                                }
                        }

                        if(!l_resp)
                        {
                                l_obj.AddMember(rapidjson::Value("Error", l_js_allocator).Move(),
                                                rapidjson::Value((*i_rx)->m_error_str.c_str(), l_js_allocator).Move(),
                                                l_js_allocator);
                                l_obj.AddMember("status-code", 500, l_js_allocator);
                                l_js_array.PushBack(l_obj, l_js_allocator);
                                continue;
                        }

                        // Status Code
                        if(a_part_map & PART_STATUS_CODE)
                        {
                                l_obj.AddMember("status-code", l_resp->get_status(), l_js_allocator);
                        }

                        // Headers
                        const ns_hlx::kv_map_list_t &l_headers = l_resp->get_headers();
                        if(a_part_map & PART_HEADERS)
                        {
                                for(ns_hlx::kv_map_list_t::const_iterator i_header = l_headers.begin();
                                    i_header != l_headers.end();
                                    ++i_header)
                                {
                                        for(ns_hlx::str_list_t::const_iterator i_val = i_header->second.begin();
                                            i_val != i_header->second.end();
                                            ++i_val)
                                        {
                                                l_obj.AddMember(rapidjson::Value(i_header->first.c_str(), l_js_allocator).Move(),
                                                                rapidjson::Value(i_val->c_str(), l_js_allocator).Move(),
                                                                l_js_allocator);
                                        }
                                }
                        }
                        // ---------------------------------------------------
                        // SSL connection info
                        // ---------------------------------------------------
                        // TODO Add flag -only add to output if flag
                        // ---------------------------------------------------
                        // Find tls_info for host
                        if(a_settings.m_tls_info_map.find(l_subr->get_host()) != a_settings.m_tls_info_map.end())
                        {
                                tls_info_t l_info = a_settings.m_tls_info_map[l_subr->get_host()];
                                // TODO
                                if(l_info.m_tls_info_cipher_str)
                                {
                                        l_obj.AddMember(rapidjson::Value("Cipher", l_js_allocator).Move(),
                                                        rapidjson::Value(l_info.m_tls_info_cipher_str, l_js_allocator).Move(),
                                                        l_js_allocator);
                                }
                                if(l_info.m_tls_info_protocol_str)
                                {
                                        l_obj.AddMember(rapidjson::Value("Protocol", l_js_allocator).Move(),
                                                        rapidjson::Value(l_info.m_tls_info_protocol_str, l_js_allocator).Move(),
                                                        l_js_allocator);
                                }
                        }

                        // Search for json
                        bool l_content_type_json = false;
                        ns_hlx::kv_map_list_t::const_iterator i_h = l_headers.find("Content-type");
                        if(i_h != l_headers.end())
                        {
                                for(ns_hlx::str_list_t::const_iterator i_val = i_h->second.begin();
                                    i_val != i_h->second.end();
                                    ++i_val)
                                {
                                        if((*i_val) == "application/json")
                                        {
                                                l_content_type_json = true;
                                        }
                                }
                        }

                        // Body
                        if(a_part_map & PART_BODY)
                        {

                                //NDBG_PRINT("RESPONSE SIZE: %ld\n", (*i_rx)->m_response_body.length());
                                const char *l_body_buf = l_resp->get_body_data();
                                uint64_t l_body_len = l_resp->get_body_len();
                                if(l_body_len)
                                {
                                        // Append json
                                        if(l_content_type_json)
                                        {
                                                rapidjson::Document l_doc_body;
                                                l_doc_body.Parse(l_body_buf);
                                                l_obj.AddMember("body",
                                                                rapidjson::Value(l_doc_body, l_js_allocator).Move(),
                                                                l_js_allocator);

                                        }
                                        else
                                        {
                                                JS_ADD_MEMBER("body", l_body_buf);
                                        }
                                }
                                else
                                {
                                        JS_ADD_MEMBER("body", "NO_RESPONSE");
                                }
                        }
                        l_js_array.PushBack(l_obj, l_js_allocator);
                }
        }

        // TODO -Can I just create an array -do I have to stick in a document?
        l_js_doc.AddMember("array", l_js_array, l_js_allocator);
        rapidjson::StringBuffer l_strbuf;
        rapidjson::Writer<rapidjson::StringBuffer> l_js_writer(l_strbuf);
        l_js_doc["array"].Accept(l_js_writer);

        //NDBG_PRINT("Document: \n%s\n", l_strbuf.GetString());
        std::string l_responses_str = l_strbuf.GetString();
#else
        std::string l_responses_str = "";
#endif
        return l_responses_str;
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
std::string dump_all_responses(output_type_t a_output_type,
                               int a_part_map)
{
        std::string l_responses_str = "";
#if 0
        switch(a_output_type)
        {
        case OUTPUT_LINE_DELIMITED:
        {
                l_responses_str = dump_all_responses_line_dl(a_settings, a_resp_list, a_color, a_pretty, a_part_map);
                break;
        }
        case OUTPUT_JSON:
        {
                l_responses_str = dump_all_responses_json(a_settings, a_resp_list, a_part_map);
                break;
        }
        default:
        {
                break;
        }
        }
#endif
        return l_responses_str;
}
