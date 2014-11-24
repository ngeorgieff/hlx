//: ----------------------------------------------------------------------------
//: Copyright (C) 2014 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    t_client.cc
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
#include "t_client.h"
#include "bsx.h"

#include <unistd.h>

// inet_aton
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <string.h>
#include <string>

#include <stdint.h>
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif
#include <inttypes.h>

// Required???
#include <sys/time.h>
#include <sys/types.h>
#include <stdlib.h>
#include <fcntl.h>
#include <ctype.h>

// Required???
#include <sys/select.h>

#include <libssh2.h>

//: ----------------------------------------------------------------------------
//: Macros
//: ----------------------------------------------------------------------------
#define T_CLIENT_CONN_CLEANUP(a_t_client, a_conn, a_cmdlet, a_status, a_result) \
        do { \
                a_cmdlet->set_result(a_status, a_result); \
                if(a_status < 0) cmdlet_repo::get()->up_done(true); \
                else cmdlet_repo::get()->up_done(false); \
                a_t_client->cleanup_connection(a_conn); \
        }while(0)

//: ----------------------------------------------------------------------------
//: Fwd Decl's
//: ----------------------------------------------------------------------------

//: ----------------------------------------------------------------------------
//: Thread local global
//: ----------------------------------------------------------------------------
__thread t_client *g_t_client = NULL;


//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
#if 0
static int waitsocket(int a_socket_fd, LIBSSH2_SESSION *a_session)
{
        struct timeval l_timeout;
        int l_rc;
        fd_set l_fd;
        fd_set *l_writefd = NULL;
        fd_set *l_readfd = NULL;
        int l_dir;

        printf("%s.%s.%d: BLoop.\n", __FILE__,__FUNCTION__,__LINE__);

        l_timeout.tv_sec = 10;
        l_timeout.tv_usec = 0;

        FD_ZERO(&l_fd);
        FD_SET(a_socket_fd, &l_fd);

        // now make sure we wait in the correct direction
        l_dir = libssh2_session_block_directions(a_session);
        if (l_dir & LIBSSH2_SESSION_BLOCK_INBOUND)  l_readfd  = &l_fd;
        if (l_dir & LIBSSH2_SESSION_BLOCK_OUTBOUND) l_writefd = &l_fd;

        l_rc = select(a_socket_fd + 1, l_readfd, l_writefd, NULL, &l_timeout);

        return l_rc;
}
#endif


//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
t_client::t_client(bool a_verbose,
                bool a_color,
                uint32_t a_sock_opt_recv_buf_size,
                uint32_t a_sock_opt_send_buf_size,
                bool a_sock_opt_no_delay,
                uint32_t a_timeout_s,
                evr_loop_type_t a_evr_loop_type,
                uint32_t a_max_parallel_connections,
                const std::string &a_user,
                const std::string &a_password,
                const std::string &a_public_key_file,
                const std::string &a_private_key_file):

        m_t_run_thread(),
        m_verbose(a_verbose),
        m_color(a_color),
        m_sock_opt_recv_buf_size(a_sock_opt_recv_buf_size),
        m_sock_opt_send_buf_size(a_sock_opt_send_buf_size),
        m_sock_opt_no_delay(a_sock_opt_no_delay),
        m_timeout_s(a_timeout_s),
        m_evr_loop_type(a_evr_loop_type),
        m_stopped(false),
        m_max_parallel_connections(a_max_parallel_connections),
        m_nconn_vector(a_max_parallel_connections),
        m_conn_free_list(),
        m_conn_used_set(),
        m_num_cmds(-1),
        m_num_cmds_completed(0),
        m_num_cmds_pending(0),
        m_evr_loop(NULL),
        m_user(a_user),
        m_password(a_password),
        m_public_key_file(a_public_key_file),
        m_private_key_file(a_private_key_file)
{

        for(uint32_t i_conn = 0; i_conn < a_max_parallel_connections; ++i_conn)
        {
                nconn *l_nconn = new nconn(m_verbose,
                                m_color,
                                m_sock_opt_recv_buf_size,
                                m_sock_opt_send_buf_size,
                                m_sock_opt_no_delay,
                                true,
                                false,
                                m_timeout_s,
                                1,
                                NULL);

                l_nconn->set_id(i_conn);
                m_nconn_vector[i_conn] = l_nconn;
                m_conn_free_list.push_back(i_conn);
        }
}


//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
t_client::~t_client()
{
        for(uint32_t i_conn = 0; i_conn < m_nconn_vector.size(); ++i_conn)
        {
                delete m_nconn_vector[i_conn];
        }

        if(m_evr_loop)
        {
                delete m_evr_loop;
        }
}


//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int t_client::run(void)
{

        int32_t l_pthread_error = 0;

        l_pthread_error = pthread_create(&m_t_run_thread,
                        NULL,
                        t_run_static,
                        this);
        if (l_pthread_error != 0)
        {
                // failed to create thread

                NDBG_PRINT("Error: creating thread.  Reason: %s\n.", strerror(l_pthread_error));
                return STATUS_ERROR;

        }

        return STATUS_OK;

}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
void t_client::stop(void)
{
        m_stopped = true;
        int32_t l_status;
        l_status = m_evr_loop->stop();
        if(l_status != STATUS_OK)
        {
                NDBG_PRINT("Error performing stop.\n");
        }
}


//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
void *t_client::evr_loop_file_writeable_cb(void *a_data)
{
        if(!a_data)
        {
                //NDBG_PRINT("a_data == NULL\n");
                return NULL;
        }

        nconn* l_nconn = static_cast<nconn*>(a_data);
        cmdlet *l_cmdlet = static_cast<cmdlet *>(l_nconn->get_data1());
        t_client *l_t_client = g_t_client;

        //NDBG_PRINT("%sWRITEABLE%s[%d] %p\n", ANSI_COLOR_FG_BLUE, ANSI_COLOR_OFF, l_nconn->m_fd, l_nconn);

        // Cancel last timer
        l_t_client->m_evr_loop->cancel_timer(&(l_nconn->m_timer_obj));

        int32_t l_status = STATUS_OK;
        l_status = l_nconn->run_state_machine(l_t_client->m_evr_loop, l_cmdlet->m_host_info);
        if(STATUS_ERROR == l_status)
        {
                NDBG_PRINT("Error: performing run_state_machine\n");
                T_CLIENT_CONN_CLEANUP(l_t_client, l_nconn, l_cmdlet, 500, "Error performing connect_cb");
                return NULL;
        }

        // Add idle timeout
        l_t_client->m_evr_loop->add_timer( l_t_client->get_timeout_s()*1000, evr_loop_file_timeout_cb, l_nconn, &(l_nconn->m_timer_obj));

        return NULL;

}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
void *t_client::evr_loop_file_readable_cb(void *a_data)
{
        if(!a_data)
        {
                //NDBG_PRINT("a_data == NULL\n");
                return NULL;
        }

        nconn* l_nconn = static_cast<nconn*>(a_data);
        cmdlet *l_cmdlet = static_cast<cmdlet *>(l_nconn->get_data1());
        t_client *l_t_client = g_t_client;

        //NDBG_PRINT("%sREADABLE%s[%d] %p\n", ANSI_COLOR_FG_GREEN, ANSI_COLOR_OFF, l_nconn->m_fd, l_nconn);

        // Cancel last timer
        l_t_client->m_evr_loop->cancel_timer(&(l_nconn->m_timer_obj));

        int32_t l_status = STATUS_OK;
        l_status = l_nconn->run_state_machine(l_t_client->m_evr_loop, l_cmdlet->m_host_info);
        if(STATUS_ERROR == l_status)
        {
                NDBG_PRINT("Error: performing run_state_machine\n");
                T_CLIENT_CONN_CLEANUP(l_t_client, l_nconn, l_cmdlet, 500, "Error performing connect_cb");
                return NULL;
        }

        //if(l_status >= 0)
        //{
        //        l_cmdlet->m_stat_agg.m_num_bytes_read += l_status;
        //}

        // Check for done...
        // TODO REMOVE
        //NDBG_PRINT("%sREADABLE%s[%d] %p STATE: %d\n", ANSI_COLOR_FG_GREEN, ANSI_COLOR_OFF, l_nconn->m_fd, l_nconn, l_nconn->get_state());
        if((l_nconn->get_state() == nconn::CONN_STATE_DONE) ||
                        (l_status == STATUS_ERROR))
        {
                T_CLIENT_CONN_CLEANUP(l_t_client, l_nconn, l_cmdlet, l_status, "");
                return NULL;
        }

        // Add idle timeout
        l_t_client->m_evr_loop->add_timer( l_t_client->get_timeout_s()*1000, evr_loop_file_timeout_cb, l_nconn, &(l_nconn->m_timer_obj));

        return NULL;
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
void *g_completion_timer;
void *t_client::evr_loop_timer_completion_cb(void *a_data)
{
        return NULL;
}


//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
void *t_client::evr_loop_file_error_cb(void *a_data)
{
        //NDBG_PRINT("%sSTATUS_ERRORS%s\n", ANSI_COLOR_FG_RED, ANSI_COLOR_OFF);
        return NULL;
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
void *t_client::evr_loop_file_timeout_cb(void *a_data)
{
        if(!a_data)
        {
                //NDBG_PRINT("a_data == NULL\n");
                return NULL;
        }

        nconn* l_nconn = static_cast<nconn*>(a_data);
        cmdlet *l_cmdlet = static_cast<cmdlet *>(l_nconn->get_data1());
        t_client *l_t_client = g_t_client;

        //printf("%sT_O%s: %p\n",ANSI_COLOR_FG_BLUE, ANSI_COLOR_OFF,
        //		l_rconn->m_timer_obj);

        // Add stats
        //add_stat_to_agg(l_cmdlet->m_stat_agg, l_nconn->get_stats());
        if(l_t_client->m_verbose)
        {
                NDBG_PRINT("%sTIMING OUT CONN%s: i_conn: %lu HOST: %s LAST_STATE: %d THIS: %p\n",
                                ANSI_COLOR_BG_RED, ANSI_COLOR_OFF,
                                l_nconn->get_id(),
                                l_cmdlet->m_host.c_str(),
                                l_nconn->get_state(),
                                l_t_client);
        }

        // Cleanup
        T_CLIENT_CONN_CLEANUP(l_t_client, l_nconn, l_cmdlet, 502, "Connection timed out");

        return NULL;
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
void *t_client::evr_loop_timer_cb(void *a_data)
{
        return NULL;
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
void *t_client::t_run(void *a_nothing)
{

        // Set thread local
        g_t_client = this;

        // Create loop
        m_evr_loop = new evr_loop(
                        evr_loop_file_readable_cb,
                        evr_loop_file_writeable_cb,
                        evr_loop_file_error_cb,
                        m_evr_loop_type,
                        m_max_parallel_connections);

        cmdlet_repo *l_cmdlet_repo = cmdlet_repo::get();

        // -------------------------------------------
        // Main loop.
        // -------------------------------------------
        //NDBG_PRINT("starting main loop\n");
        while(!m_stopped &&
                        !l_cmdlet_repo->done())
        {

                // -------------------------------------------
                // Start Connections
                // -------------------------------------------
                //NDBG_PRINT("%sSTART_CONNECTIONS%s\n", ANSI_COLOR_BG_MAGENTA, ANSI_COLOR_OFF);
                if(!l_cmdlet_repo->done())
                {
                        int32_t l_status;
                        l_status = start_connections();
                        if(l_status != STATUS_OK)
                        {
                                NDBG_PRINT("%sSTART_CONNECTIONS%s ERROR!\n", ANSI_COLOR_BG_RED, ANSI_COLOR_OFF);
                                return NULL;
                        }
                }

                // Run loop
                m_evr_loop->run();

        }

        //NDBG_PRINT("%sFINISHING_CONNECTIONS%s\n", ANSI_COLOR_BG_MAGENTA, ANSI_COLOR_OFF);

        // Still awaiting responses -wait...
        uint64_t l_cur_time = get_time_s();
        uint64_t l_end_time = l_cur_time + m_timeout_s;
        while(!m_stopped && (m_num_cmds_pending > 0) && (l_cur_time < l_end_time))
        {
                // Run loop
                //NDBG_PRINT("waiting: m_num_pending: %d --time-left: %d\n", (int)m_num_pending, int(l_end_time - l_cur_time));
                m_evr_loop->run();

                // TODO -this is pretty hard polling -make option???
                usleep(10000);
                l_cur_time = get_time_s();

        }
        //NDBG_PRINT("%sDONE_CONNECTIONS%s\n", ANSI_COLOR_BG_YELLOW, ANSI_COLOR_OFF);

        m_stopped = true;

#if 0
        // ---------------------------------------------------------------------
        // TODO TEST
        // ---------------------------------------------------------------------
        NDBG_PRINT("TESTING\n");

        unsigned long hostaddr;
        int sock;
        struct sockaddr_in sin;
        //const char *fingerprint;
        LIBSSH2_SESSION *session;
        LIBSSH2_CHANNEL *channel;
        int rc;
        int exitcode;
        char *exitsignal = (char *) "none";
        int bytecount = 0;
        //size_t len;
        //LIBSSH2_KNOWNHOSTS *nh;
        //int type;

        // Create a session instance
        session = libssh2_session_init();
        if (!session)
        {
                return NULL;
        }

        // tell libssh2 we want it all done non-blocking
        libssh2_session_set_blocking(session, 0);

        // ---------------------------------------
        // Handshake
        // ---------------------------------------
        // ... start it up. This will trade welcome banners, exchange keys,
        // and setup crypto, compression, and MAC layers
        while ((rc = libssh2_session_handshake(session, sock)) == LIBSSH2_ERROR_EAGAIN);
        if (rc)
        {
                fprintf(stderr, "Failure establishing SSH session: %d\n", rc);
                return NULL;
        }

        // -------------------------------------------------
        // Validation
        // -------------------------------------------------
#if 0
        nh = libssh2_knownhost_init(session);
        if (!nh)
        {
                // eeek, do cleanup here
                return 2;
        }

        // read all hosts from here
        libssh2_knownhost_readfile(nh, "known_hosts", LIBSSH2_KNOWNHOST_FILE_OPENSSH);

        // store all known hosts to here
        libssh2_knownhost_writefile(nh, "dumpfile", LIBSSH2_KNOWNHOST_FILE_OPENSSH);

        fingerprint = libssh2_session_hostkey(session, &len, &type);
        if (fingerprint)
        {
                struct libssh2_knownhost *host;
#if LIBSSH2_VERSION_NUM >= 0x010206
                // introduced in 1.2.6
                int check = libssh2_knownhost_checkp(nh, hostname, 22,

                                fingerprint, len,
                                LIBSSH2_KNOWNHOST_TYPE_PLAIN|
                                LIBSSH2_KNOWNHOST_KEYENC_RAW,
                                &host);
#else
                /* 1.2.5 or older */
                int check = libssh2_knownhost_check(nh, hostname,

                fingerprint, len, LIBSSH2_KNOWNHOST_TYPE_PLAIN | LIBSSH2_KNOWNHOST_KEYENC_RAW, &host);
#endif
                fprintf(stderr, "Host check: %d, key: %s\n", check,
                                (check <= LIBSSH2_KNOWNHOST_CHECK_MISMATCH) ? host->key : "<none>");

                // At this point, we could verify that 'check' tells us the key is
                // fine or bail out.

        } else
        {
                // eeek, do cleanup here
                return 3;
        }
        libssh2_knownhost_free(nh);
#endif

        // -------------------------------------------------
        // Authentication
        // -------------------------------------------------
        if (!m_password.empty())
        {
                // We could authenticate via password
                while ((rc = libssh2_userauth_password(session,
                                                       m_user.c_str(),
                                                       m_password.c_str())) == LIBSSH2_ERROR_EAGAIN);
                if (rc)
                {
                        char *errmsg;
                        int errlen;
                        int err = libssh2_session_last_error(session, &errmsg, &errlen, 0);
                        fprintf(stderr, "Authentication by password failed: (%d) %s\n", err, errmsg);
                        fprintf(stderr, "Authentication by password failed.\n");
                        goto shutdown;
                }
        }
        else
        {

                // Or by public key
                while ((rc = libssh2_userauth_publickey_fromfile(session,
                                                                 m_user.c_str(),
                                                                 m_public_key_file.c_str(),
                                                                 m_private_key_file.c_str(),
                                                                 m_password.c_str())) == LIBSSH2_ERROR_EAGAIN);
                if (rc)
                {
                        char *errmsg;
                        int errlen;
                        int err = libssh2_session_last_error(session, &errmsg, &errlen, 0);
                        fprintf(stderr, "Authentication by public key failed: (%d) %s\n", err, errmsg);
                        fprintf(stderr, "Authentication by public key failed. rc: %d\n", rc);

                        goto shutdown;
                }

        }


        // ---------------------------------------
        // Open Session
        // Exec non-blocking on the remove host
        // ---------------------------------------
        while ((channel = libssh2_channel_open_session(session)) == NULL &&

        libssh2_session_last_error(session, NULL, NULL, 0) == LIBSSH2_ERROR_EAGAIN)
        {
                waitsocket(sock, session);
        }
        if (channel == NULL)
        {
                fprintf(stderr, "Error\n");
                exit(1);
        }

        // ---------------------------------------
        // Exec command
        // ---------------------------------------
        while ((rc = libssh2_channel_exec(channel, commandline)) == LIBSSH2_ERROR_EAGAIN)
        {
                waitsocket(sock, session);
        }
        if (rc != 0)
        {
                fprintf(stderr, "Error\n");
                exit(1);
        }
        for (;;)
        {
                // loop until we block
                int rc;
                do
                {
                        char buffer[0x4000];
                        rc = libssh2_channel_read(channel, buffer, sizeof(buffer));

                        if (rc > 0)
                        {
                                int i;
                                bytecount += rc;
                                fprintf(stderr, "We read:\n");
                                for (i = 0; i < rc; ++i)
                                {
                                        fputc(buffer[i], stderr);
                                }
                                fprintf(stderr, "\n");
                        } else
                        {
                                if (rc != LIBSSH2_ERROR_EAGAIN)
                                {
                                        // no need to output this for the EAGAIN case
                                        fprintf(stderr, "libssh2_channel_read returned %d\n", rc);
                                }
                        }
                } while (rc > 0);

                // this is due to blocking that would occur otherwise so we loop on this condition
                if (rc == LIBSSH2_ERROR_EAGAIN)
                {
                        waitsocket(sock, session);
                }
                else
                {
                        break;
                }
        }


        exitcode = 127;
        while ((rc = libssh2_channel_close(channel)) == LIBSSH2_ERROR_EAGAIN) waitsocket(sock, session);
        if (rc == 0)
        {
                exitcode = libssh2_channel_get_exit_status(channel);
                libssh2_channel_get_exit_signal(channel, &exitsignal,NULL, NULL, NULL, NULL, NULL);
        }

        if (exitsignal)
        {
                fprintf(stderr, "\nGot signal: %s\n", exitsignal);
        }
        else
        {
                fprintf(stderr, "\nEXIT: %d bytecount: %d\n", exitcode, bytecount);
        }

        libssh2_channel_free(channel);

        channel = NULL;

shutdown:
        libssh2_session_disconnect(session,"Normal Shutdown, Thank you for playing");
        libssh2_session_free(session);

        close(sock);
        fprintf(stderr, "all done\n");

        // ---------------------------------------------------------------------
        // TODO TEST
        // ---------------------------------------------------------------------
#endif

        return NULL;

}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t t_client::start_connections(void)
{
        int32_t l_status;
        cmdlet_repo *l_cmdlet_repo = cmdlet_repo::get();
        cmdlet *l_cmdlet = NULL;

        // Find an empty connection slot.
        //NDBG_PRINT("m_conn_free_list.size(): %Zu\n", m_conn_free_list.size());
        for (conn_id_list_t::iterator i_conn = m_conn_free_list.begin();
               (i_conn != m_conn_free_list.end()) &&
               (!l_cmdlet_repo->done()) &&
               !m_stopped;
             )
        {

                // Loop trying to get cmdlet
                l_cmdlet = NULL;
                while(((l_cmdlet = l_cmdlet_repo->try_get_resolved()) == NULL) && (!l_cmdlet_repo->done()));
                if((l_cmdlet == NULL) && l_cmdlet_repo->done())
                {
                        // Bail out
                        return STATUS_OK;
                }

                // Start connection for this cmdlet
                //NDBG_PRINT("i_conn: %d\n", *i_conn);
                nconn *l_nconn = m_nconn_vector[*i_conn];
                // TODO Check for NULL


                // Assign the cmdlet for this connection
                l_nconn->set_data1(l_cmdlet);

                // Set scheme
                l_nconn->set_scheme(nconn::SCHEME_SSH);

                // SSH settings
                l_nconn->set_ssh2_user(m_user);
                l_nconn->set_ssh2_password(m_password);
                l_nconn->set_ssh2_public_key_file(m_public_key_file);
                l_nconn->set_ssh2_private_key_file(m_private_key_file);

                // Create request
                create_cmd(*l_nconn, *l_cmdlet);

                m_conn_used_set.insert(*i_conn);
                m_conn_free_list.erase(i_conn++);

                // Add to num pending
                ++m_num_cmds_pending;

                // TODO Make configurable
                m_evr_loop->add_timer(m_timeout_s*1000, evr_loop_file_timeout_cb, l_nconn, &(l_nconn->m_timer_obj));

                //NDBG_PRINT("%sCONNECT%s: %s\n", ANSI_COLOR_BG_MAGENTA, ANSI_COLOR_OFF, l_cmdlet->m_host.c_str());
                l_nconn->set_host(l_cmdlet->m_host);
                l_status = l_nconn->run_state_machine(m_evr_loop, l_cmdlet->m_host_info);
                if((STATUS_OK != l_status) &&
                                (l_nconn->get_state() != nconn::CONN_STATE_CONNECTING))
                {
                        NDBG_PRINT("Error: Performing do_connect\n");
                        T_CLIENT_CONN_CLEANUP(this, l_nconn, l_cmdlet, -1, "Performing do_connect");
                        continue;
                }
        }

        return STATUS_OK;

}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t t_client::create_cmd(nconn &ao_conn, const cmdlet &a_cmdlet)
{
        // Get connection
        char *l_req_buf = ao_conn.m_req_buf;
        uint32_t l_req_buf_len = 0;
        uint32_t l_max_buf_len = sizeof(ao_conn.m_req_buf);

        // -------------------------------------------
        // End of request terminator...
        // -------------------------------------------
        l_req_buf_len += snprintf(l_req_buf, l_max_buf_len, "%s", a_cmdlet.m_cmd_line.c_str());

        // Set len
        ao_conn.m_req_buf_len = l_req_buf_len;

        return STATUS_OK;
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t t_client::cleanup_connection(nconn *a_nconn, bool a_cancel_timer)
{
        uint64_t l_conn_id = a_nconn->get_id();

        // Cancel last timer
        if(a_cancel_timer)
        {
                m_evr_loop->cancel_timer(&(a_nconn->m_timer_obj));
        }
        m_evr_loop->del_fd(a_nconn->get_fd());
        a_nconn->reset_stats();
        a_nconn->done_cb();

        // Add back to free list
        m_conn_free_list.push_back(l_conn_id);
        m_conn_used_set.erase(l_conn_id);

        // Reduce num pending
        ++m_num_cmds_completed;
        --m_num_cmds_pending;

        return STATUS_OK;
}


