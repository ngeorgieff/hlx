//: ----------------------------------------------------------------------------
//: Copyright (C) 2014 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    bsx.cc
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
#include "bsx.h"
#include "t_client.h"
#include "cmdlet.h"

//#include "util.h"

#include <libssh2.h>

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t bsx::run(host_list_t &a_host_list)
{
        int32_t l_retval = STATUS_OK;
        cmdlet_repo *l_cmdlet_repo = NULL;

        // Check is initialized
        if(!m_is_initd)
        {
                l_retval = init();
                if(STATUS_OK != l_retval)
                {
                        NDBG_PRINT("Error: performing init.\n");
                        return STATUS_ERROR;
                }
        }

        // Create the reqlet list
        l_cmdlet_repo = cmdlet_repo::get();
        uint32_t l_cmdlet_num = 0;
        for(host_list_t::iterator i_host = a_host_list.begin();
                        i_host != a_host_list.end();
                        ++i_host, ++l_cmdlet_num)
        {
                // Create a re
                cmdlet *l_cmdlet = new cmdlet(l_cmdlet_num, *i_host, m_exec_line);
                // TODO Make port configurable

                // Add to list
                l_cmdlet_repo->add_cmdlet(l_cmdlet);

        }

        // -------------------------------------------
        // Create t_client list...
        // -------------------------------------------
        for(uint32_t i_client_idx = 0; i_client_idx < m_num_threads; ++i_client_idx)
        {

                if(m_verbose)
                {
                        NDBG_PRINT("Creating...\n");
                }

                // Construct with settings...
                t_client *l_t_client = new t_client(
                        m_verbose,
                        m_color,
                        m_sock_opt_recv_buf_size,
                        m_sock_opt_send_buf_size,
                        m_sock_opt_no_delay,
                        m_timeout_s,
                        m_evr_loop_type,
                        m_start_parallel,
                        m_user,
                        m_password,
                        m_public_key_file,
                        m_private_key_file
                );

                m_t_client_list.push_back(l_t_client);
        }

        // Wipe
        //m_user.clear();
        //m_password.clear();
        //m_public_key.clear();
        //m_private_key_file.clear();

        // -------------------------------------------
        // Run...
        // -------------------------------------------
        for(t_client_list_t::iterator i_t_client = m_t_client_list.begin();
                        i_t_client != m_t_client_list.end();
                        ++i_t_client)
        {
                if(m_verbose)
                {
                        NDBG_PRINT("Running...\n");
                }
                (*i_t_client)->run();
        }

        return l_retval;

}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t bsx::stop(void)
{
        int32_t l_retval = STATUS_OK;

        for (t_client_list_t::iterator i_t_client = m_t_client_list.begin();
                        i_t_client != m_t_client_list.end();
                        ++i_t_client)
        {
                (*i_t_client)->stop();
        }

        return l_retval;

}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t bsx::wait_till_stopped(void)
{
        int32_t l_retval = STATUS_OK;

        // -------------------------------------------
        // Join all threads before exit
        // -------------------------------------------
        for(t_client_list_t::iterator i_client = m_t_client_list.begin();
                        i_client != m_t_client_list.end(); ++i_client)
        {

                //if(m_verbose)
                //{
                // 	NDBG_PRINT("joining...\n");
                //}
                pthread_join(((*i_client)->m_t_run_thread), NULL);

        }

        return l_retval;

}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
bool bsx::is_running(void)
{
        for (t_client_list_t::iterator i_client_bsx = m_t_client_list.begin();
                        i_client_bsx != m_t_client_list.end(); ++i_client_bsx)
        {
                if((*i_client_bsx)->is_running())
                        return true;
        }

        return false;
}


//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t bsx::init(void)
{
        // Check if already is initd
        if(m_is_initd)
                return STATUS_OK;

        //NDBG_PRINT("%sINIT%s: DONE\n", ANSI_COLOR_BG_GREEN, ANSI_COLOR_OFF);

        // -------------------------------------------
        // Start async resolver
        // -------------------------------------------
        //t_async_resolver::get()->run();

        int l_libssh2_init_status;
        l_libssh2_init_status = libssh2_init(0);
        if (l_libssh2_init_status != 0)
        {
                printf("Error libssh2 initialization failed (%d)\n", l_libssh2_init_status);
                return STATUS_ERROR;
        }

        m_is_initd = true;
        return STATUS_OK;

}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
bsx::bsx(void):
        m_t_client_list(),
        m_is_initd(false),
        m_verbose(false),
        m_color(false),
        m_quiet(false),
        m_sock_opt_recv_buf_size(0),
        m_sock_opt_send_buf_size(0),
        m_sock_opt_no_delay(false),
        m_evr_loop_type(EVR_LOOP_EPOLL),
        m_start_parallel(1),
        m_num_threads(1),
        m_exec_line(),
        m_timeout_s(BSX_DEFAULT_CONN_TIMEOUT_S),
        m_user(),
        m_password(),
        m_public_key_file(),
        m_private_key_file()
{

}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
bsx::~bsx()
{
        // -------------------------------------------
        // Delete t_client list...
        // -------------------------------------------
        for(t_client_list_t::iterator i_client_bsx = m_t_client_list.begin();
                        i_client_bsx != m_t_client_list.end(); )
        {

                t_client *l_t_client_ptr = *i_client_bsx;
                delete l_t_client_ptr;
                m_t_client_list.erase(i_client_bsx++);

        }

        // libssh cleanup
        libssh2_exit();


        // SSL Cleanup
        //nconn_kill_locks();

        // TODO Deprecated???
        //EVP_cleanup();

}


//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
bsx *bsx::get(void)
{
        if (m_singleton_ptr == NULL) {
                //If not yet created, create the singleton instance
                m_singleton_ptr = new bsx();

                // Initialize

        }
        return m_singleton_ptr;
}

//: ----------------------------------------------------------------------------
//: Class variables
//: ----------------------------------------------------------------------------
// the pointer to the singleton for the instance 
bsx *bsx::m_singleton_ptr;

