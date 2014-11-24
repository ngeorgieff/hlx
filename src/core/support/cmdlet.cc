//: ----------------------------------------------------------------------------
//: Copyright (C) 2014 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    cmdlet_repo.cc
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
#include "cmdlet.h"
#include "ndebug.h"
#include "resolver.h"

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t cmdlet::resolve(void)
{

        int32_t l_status = STATUS_OK;
        l_status = resolver::get()->cached_resolve(m_host, m_port, m_host_info);
        if(l_status != STATUS_OK)
        {
                return STATUS_ERROR;
        }

        //show_host_info();

        m_is_resolved_flag = true;
        return STATUS_OK;

}


//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
void cmdlet::show_host_info(void)
{
        printf("+-----------+\n");
        printf("| Host Info |\n");
        printf("+-----------+-------------------------\n");
        printf(": m_sock_family:   %d\n", m_host_info.m_sock_family);
        printf(": m_sock_type:     %d\n", m_host_info.m_sock_type);
        printf(": m_sock_protocol: %d\n", m_host_info.m_sock_protocol);
        printf(": m_sa_len:        %d\n", m_host_info.m_sa_len);
        printf("+-------------------------------------\n");

}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
const std::string &cmdlet::get_label(void)
{
        return m_tag;
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
void cmdlet::set_result(int32_t a_status, const char *a_result)
{
        // Set cmdlet response
        m_status = a_status;

        if(a_result)
        {
                std::string l_result(a_result);
                if(!l_result.empty())
                {
                        m_result = a_result;
                }
        }
        std::string l_result(a_result);
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
void cmdlet_repo::dump_all_results(bool a_color)
{
        std::string l_host_color = "";
        //std::string l_status_color = "";
        std::string l_result_color = "";
        std::string l_off_color = "";
        if(a_color)
        {
                l_host_color = ANSI_COLOR_FG_BLUE;
                //l_status_color = ANSI_COLOR_FG_GREEN;
                l_result_color = ANSI_COLOR_FG_YELLOW;
                l_off_color = ANSI_COLOR_OFF;
        }

        for(cmdlet_list_t::iterator i_cmdlet = m_cmdlet_list.begin();
            i_cmdlet != m_cmdlet_list.end();
            ++i_cmdlet)
        {
                NDBG_OUTPUT("OUTPUT_CMDLET[%p]: result_length: %d\n", *i_cmdlet, (int)(*i_cmdlet)->m_result.length());

                // Host
                NDBG_OUTPUT("[%s%s%s]:\n", l_host_color.c_str(), (*i_cmdlet)->m_host.c_str(), l_off_color.c_str());

                // Result
                NDBG_OUTPUT("%s%s%s\n", l_result_color.c_str(), (*i_cmdlet)->m_result.c_str(), l_off_color.c_str());

                // Status Code
                // TODO
        }
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
cmdlet *cmdlet_repo::get_cmdlet(void)
{
        cmdlet *l_cmdlet = NULL;

        pthread_mutex_lock(&m_mutex);
        if(!m_cmdlet_list.empty() &&
           (m_num_get < m_num_cmdlets))
        {
                l_cmdlet = *m_cmdlet_list_iter;
                ++m_num_get;
                ++m_cmdlet_list_iter;
        }
        pthread_mutex_unlock(&m_mutex);

        return l_cmdlet;
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
cmdlet *cmdlet_repo::try_get_resolved(void)
{
        cmdlet *l_cmdlet = NULL;
        int32_t l_status;

        l_cmdlet = get_cmdlet();
        if(NULL == l_cmdlet)
        {
                return NULL;
        }

        // Try resolve
        l_status = l_cmdlet->resolve();
        if(STATUS_OK != l_status)
        {
                up_resolved(true);
                return NULL;
        }

        up_resolved(false);
        return l_cmdlet;

}


//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t cmdlet_repo::add_cmdlet(cmdlet *a_cmdlet)
{
        bool l_was_empty = false;
        if(m_cmdlet_list.empty())
        {
                l_was_empty = true;
        }

        //NDBG_PRINT("Adding to repo.\n");
        m_cmdlet_list.push_back(a_cmdlet);
        ++m_num_cmdlets;

        if(l_was_empty)
        {
                m_cmdlet_list_iter = m_cmdlet_list.begin();
        }

        return STATUS_OK;
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
void cmdlet_repo::display_status_line(bool a_color)
{
        if(a_color)
        {
                printf("Done/Resolved/Req'd/Total/Error %s%8u%s / %s%8u%s / %s%8u%s / %s%8u%s / %s%8u%s\n",
                                ANSI_COLOR_FG_GREEN, m_num_done, ANSI_COLOR_OFF,
                                ANSI_COLOR_FG_MAGENTA, m_num_resolved, ANSI_COLOR_OFF,
                                ANSI_COLOR_FG_YELLOW, m_num_get, ANSI_COLOR_OFF,
                                ANSI_COLOR_FG_BLUE, m_num_cmdlets, ANSI_COLOR_OFF,
                                ANSI_COLOR_FG_RED, m_num_error, ANSI_COLOR_OFF);
        }
        else
        {
                printf("Done/Resolved/Req'd/Total/Error %8u / %8u / %8u / %8u / %8u\n",m_num_done, m_num_resolved, m_num_get, m_num_cmdlets, m_num_error);
        }
}


//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
cmdlet_repo::cmdlet_repo(void):
        m_cmdlet_list(),
        m_cmdlet_list_iter(),
        m_mutex(),
        m_num_cmdlets(0),
        m_num_get(0),
        m_num_done(0),
        m_num_resolved(0),
        m_num_error(0)
{
        // Init mutex
        pthread_mutex_init(&m_mutex, NULL);
}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
cmdlet_repo *cmdlet_repo::get(void)
{
        if (m_singleton_ptr == NULL) {
                //If not yet created, create the singleton instance
                m_singleton_ptr = new cmdlet_repo();

                // Initialize

        }
        return m_singleton_ptr;
}

//: ----------------------------------------------------------------------------
//: Class variables
//: ----------------------------------------------------------------------------
// the pointer to the singleton for the instance
cmdlet_repo *cmdlet_repo::m_singleton_ptr;



