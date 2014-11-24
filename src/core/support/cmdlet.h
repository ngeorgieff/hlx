//: ----------------------------------------------------------------------------
//: Copyright (C) 2014 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    cmdlet_repo.h
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
#ifndef _CMDLET_REPO_H
#define _CMDLET_REPO_H


//: ----------------------------------------------------------------------------
//: Includes
//: ----------------------------------------------------------------------------
#include "ndebug.h"
#include "host_info.h"

//#include <pthread.h>
#include <list>

//: ----------------------------------------------------------------------------
//: Constants
//: ----------------------------------------------------------------------------
#define DEFAULT_SSH_PORT 22

//: ----------------------------------------------------------------------------
//: Macros
//: ----------------------------------------------------------------------------


//: ----------------------------------------------------------------------------
//: Enums
//: ----------------------------------------------------------------------------


//: ----------------------------------------------------------------------------
//: Types
//: ----------------------------------------------------------------------------
class cmdlet;
typedef std::list <cmdlet *> cmdlet_list_t;


//: ----------------------------------------------------------------------------
//: Fwd Decl's
//: ----------------------------------------------------------------------------


//: ----------------------------------------------------------------------------
//: \details: cmdlet
//: ----------------------------------------------------------------------------
class cmdlet
{
public:

        // -------------------------------------------
        // Public methods
        // -------------------------------------------
        cmdlet(uint64_t a_id,
                        const std::string &a_host,
                        const std::string &a_cmd_line):
                m_host(a_host),
                m_host_info(),
                m_cmd_line(a_cmd_line),
                m_result(),
                m_status(0),
                m_port(DEFAULT_SSH_PORT),
                m_id(a_id),
                m_is_resolved_flag(false),
                m_tag("UNDEFINED")
        {};
        ~cmdlet() {};
        uint64_t get_id(void) {return m_id;}
        bool is_resolved(void) {return m_is_resolved_flag;}
        int32_t resolve(void);
        void show_host_info(void);
        const std::string &get_label(void);
        void set_host(std::string &a_host) { m_host = a_host;}
        void set_result(int32_t a_status, const char *a_result);

        // -------------------------------------------
        // Public members
        // -------------------------------------------
        std::string m_host;
        host_info_t m_host_info;
        std::string m_cmd_line;
        std::string m_result;
        int32_t m_status;
        uint16_t m_port;

        // -------------------------------------------
        // Class methods
        // -------------------------------------------

private:
        // -------------------------------------------
        // Private methods
        // -------------------------------------------
        DISALLOW_COPY_AND_ASSIGN(cmdlet)


        // -------------------------------------------
        // Private members
        // -------------------------------------------
        // Unique id
        uint64_t m_id;
        bool m_is_resolved_flag;
        std::string m_tag;

        // -------------------------------------------
        // Class members
        // -------------------------------------------

};

//: ----------------------------------------------------------------------------
//: \details: TODO
//: ----------------------------------------------------------------------------
class cmdlet_repo
{

public:

        cmdlet *get_cmdlet(void);
        int32_t add_cmdlet(cmdlet *a_cmdlet);

        // Get the singleton instance
        static cmdlet_repo *get(void);

        uint32_t get_num_cmdlets(void) {return m_num_cmdlets;};
        uint32_t get_num_get(void) {return m_num_get;};
        bool empty(void) {return m_cmdlet_list.empty();};
        bool done(void) {return (m_num_get >= m_num_cmdlets);};
        void up_done(bool a_error) { ++m_num_done; if(a_error)++m_num_error;};
        void up_resolved(bool a_error) {if(a_error)++m_num_error; else ++m_num_resolved;};
        void display_status_line(bool a_color);
        void dump_all_results(bool a_color);
        cmdlet *try_get_resolved(void);

private:
        DISALLOW_COPY_AND_ASSIGN(cmdlet_repo)
        cmdlet_repo();

        cmdlet_list_t m_cmdlet_list;
        cmdlet_list_t::iterator m_cmdlet_list_iter;
        pthread_mutex_t m_mutex;
        uint32_t m_num_cmdlets;
        uint32_t m_num_get;
        uint32_t m_num_done;
        uint32_t m_num_resolved;
        uint32_t m_num_error;


        // -------------------------------------------------
        // Class members
        // -------------------------------------------------
        // the pointer to the singleton for the instance
        static cmdlet_repo *m_singleton_ptr;

};

#endif


