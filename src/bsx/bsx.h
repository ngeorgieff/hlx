//: ----------------------------------------------------------------------------
//: Copyright (C) 2014 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    hle.h
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
#ifndef _BSX_H
#define _BSX_H


//: ----------------------------------------------------------------------------
//: Includes
//: ----------------------------------------------------------------------------
#include "evr.h"
#include "ndebug.h"

#include <stdint.h>
#include <string>
#include <list>
#include <map>


//: ----------------------------------------------------------------------------
//: Constants
//: ----------------------------------------------------------------------------
// Version
#define BSX_VERSION_MAJOR 0
#define BSX_VERSION_MINOR 0
#define BSX_VERSION_MACRO 1
#define BSX_VERSION_PATCH "alpha"

#define BSX_DEFAULT_CONN_TIMEOUT_S 30


//: ----------------------------------------------------------------------------
//: Macros
//: ----------------------------------------------------------------------------

//: ----------------------------------------------------------------------------
//: Enums
//: ----------------------------------------------------------------------------


//: ----------------------------------------------------------------------------
//: Types
//: ----------------------------------------------------------------------------


//: ----------------------------------------------------------------------------
//: Fwd Decl's
//: ----------------------------------------------------------------------------
class t_client;
typedef std::list <std::string> host_list_t;
typedef std::list <t_client *> t_client_list_t;
typedef std::map <std::string, std::string> header_map_t;

struct ssl_ctx_st;
typedef ssl_ctx_st SSL_CTX;

//: ----------------------------------------------------------------------------
//: \details: TODO
//: ----------------------------------------------------------------------------
class bsx
{
public:
        // -------------------------------------------------
        // Public methods
        // -------------------------------------------------
        int32_t init();

        ~bsx();

        void set_verbose(bool a_val) { m_verbose = a_val;}
        void set_color(bool a_val) { m_color = a_val;}
        void set_quiet(bool a_val) { m_quiet = a_val;}
        void set_exec_line(std::string a_exec_line) {m_exec_line = a_exec_line;}
        void set_sock_opt_recv_buf_size(uint32_t a_val) {m_sock_opt_recv_buf_size = a_val;}
        void set_sock_opt_send_buf_size(uint32_t a_val) {m_sock_opt_send_buf_size = a_val;}
        void set_sock_opt_no_delay(bool a_val) {m_sock_opt_no_delay = a_val;}
        void set_event_handler_type(evr_loop_type_t a_val) {m_evr_loop_type = a_val;}
        void set_start_parallel(int32_t a_val) {m_start_parallel = a_val;}
        void set_num_threads(uint32_t a_val) {m_num_threads = a_val;}
        void set_timeout_s(int32_t a_val) {m_timeout_s = a_val;}
        void set_user(const std::string &a_user) {m_user = a_user;}
        void set_password(const std::string &a_password) {m_password = a_password;}
        void set_public_key_file(const std::string &a_public_key_file) {m_public_key_file = a_public_key_file;}
        void set_private_key_file(const std::string &a_private_key_file) {m_private_key_file = a_private_key_file;}

        // Running...
        int32_t run(host_list_t &a_host_list);

        int32_t stop(void);
        int32_t wait_till_stopped(void);
        bool is_running(void);

        // -------------------------------------------------
        // Class methods
        // -------------------------------------------------
        // Get the singleton instance
        static bsx *get(void);

        // -------------------------------------------------
        // Public members
        // -------------------------------------------------
        t_client_list_t m_t_client_list;

private:
        // -------------------------------------------------
        // Private methods
        // -------------------------------------------------
        DISALLOW_COPY_AND_ASSIGN(bsx)
        bsx();

        // -------------------------------------------------
        // Private members
        // -------------------------------------------------
        bool m_is_initd;

        // -------------------------------------------------
        // Settings
        // -------------------------------------------------
        bool m_verbose;
        bool m_color;
        bool m_quiet;
        uint32_t m_sock_opt_recv_buf_size;
        uint32_t m_sock_opt_send_buf_size;
        bool m_sock_opt_no_delay;
        evr_loop_type_t m_evr_loop_type;
        int32_t m_start_parallel;
        uint32_t m_num_threads;
        std::string m_exec_line;
        uint32_t m_timeout_s;

        // Authentication
        std::string m_user;
        std::string m_password;
        std::string m_public_key_file;
        std::string m_private_key_file;

        // -------------------------------------------------
        // Class members
        // -------------------------------------------------
        // the pointer to the singleton for the instance 
        static bsx *m_singleton_ptr;

};


#endif


