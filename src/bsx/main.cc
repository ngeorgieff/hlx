//: ----------------------------------------------------------------------------
//: Copyright (C) 2014 Verizon.  All Rights Reserved.
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
#include "bsx.h"
#include "util.h"
#include "cmdlet.h"
#include "ndebug.h"
#include "resolver.h"

#include <string.h>

// getrlimit
#include <sys/time.h>
#include <sys/resource.h>

// signal
#include <signal.h>

// Shared pointer
//#include <tr1/memory>

#include <list>
#include <algorithm>

#include <stdio.h>
#include <stdlib.h>
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
#define ENABLE_PROFILER 1
#ifdef ENABLE_PROFILER
#include <google/profiler.h>
#endif

//: ----------------------------------------------------------------------------
//: Constants
//: ----------------------------------------------------------------------------
#define NB_ENABLE  1
#define NB_DISABLE 0

#define MAX_READLINE_SIZE 1024

//: ----------------------------------------------------------------------------
//: Types
//: ----------------------------------------------------------------------------


//: ----------------------------------------------------------------------------
//: Settings
//: ----------------------------------------------------------------------------
typedef struct settings_struct
{
        bool m_verbose;
        bool m_color;
        bool m_quiet;
        bool m_show_stats;

        // ---------------------------------
        // Defaults...
        // ---------------------------------
        settings_struct() :
                m_verbose(false),
                m_color(false),
                m_quiet(false),
                m_show_stats(false)
        {}

} settings_struct_t;

// ---------------------------------------------------------
// Structure of arguments to pass to client thread
// ---------------------------------------------------------
typedef struct thread_args_struct
{
        t_client_list_t m_t_client_list;
        settings_struct m_settings;

        thread_args_struct() :
                m_t_client_list(),
                m_settings()
        {};

} thread_args_struct_t;

//: ----------------------------------------------------------------------------
//: Forward Decls
//: ----------------------------------------------------------------------------
void command_exec(thread_args_struct_t &a_thread_args);
int32_t add_line(FILE *a_file_ptr, host_list_t &a_host_list);

//: ----------------------------------------------------------------------------
//: \details: Print the version.
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
bool g_test_finished = false;
bool g_cancelled = false;

void sig_handler(int signo)
{
  if (signo == SIGINT)
  {
          // Kill program
          //NDBG_PRINT("SIGINT\n");
          g_test_finished = true;
          g_cancelled = true;
          bsx::get()->stop();
  }
}

//: ----------------------------------------------------------------------------
//: \details: Print the version.
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
void print_version(FILE* a_stream, int a_exit_code)
{

        // print out the version information
        fprintf(a_stream, "bsx Bulk SSH Exec.\n");
        fprintf(a_stream, "Copyright (C) 2014 Verizon.\n");
        fprintf(a_stream, "               Version: %d.%d.%d.%s\n",
                        BSX_VERSION_MAJOR,
                        BSX_VERSION_MINOR,
                        BSX_VERSION_MACRO,
                        BSX_VERSION_PATCH);
        exit(a_exit_code);

}


//: ----------------------------------------------------------------------------
//: \details: Print the command line help.
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
void print_usage(FILE* a_stream, int a_exit_code)
{
        fprintf(a_stream, "Usage: bsx host [options]\n");
        fprintf(a_stream, "Options are:\n");
        fprintf(a_stream, "  -h, --help           Display this help and exit.\n");
        fprintf(a_stream, "  -v, --version        Display the version number and exit.\n");
        fprintf(a_stream, "  \n");

        fprintf(a_stream, "Exec Options -or without parameter\n");
        fprintf(a_stream, "  -X, --exec           Execute line -REQUIRED.\n");
        fprintf(a_stream, "  \n");

        fprintf(a_stream, "Authentication Options\n");
        fprintf(a_stream, "  -i, --identity       Private key.\n");
        fprintf(a_stream, "                       Note will generate .pub version in /tmp if no <identity>.pub found.\n");
        fprintf(a_stream, "  -u, --user           User -will prompt for password if no key provided.\n");
        fprintf(a_stream, "  \n");

        fprintf(a_stream, "Hostname Input Options -also STDIN:\n");
        fprintf(a_stream, "  -f, --host_file      Host name file.\n");
        fprintf(a_stream, "  -x, --execute        Script to execute to get host names.\n");
        fprintf(a_stream, "  \n");

        fprintf(a_stream, "Settings:\n");
        fprintf(a_stream, "  -p, --parallel       Num parallel.\n");
        fprintf(a_stream, "  -t, --threads        Number of parallel threads.\n");
        fprintf(a_stream, "  -T, --timeout        Timeout (seconds).\n");
        fprintf(a_stream, "  -R, --recv_buffer    Socket receive buffer size.\n");
        fprintf(a_stream, "  -S, --send_buffer    Socket send buffer size.\n");
        fprintf(a_stream, "  -D, --no_delay       Socket TCP no-delay.\n");
        fprintf(a_stream, "  -A, --ai_cache       Path to Address Info Cache (DNS lookup cache).\n");
        fprintf(a_stream, "  \n");

        fprintf(a_stream, "Print Options:\n");
        fprintf(a_stream, "  -r, --verbose        Verbose logging\n");
        fprintf(a_stream, "  -c, --color          Color\n");
        fprintf(a_stream, "  -q, --quiet          Suppress output\n");
        fprintf(a_stream, "  -s, --show_progress  Show progress\n");
        fprintf(a_stream, "  \n");

        //fprintf(a_stream, "Output Options: -defaults to line delimited\n");
        //fprintf(a_stream, "  \n");

        fprintf(a_stream, "Debug Options:\n");
        fprintf(a_stream, "  -G, --gprofile       Google profiler output file\n");

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
        // Get hlo instance
        bsx *l_bsx = bsx::get();

        // -------------------------------------------
        // Get args...
        // -------------------------------------------
        char l_opt;
        std::string l_argument;
        int l_option_index = 0;
        struct option l_long_options[] =
                {
                { "help",           0, 0, 'h' },
                { "version",        0, 0, 'v' },
                { "exec",           1, 0, 'X' },
                { "identity",       1, 0, 'i' },
                { "user",           1, 0, 'u' },
                { "host_file",      1, 0, 'f' },
                { "execute",        1, 0, 'x' },
                { "parallel",       1, 0, 'p' },
                { "threads",        1, 0, 't' },
                { "timeout",        1, 0, 'T' },
                { "recv_buffer",    1, 0, 'R' },
                { "send_buffer",    1, 0, 'S' },
                { "no_delay",       1, 0, 'D' },
                { "ai_cache",       1, 0, 'A' },
                { "verbose",        0, 0, 'r' },
                { "color",          0, 0, 'c' },
                { "quiet",          0, 0, 'q' },
                { "show_progress",  0, 0, 's' },
                { "gprofile",       1, 0, 'G' },

                // list sentinel
                { 0, 0, 0, 0 }
        };

        settings_struct_t l_settings;
        thread_args_struct_t l_thread_args;

        std::string l_gprof_file;
        std::string l_execute_line;
        std::string l_host_file_str;
        std::string l_exec_line;
        std::string l_ai_cache;
        std::string l_identity_file;
        std::string l_username;

        // -------------------------------------------------
        // Args...
        // -------------------------------------------------
        char l_short_arg_list[] = "hvX:i:u:f:x:p:t:T:R:S:DA:rcqsG:";
        while ((l_opt = getopt_long_only(argc, argv, l_short_arg_list, l_long_options, &l_option_index)) != -1)
        {

                if (optarg)
                        l_argument = std::string(optarg);
                else
                        l_argument.clear();
                //NDBG_PRINT("arg[%c=%d]: %s\n", l_opt, l_option_index, l_argument.c_str());

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
                case 'v':
                {
                        print_version(stdout, 0);
                        break;
                }

                // ---------------------------------------
                // Exec line
                // ---------------------------------------
                case 'X':
                {
                        l_exec_line = l_argument;
                        break;
                }

                // ---------------------------------------
                // Identity line
                // ---------------------------------------
                case 'i':
                {
                        l_identity_file = l_argument;
                        break;
                }

                // ---------------------------------------
                // username
                // ---------------------------------------
                case 'u':
                {
                        l_username = l_argument;
                        break;
                }
                // ---------------------------------------
                // Host file
                // ---------------------------------------
                case 'f':
                {
                        l_host_file_str = l_argument;
                        break;
                }


                // ---------------------------------------
                // Execute line
                // ---------------------------------------
                case 'x':
                {
                        l_execute_line = l_argument;
                        break;
                }

                // ---------------------------------------
                // parallel
                // ---------------------------------------
                case 'p':
                {
                        int l_start_parallel = 1;
                        //NDBG_PRINT("arg: --parallel: %s\n", optarg);
                        //l_settings.m_start_type = START_PARALLEL;
                        l_start_parallel = atoi(optarg);
                        if (l_start_parallel < 1)
                        {
                                printf("parallel must be at least 1\n");
                                print_usage(stdout, -1);
                        }
                        l_bsx->set_start_parallel(l_start_parallel);
                        break;
                }

                // ---------------------------------------
                // num threads
                // ---------------------------------------
                case 't':
                {
                        int l_max_threads = 1;
                        //NDBG_PRINT("arg: --threads: %s\n", l_argument.c_str());
                        l_max_threads = atoi(optarg);
                        if (l_max_threads < 1)
                        {
                                printf("num-threads must be at least 1\n");
                                print_usage(stdout, -1);
                        }

                        l_bsx->set_num_threads(l_max_threads);
                        break;
                }

                // ---------------------------------------
                // Timeout
                // ---------------------------------------
                case 'T':
                {
                        int l_timeout_s = -1;
                        //NDBG_PRINT("arg: --threads: %s\n", l_argument.c_str());
                        l_timeout_s = atoi(optarg);
                        if (l_timeout_s < 1)
                        {
                                printf("connection timeout must be at least 1\n");
                                print_usage(stdout, -1);
                        }

                        l_bsx->set_timeout_s(l_timeout_s);
                        break;
                }

                // ---------------------------------------
                // sock_opt_recv_buf_size
                // ---------------------------------------
                case 'R':
                {
                        int l_sock_opt_recv_buf_size = atoi(optarg);
                        // TODO Check value...
                        l_bsx->set_sock_opt_recv_buf_size(l_sock_opt_recv_buf_size);
                        break;
                }

                // ---------------------------------------
                // sock_opt_send_buf_size
                // ---------------------------------------
                case 'S':
                {
                        int l_sock_opt_send_buf_size = atoi(optarg);
                        // TODO Check value...
                        l_bsx->set_sock_opt_send_buf_size(l_sock_opt_send_buf_size);
                        break;
                }

                // ---------------------------------------
                // No delay
                // ---------------------------------------
                case 'D':
                {
                        l_bsx->set_sock_opt_no_delay(true);
                        break;
                }

                // ---------------------------------------
                // Address Info cache
                // ---------------------------------------
                case 'A':
                {
                        l_ai_cache = l_argument;
                        break;
                }

                // ---------------------------------------
                // verbose
                // ---------------------------------------
                case 'r':
                {
                        l_settings.m_verbose = true;
                        l_bsx->set_verbose(true);
                        break;
                }

                // ---------------------------------------
                // color
                // ---------------------------------------
                case 'c':
                {
                        l_settings.m_color = true;
                        l_bsx->set_color(true);
                        break;
                }

                // ---------------------------------------
                // quiet
                // ---------------------------------------
                case 'q':
                {
                        l_settings.m_quiet = true;
                        l_bsx->set_quiet(true);
                        break;
                }

                // ---------------------------------------
                // show progress
                // ---------------------------------------
                case 's':
                {
                        l_settings.m_show_stats = true;
                        break;
                }

                // ---------------------------------------
                // Google Profiler Output File
                // ---------------------------------------
                case 'G':
                {
                        l_gprof_file = l_argument;
                        break;
                }

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
        if(l_exec_line.empty())
        {
                fprintf(stdout, "No exec line specified.\n");
                print_usage(stdout, -1);
        }
        // else set url
        l_bsx->set_exec_line(l_exec_line);

        host_list_t l_host_list;
        // -------------------------------------------------
        // Host list processing
        // -------------------------------------------------
        // Read from command
        if(!l_execute_line.empty())
        {
                FILE *fp;
                int32_t l_status = STATUS_OK;

                fp = popen(l_execute_line.c_str(), "r");
                // Error executing...
                if (fp == NULL)
                {
                }

                l_status = add_line(fp, l_host_list);
                if(STATUS_OK != l_status)
                {
                        return STATUS_ERROR;
                }

                l_status = pclose(fp);
                // Error reported by pclose()
                if (l_status == -1)
                {
                        printf("Error: performing pclose\n");
                        return STATUS_ERROR;
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
                int32_t l_status = STATUS_OK;

                l_file = fopen(l_host_file_str.c_str(),"r");
                if (NULL == l_file)
                {
                        printf("Error opening file: %s.  Reason: %s\n", l_host_file_str.c_str(), strerror(errno));
                        return STATUS_ERROR;
                }

                l_status = add_line(l_file, l_host_list);
                if(STATUS_OK != l_status)
                {
                        return STATUS_ERROR;
                }

                //NDBG_PRINT("ADD_FILE: DONE: %s\n", a_url_file.c_str());

                l_status = fclose(l_file);
                if (0 != l_status)
                {
                        NDBG_PRINT("Error performing fclose.  Reason: %s\n", strerror(errno));
                        return STATUS_ERROR;
                }
        }
        // Read from stdin
        else
        {
                int32_t l_status = STATUS_OK;
                l_status = add_line(stdin, l_host_list);
                if(STATUS_OK != l_status)
                {
                        return STATUS_ERROR;
                }
        }

        if(l_settings.m_verbose)
        {
                NDBG_PRINT("Showing hostname list:\n");
                //for(host_list_t::iterator i_host = l_host_list.begin(); i_host != l_host_list.end(); ++i_host)
                //{
                //        NDBG_OUTPUT("%s\n", i_host->c_str());
                //}
        }

        // -------------------------------------------------
        // Authentication processing
        // -------------------------------------------------
        // TODO CRAP!!!
        l_bsx->set_user(std::string(""));
        l_bsx->set_password(std::string(""));
        l_bsx->set_public_key_file(std::string(""));
        l_bsx->set_private_key_file(std::string(""));

        // -------------------------------------------
        // Sigint handler
        // -------------------------------------------
        if (signal(SIGINT, sig_handler) == SIG_ERR)
        {
                printf("Error: can't catch SIGINT\n");
                return STATUS_ERROR;
        }
        // TODO???
        //signal(SIGPIPE, SIG_IGN);

        // -------------------------------------------
        // Init resolver with cache
        // -------------------------------------------
        int32_t l_ldb_init_status;
        l_ldb_init_status = resolver::get()->init(l_ai_cache, true);
        if(STATUS_OK != l_ldb_init_status)
        {
                return STATUS_ERROR;
        }

        // Start Profiler
        if (!l_gprof_file.empty())
        {
                ProfilerStart(l_gprof_file.c_str());
        }

        // Run
        int32_t l_run_status = 0;
        l_run_status = l_bsx->run(l_host_list);
        if(0 != l_run_status)
        {
                printf("Error: performing bsx::run");
                return STATUS_ERROR;
        }

        //uint64_t l_start_time_ms = get_time_ms();

        // -------------------------------------------
        // Run command exec
        // -------------------------------------------
        // Copy in settings
        l_thread_args.m_settings = l_settings;
        command_exec(l_thread_args);

        if(l_settings.m_verbose)
        {
                printf("Finished -joining all threads\n");
        }

        // Wait for completion
        l_bsx->wait_till_stopped();

        if (!l_gprof_file.empty())
        {
                ProfilerStop();
        }

        //uint64_t l_end_time_ms = get_time_ms() - l_start_time_ms;

        // -------------------------------------------
        // Results...
        // -------------------------------------------
        if(!g_cancelled)
        {
                cmdlet_repo::get()->dump_all_results();
        }

        // -------------------------------------------
        // Cleanup...
        // -------------------------------------------
        // TODO

        //if(l_settings.m_verbose)
        //{
        //      NDBG_PRINT("Cleanup\n");
        //}

        return 0;

}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int kbhit()
{
        struct timeval tv;
        fd_set fds;
        tv.tv_sec = 0;
        tv.tv_usec = 0;
        FD_ZERO(&fds);
        FD_SET(STDIN_FILENO, &fds);
        //STDIN_FILENO is 0
        select(STDIN_FILENO + 1, &fds, NULL, NULL, &tv);
        return FD_ISSET(STDIN_FILENO, &fds);
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
void command_exec(thread_args_struct_t &a_thread_args)
{
        int i = 0;
        char l_cmd = ' ';
        bool l_sent_stop = false;
        bsx *l_bsx = bsx::get();
        //bool l_first_time = true;

        nonblock(NB_ENABLE);

        cmdlet_repo *l_cmdlet_repo = cmdlet_repo::get();

        //: ------------------------------------
        //:   Loop forever until user quits
        //: ------------------------------------
        while (!g_test_finished)
        {
                i = kbhit();
                if (i != 0)
                {

                        l_cmd = fgetc(stdin);

                        switch (l_cmd)
                        {

                        // Quit -only works when not reading from stdin
                        case 'q':
                        {
                                g_test_finished = true;
                                g_cancelled = true;
                                l_bsx->stop();
                                l_sent_stop = true;
                                break;
                        }

                        // Default
                        default:
                        {
                                break;
                        }
                        }
                }

                // TODO add define...
                usleep(200000);

                if(a_thread_args.m_settings.m_show_stats)
                {
                        l_cmdlet_repo->display_status_line(a_thread_args.m_settings.m_color);
                }

                if (!l_bsx->is_running())
                {
                        //NDBG_PRINT("IS NOT RUNNING.\n");
                        g_test_finished = true;
                }

        }

        // Send stop -if unsent
        if(!l_sent_stop)
        {
                l_bsx->stop();
                l_sent_stop = true;
        }

        nonblock(NB_DISABLE);

}

//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t add_line(FILE *a_file_ptr, host_list_t &a_host_list)
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
                        return STATUS_ERROR;
                }
                // read full line
                // Nuke endline
                l_readline[l_readline_len - 1] = '\0';
                std::string l_string(l_readline);
                l_string.erase( std::remove_if( l_string.begin(), l_string.end(), ::isspace ), l_string.end() );
                if(!l_string.empty())
                        a_host_list.push_back(l_string);
                //NDBG_PRINT("READLINE: %s\n", l_readline);
        }

        return STATUS_OK;
}
