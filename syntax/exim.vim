" Vim syntax file
" Language: Exim4 configuration file exim.conf
" Maintainer: David Ne\v{c}as (Yeti) <yeti@physics.muni.cz>
" Last Change: 2004-02-06
" URL: http://trific.ath.cx/Ftp/vim/syntax/exim.vim
" Required Vim Version: 6.0

" Note: The numbers and names are references to Exim specification chapters
"       and sections mentioning a particular construct or keyword.

" Setup {{{
" React to possibly already-defined syntax.
" For version 5.x: Clear all syntax items unconditionally
" For version 6.x: Quit when a syntax file was already loaded
if version >= 600
  if exists("b:current_syntax")
    finish
  endif
else
  syntax clear
endif

syn case match
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""" }}}
" Base constructs {{{
" 6.2. Configuration file format
syn match eximComment "^\s*#.*$" contains=eximFixme
syn keyword eximFixme FIXME TODO XXX NOT contained
" 6.7 Boolean options
syn keyword eximConstant true false yes no
" 6.6. Common option syntax
syn keyword eximHide hide
" 6.8. Integer values
" 6.9. Octal integer values
syn match eximNumber "\<\d\+[KM]\=\>"
syn match eximNumber "\<0[xX]\x\+\>"
" 6.10. Fixed point number values
syn match eximNumber "\<\d\+\(\.\d\{,3}\)\=\>"
" 6.11. Time interval values
syn match eximTime "\<\(\d\+[wdhms]\)\+\>"
syn match eximSpecialChar "\\[\\nrtN]\|\\\o\{1,3}\|\\x\x\{1,2}"
syn match eximListChanger "=\s*\zs<."
syn match eximLineContinuation "\\$"
" 6.16. Format of driver configurations
" (also ACL)
syn match eximDriver "^\s*\i\+:"
" 10.5. Named lists
syn match eximListReference "+\i\+\>"
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""" }}}
" 11. String expansions {{{
syn match eximVariableReference "\$\i\+"
syn match eximVariableReference "\$header_[-a-zA-Z0-9_]\+\>"
syn region eximBracedGroup matchgroup=eximSpecialChar start="\$\={" end="}" transparent contains=TOP
" 11.4 Expansion items
" 11.5 Expansion operators
syn match eximStringOperation "{\@<=\K[-a-zA-Z0-9_]*\>" transparent contained containedin=eximBracedGroup contains=eximStringOperationName,eximExpansionVariable
syn keyword eximStringOperationName address base62 domain escape eval expand from_utf8 h hash hex2b64 lc l length local_part mask md5 nhash rxquote rfc2047 sha1 stat s strlen substr uc contained
syn keyword eximStringOperationName extract hash hmac length lookup nhash perl readfile readsocket run sg substr tr contained
syn match eximStringOperationName "\<if\>" contained nextgroup=eximOperationConditionName skipwhite
syn match eximStringOperationName "\<r\=h\(eader\)\=_[-a-zA-Z0-9_]\+\>"
syn keyword eximStringOperationName quote quote_cdb quote_dbm[nz] quote_dsearch quote_lsearch quote_nis[plus] quote_wildlsearch quote_dnsdb quote_ldap[dn] quote_ldapm quote_local_part quote_mysql quote_nisplus quote_oracle quote_passwd quote_pgsql quote_testdb quote_whoson contained
syn match eximStringOperationName "\<\(n\=hash\|substr\)\(_-\=\d\+\)\{1,2}\>" contained
syn match eximStringOperationName "\<length_-\=\d\+\>" contained
" 11.6 Expansion conditions
syn keyword eximOperationConditionName crypteq def eq eqi exists first_delivery ldpauth match pam pwcheck queue_running radius contained containedin=eximBracedGroup
" 11.7 Combining expansion conditions
syn keyword eximOperationConditionName or and contained containedin=eximBracedGroup
" 11.8 Expansion variables
" XXX: unused
syn match eximExpansionVariable "acl_[cm]\d\|s\=n\d\|\d" contained
syn keyword eximExpansionVariable acl_verify_message address_data address_file address_pipe authenticated_id authenticated_sender authentication_failed contained
syn keyword eximExpansionVariable body_linecount bounce_recipient caller_gid caller_uid compile_date compile_number contained
syn keyword eximExpansionVariable dnslist_domain dnslist_text dnslist_value domain domain_data domain_data home contained
syn keyword eximExpansionVariable host host_address host_data host_lookup_failed inode interface_address interface_port ldap_dn load_average contained
syn keyword eximExpansionVariable local_part local_part_data local_part_prefix local_part_suffix local_scan_data localhost_number contained
syn keyword eximExpansionVariable message_age message_body message_body_end message_body_size message_headers message_id message_size contained
syn keyword eximExpansionVariable original_domain original_local_part originator_gid originator_uid parent_domain parent_local_part pid pipe_addresses primary_hostname qualify_domain qualify_recipient contained
syn keyword eximExpansionVariable rcpt_count rcpt_defer_count rcpt_fail_count received_for received_protocol recipients recipients_count reply_address return_path return_size_limit runrc self_hostname contained
syn keyword eximExpansionVariable sender_address sender_address_domain sender_address_local_part sender_fullhost sender_helo_name sender_host_address sender_host_authenticated sender_host_name sender_host_port sender_ident sender_rcvhost contained
syn keyword eximExpansionVariable smtp_command_argument spool_directory thisaddress tls_certificate_verified tls_cipher tls_peerdn contained
syn keyword eximExpansionVariable tod_bsdinbox tod_epoch tod_full tod_log tod_logfile tod_zone tod_zulu value version_number warn_message_delay warn_message_recipients contained
" Exim 4.30
syn keyword eximExpansionVariable mailstore_basename local_user_uid local_user_gid received_count contained
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""" }}}
" 6. The Exim run time configuration file {{{
" 6.2. Configuration file format
syn match eximSection "^\s*begin\>" nextgroup=eximSectionName skipwhite
syn keyword eximSectionName acl authenticators routers transports retry rewrite local_scan contained
syn region eximRewriteSection start="\s*begin\s\+rewrite" end="^\ze\s*begin\>" end="\%$" contains=TOP,eximOption
syn region eximRetrySection start="\s*begin\s\+retry" end="^\ze\s*begin\>" end="\%$" contains=TOP,eximOption
" 6.3. File inclusions in the configuration file
syn match eximInclude "^\s*.include\(_if_exists\)\?\>"
" 6.4. Macros in the configuration file
syn region eximMacroDefinition matchgroup=eximMacroName start="^[A-Z]\i*\s*=" end="$" skip="\\\s*$" transparent contains=TOP
" 6.5. Conditional skips in the configuration file
syn match eximIfThen "^\s*.\(ifdef\|ifndef\|endifdef\|elifndef\|else\|endif\)\>"
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""" }}}
" 9. File and databasae lookups {{{
syn keyword eximLookupType cdb dbm[nz] dsearch lsearch nis wildlsearch
syn keyword eximLookupType dnsdb ldap[dn] ldapm mysql nisplus oracle passwd pgsql testdb whoson
" The contains= is to fool keyword-before-match matching order
syn match eximLookupType "\<partial\d\=\(-\|([^)]*)\)\(cdb\|dbm\|dbmnz\|dsearch\|lsearch\|nis\|wildlsearch\)\>" contains=eximLookupType
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""" }}}
" 10. Domain, Host, Address, and Local Part lists {{{
syn match eximListDefinition "^\s*\(domain\|host\|address\|localpart\)list\>" nextgroup=eximListName skipwhite
syn match eximListName "\i\+" contained
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""" }}}
" 13. Main configuration {{{
" 13.1 Miscellaneous
syn keyword eximOption bi_command keep_malformed localhost_number message_body_visible timezone
syn keyword eximOption message_logs no_message_logs not_message_logs
syn keyword eximOption print_topbitchars no_print_topbitchars not_print_topbitchars
syn keyword eximOption split_spool_directory no_split_spool_directory not_split_spool_directory
" 13.2 Exim parameters
syn keyword eximOption exim_group exim_path exim_user primary_hostname spool_directory
" 13.3. Privilege controls
syn keyword eximOption admin_groups local_from_prefix local_from_suffix never_users trusted_groups trusted_users
syn keyword eximOption deliver_drop_privilege no_deliver_drop_privilege not_deliver_drop_privilege
syn keyword eximOption local_from_check no_local_from_check not_local_from_check
syn keyword eximOption local_sender_retain no_local_sender_retain not_local_sender_retain
syn keyword eximOption prod_requires_admin no_prod_requires_admin not_prod_requires_admin
syn keyword eximOption queue_list_requires_admin no_queue_list_requires_admin not_queue_list_requires_admin
" 13.4. Logging
syn keyword eximOption log_file_path log_selector log_timezone syslog_facility syslog_processname
syn keyword eximOption preserve_message_logs no_preserve_message_logs not_preserve_message_logs
syn keyword eximOption syslog_timestamp no_syslog_timestamp not_syslog_timestamp
" 13.5. Frozen messages
syn keyword eximOption auto_thaw freeze_tell timeout_frozen_after
syn keyword eximOption move_frozen_messages no_move_frozen_messages not_move_frozen_messages
" 13.6. Data lookups
syn keyword eximOption ldap_default_servers ldap_version lookup_open_max mysql_servers oracle_servers pgsql_servers
" 13.7. Message ids
syn keyword eximOption message_id_header_domain message_id_header_text
" 13.8. Embedded Perl Startup
syn keyword eximOption perl_startup
syn keyword eximOption perl_at_start no_perl_at_start not_perl_at_start
" 13.9. Daemon
syn keyword eximOption daemon_smtp_port local_interfaces pid_file_path
" 13.10. Resource control
syn keyword eximOption check_log_inodes check_log_space check_spool_inodes check_spool_space deliver_queue_load_max smtp_load_reserve queue_only_load
" 13.11. Policy controls
syn keyword eximOption acl_not_smtp acl_smtp_auth acl_smtp_connect acl_smtp_data acl_smtp_etrn acl_smtp_expn acl_smtp_helo acl_smtp_mail acl_smtp_rcpt acl_smtp_starttls acl_smtp_vrfy header_maxsize header_line_maxsize helo_verify_hosts host_lookup host_reject_connection hosts_treat_as_local local_scan_timeout message_size_limit percent_hack_domains host_lookup_order
" 13.12. Callout cache
syn keyword eximOption callout_domain_negative_expire callout_domain_positive_expire callout_negative_expire callout_positive_expire callout_random_local_part
" 13.13. TLS
syn keyword eximOption tls_advertise_hosts tls_certificate tls_dhparam tls_privatekey tls_try_verify_hosts tle_verify_certificates tls_verify_hosts
" 13.14. Local user handling
syn keyword eximOption finduser_retries gecos_name gecos_pattern max_username_length unknown_login unknown_username uucp_from_pattern uucp_from_sender
" 13.15. Incoming messages
syn keyword eximOption header_maxsize header_line_maxsize percent_hack_domains receive_timeout received_header_text received_headers_max recipient_unqualified_hosts recipients_max
syn keyword eximOption recipients_max_reject no_recipients_max_reject not_recipients_max_reject
" 13.16. Incoming SMTP
syn keyword eximOption rfc1413_hosts rfc1413_query_timeout sender_unqualified_hosts smtp_accept_max smtp_accept_max_nommail smtp_accept_max_nonmail_hosts smtp_accept_max_per_connection smtp_accept_max_per_host smtp_accept_queue smtp_accept_queue_per_connection smtp_accept_reserve smtp_banner smtp_connect_backlog smtp_etrn_command smtp_load_reserve smtp_max_unknown_commands smtp_ratelimit_hosts smtp_ratelimit_mail smtp_ratelimit_rcpt smtp_receive_timeout smtp_reserve_hosts smtp_return_error_details
syn keyword eximOption smtp_accept_keepalive no_smtp_accept_keepalive not_smtp_accept_keepalive
syn keyword eximOption smtp_check_spool_space no_smtp_check_spool_space not_smtp_check_spool_space
syn keyword eximOption smtp_enforce_sync no_smtp_enforce_sync not_smtp_enforce_sync
syn keyword eximOption smtp_etrn_serialize no_smtp_etrn_serialize not_smtp_etrn_serialize
" 13.17. SMTP extensions
syn keyword eximOption auth_advertise_hosts ignore_fromline_hosts pipelining_advertise_hosts tls_advertise_hosts
syn keyword eximOption accept_8bitmime no_accept_8bitmime not_accept_8bitmime
syn keyword eximOption ignore_fromline_local no_ignore_fromline_local not_ignore_fromline_local
" 13.18. Processing messages
syn keyword eximOption allow_utf8_domains qualify_domain qualify_recipient return_path_remove strip_excess_angle_brackets strip_trailing_dot untrusted_set_sender
syn keyword eximOption allow_domain_literals no_allow_domain_literals not_allow_domain_literals
syn keyword eximOption allow_mx_to_ip no_allow_mx_to_ip not_allow_mx_to_ip
syn keyword eximOption delivery_date_remove no_delivery_date_remove not_delivery_date_remove
syn keyword eximOption drop_cr no_drop_cr not_drop_cr
syn keyword eximOption envelope_to_remove no_envelope_to_remove not_envelope_to_remove
syn keyword eximOption extract_addresses_remove_arguments no_extract_addresses_remove_arguments not_extract_addresses_remove_arguments
syn keyword eximOption return_path_remove no_return_path_remove not_return_path_remove
syn keyword eximOption strip_excess_angle_brackets no_strip_excess_angle_brackets not_strip_excess_angle_brackets
syn keyword eximOption strip_trailing_dot no_strip_trailing_dot not_strip_trailing_dot
" 13.19. System filter
syn keyword eximOption system_filter system_filter_directory_transport system_filter_file_transport system_filter_group system_filter_pipe_transport system_filter_reply_transport system_filter_user
" 13.20. Routing and delivery
syn keyword eximOption dns_again_means_nonexist dns_check_names_pattern dns_ipv4_lookup dns_retrans dns_retry hold_domains local_interfaces queue_domains queue_only_file queue_only_load queue_run_max queue_smtp_domains remote_max_parallel remote_sort_domains retry_data_expire retry_interval_max
syn keyword eximOption queue_only no_queue_only not_queue_only
syn keyword eximOption queue_run_in_order no_queue_run_in_order not_queue_run_in_order
" 13.21. Bounce and warning messages
syn keyword eximOption bounce_message_file bounce_message_text bounce_sender_authentication errors_copy errors_reply_to delay_warning delay_warning_condition ignore_bounce_errors_after return_size_limit warn_message_file
syn keyword eximOption bounce_return_message no_bounce_return_message not_bounce_return_message
syn keyword eximOption bounce_return_body no_bounce_return_body not_bounce_return_body
" XXX New 4.30 keywords, belong nowhere
syn keyword eximOption tcp_nodelay no_tcp_nodelay not_tcp_nodelay
syn keyword eximOption smtp_max_synprot_errors
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""" }}}
" 14. Generic options for routers {{{
syn keyword eximOption address_data cannot_route_message condition debug_print domains driver errors_to fallback_hosts group headers_add headers_remove ignore_target_hosts local_part_prefix local_part_suffix local_parts pass_router redirect_router require_files self senders translate_ip_address transport transport_current_directory transport_home_directory user
syn keyword eximOption caseful_local_part no_caseful_local_part not_caseful_local_part
syn keyword eximOption check_local_user no_check_local_user not_check_local_user
syn keyword eximOption expn no_expn not_expn
syn keyword eximOption fail_verify no_fail_verify not_fail_verify
syn keyword eximOption fail_verify_recipient no_fail_verify_recipient not_fail_verify_recipient
syn keyword eximOption fail_verify_sender no_fail_verify_sender not_fail_verify_sender
syn keyword eximOption initgroups no_initgroups not_initgroups
syn keyword eximOption local_part_prefix_optional no_local_part_prefix_optional not_local_part_prefix_optional
syn keyword eximOption local_part_suffix_optional no_local_part_suffix_optional not_local_part_suffix_optional
syn keyword eximOption log_as_local no_log_as_local not_log_as_local
syn keyword eximOption more no_more not_more
syn keyword eximOption pass_on_timeout no_pass_on_timeout not_pass_on_timeout
syn keyword eximOption retry_use_local_part no_retry_use_local_part not_retry_use_local_part
syn keyword eximOption unseen no_unseen not_unseen
syn keyword eximOption verify no_verify not_verify
syn keyword eximOption verify_only no_verify_only not_verify_only
syn keyword eximOption verify_recipient no_verify_recipient not_verify_recipient
syn keyword eximOption verify_sender no_verify_sender not_verify_sender
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""" }}}
" 15. The accept router {{{
syn keyword eximDriverName accept
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""" }}}
" 16. The dnslookup router {{{
syn keyword eximDriverName dnslookup
syn keyword eximOption mx_domains widen_domains
syn keyword eximOption check_secondary_mx no_check_secondary_mx not_check_secondary_mx
syn keyword eximOption qualify_single no_qualify_single not_qualify_single
syn keyword eximOption rewrite_headers no_rewrite_headers not_rewrite_headers
syn keyword eximOption same_domain_copy_routing no_same_domain_copy_routing not_same_domain_copy_routing
syn keyword eximOption search_parents no_search_parents not_search_parents
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""" }}}
" 17. The ipliteral router {{{
syn keyword eximDriverName ipliteral
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""" }}}
" 18. The iplookup router {{{
syn keyword eximDriverName iplookup
syn keyword eximOption hosts port protocol query reroute response_pattern timeout
syn keyword eximOption optional no_optional not_optional
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""" }}}
" 19. The manualroute router {{{
syn keyword eximDriverName manualroute
syn keyword eximOption host_find_failed route_data route_list
syn keyword eximOption hosts_randomize no_hosts_randomize not_hosts_randomize
syn keyword eximOption same_domain_copy_routing no_same_domain_copy_routing not_same_domain_copy_routing
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""" }}}
" 20. The queryprogram router {{{
syn keyword eximDriverName queryprogram
syn keyword eximOption command command_group command_user current_directory timeout
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""" }}}
" 21. The redirect router {{{
syn keyword eximDriverName redirect
syn keyword eximOption data directory_transport file file_transport include_directory modemask owners owngroups pipe_transport reply_transport syntax_errors_text syntax_errors_to
syn keyword eximOption allow_defer no_allow_defer not_allow_defer
syn keyword eximOption allow_fail no_allow_fail not_allow_fail
syn keyword eximOption allow_filter no_allow_filter not_allow_filter
syn keyword eximOption allow_freeze no_allow_freeze not_allow_freeze
syn keyword eximOption check_ancestor no_check_ancestor not_check_ancestor
syn keyword eximOption check_group no_check_group not_check_group
syn keyword eximOption check_owner no_check_owner not_check_owner
syn keyword eximOption forbid_blackhole no_forbid_blackhole not_forbid_blackhole
syn keyword eximOption forbid_file no_forbid_file not_forbid_file
syn keyword eximOption forbid_filter_existstest no_forbid_filter_existstest not_forbid_filter_existstest
syn keyword eximOption forbid_filter_logwrite no_forbid_filter_logwrite not_forbid_filter_logwrite
syn keyword eximOption forbid_filter_lookup no_forbid_filter_lookup not_forbid_filter_lookup
syn keyword eximOption forbid_filter_perl no_forbid_filter_perl not_forbid_filter_perl
syn keyword eximOption forbid_filter_readfile no_forbid_filter_readfile not_forbid_filter_readfile
syn keyword eximOption forbid_filter_reply no_forbid_filter_reply not_forbid_filter_reply
syn keyword eximOption forbid_filter_run no_forbid_filter_run not_forbid_filter_run
syn keyword eximOption forbid_include no_forbid_include not_forbid_include
syn keyword eximOption forbid_pipe no_forbid_pipe not_forbid_pipe
syn keyword eximOption hide_child_in_errmsg no_hide_child_in_errmsg not_hide_child_in_errmsg
syn keyword eximOption ignore_eacces no_ignore_eacces not_ignore_eacces
syn keyword eximOption ignore_enotdir no_ignore_enotdir not_ignore_enotdir
syn keyword eximOption one_time no_one_time not_one_time
syn keyword eximOption qualify_preserve_domain no_qualify_preserve_domain not_qualify_preserve_domain
syn keyword eximOption repeat_use no_repeat_use not_repeat_use
syn keyword eximOption rewrite no_rewrite not_rewrite
syn keyword eximOption skip_syntax_errors no_skip_syntax_errors not_skip_syntax_errors
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""" }}}
" 23. Generic options for transports {{{
syn keyword eximOption current_directory debug_print driver group headers_add headers_remove headers_rewrite home_directory message_size_limit return_path shadow_condition shadow_transport transport_filter user
syn keyword eximOption body_only no_body_only not_body_only
syn keyword eximOption delivery_date_add no_delivery_date_add not_delivery_date_add
syn keyword eximOption envelope_to_add no_envelope_to_add not_envelope_to_add
syn keyword eximOption headers_only no_headers_only not_headers_only
syn keyword eximOption initgroups no_initgroups not_initgroups
syn keyword eximOption retry_use_local_part no_retry_use_local_part not_retry_use_local_part
syn keyword eximOption return_path_add no_return_path_add not_return_path_add
syn keyword eximOption transport_filter_timeout
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""" }}}
" 25. The appendfile transport {{{
syn keyword eximDriverName appendfile
syn keyword eximOption batch_id batch_max check_string create_file directory directory_file directory_mode escape_string file file_format lock_fcntl_timeout lock_interval lock_retries lockfile_mode lockfile_timeout maildir_retries maildir_tag mailstore_prefix mailstore_suffix message_prefix message_suffix mode quota quota_filecount quota_size_regex quota_warn_message quota_warn_threshold
syn keyword eximOption allow_fifo no_allow_fifo not_allow_fifo
syn keyword eximOption allow_symlink no_allow_symlink not_allow_symlink
syn keyword eximOption check_group no_check_group not_check_group
syn keyword eximOption check_owner no_check_owner not_check_owner
syn keyword eximOption create_directory no_create_directory not_create_directory
syn keyword eximOption file_must_exist no_file_must_exist not_file_must_exist
syn keyword eximOption maildir_format no_maildir_format not_maildir_format
syn keyword eximOption mailstore_format no_mailstore_format not_mailstore_format
syn keyword eximOption mbx_format no_mbx_format not_mbx_format
syn keyword eximOption mode_fail_narrower no_mode_fail_narrower not_mode_fail_narrower
syn keyword eximOption notify_comsat no_notify_comsat not_notify_comsat
syn keyword eximOption quota_is_inclusive no_quota_is_inclusive not_quota_is_inclusive
syn keyword eximOption use_bsmtp no_use_bsmtp not_use_bsmtp
syn keyword eximOption use_crlf no_use_crlf not_use_crlf
syn keyword eximOption use_fcntl_lock no_use_fcntl_lock not_use_fcntl_lock
syn keyword eximOption use_lockfile no_use_lockfile not_use_lockfile
syn keyword eximOption use_mbx_lock no_use_mbx_lock not_use_mbx_lock
syn keyword eximOption maildir_use_size_file no_maildir_use_size_file not_maildir_use_size_file
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""" }}}
" 26. The autoreply transport {{{
syn keyword eximDriverName autoreply
syn keyword eximOption bcc cc file from headers log mode once once_file_size once_repeat reply_to subject text to
syn keyword eximOption file_expand no_file_expand not_file_expand
syn keyword eximOption file_optional no_file_optional not_file_optional
syn keyword eximOption return_message no_return_message not_return_message
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""" }}}
" 27. The lmtp transport {{{
syn keyword eximDriverName lmtp
syn keyword eximOption batch_id batch_max command timeout
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""" }}}
" 28. The pipe transport {{{
syn keyword eximDriverName pipe
syn keyword eximOption allow_commands batch_id batch_max check_string command environment escape_string max_output message_prefix message_suffix path temp_errors timeout umask
syn keyword eximOption freeze_exec_fail no_freeze_exec_fail not_freeze_exec_fail
syn keyword eximOption ignore_status no_ignore_status not_ignore_status
syn keyword eximOption log_defer_output no_log_defer_output not_log_defer_output
syn keyword eximOption log_fail_output no_log_fail_output not_log_fail_output
syn keyword eximOption log_output no_log_output not_log_output
syn keyword eximOption pipe_as_creator no_pipe_as_creator not_pipe_as_creator
syn keyword eximOption restrict_to_path no_restrict_to_path not_restrict_to_path
syn keyword eximOption return_fail_output no_return_fail_output not_return_fail_output
syn keyword eximOption return_output no_return_output not_return_output
syn keyword eximOption use_bsmtp no_use_bsmtp not_use_bsmtp
syn keyword eximOption use_crlf no_use_crlf not_use_crlf
syn keyword eximOption use_shell no_use_shell not_use_shell
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""" }}}
" 29. The smtp transport {{{
syn keyword eximDriverName smtp
syn keyword eximOption command_timeout connect_timeout connection_max_messages data_timeout fallback_hosts final_timeout helo_data hosts hosts_avoid_tls hosts_max_try hosts_nopass_tls hosts_require_auth hosts_require_tls hosts_try_auth interface max_rcpt port protocol serialize_hosts size_addition tls_certificate tls_privatekey tls_require_ciphers tls_verify_certificates
syn keyword eximOption allow_localhost no_allow_localhost not_allow_localhost
syn keyword eximOption delay_after_cutoff no_delay_after_cutoff not_delay_after_cutoff
syn keyword eximOption dns_qualify_single no_dns_qualify_single not_dns_qualify_single
syn keyword eximOption dns_search_parents no_dns_search_parents not_dns_search_parents
syn keyword eximOption gethostbyname no_gethostbyname not_gethostbyname
syn keyword eximOption hosts_override no_hosts_override not_hosts_override
syn keyword eximOption hosts_randomize no_hosts_randomize not_hosts_randomize
syn keyword eximOption keepalive no_keepalive not_keepalive
syn keyword eximOption multi_domain no_multi_domain not_multi_domain
syn keyword eximOption retry_include_ip_address no_retry_include_ip_address not_retry_include_ip_address
syn keyword eximOption tls_tempfail_tryclear no_tls_tempfail_tryclear not_tls_tempfail_tryclear
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""" }}}
" 30. Address rewritting {{{
syn match eximRewriteFlags "[EFTbcfhrstSQqrw]\+\s*$" contained containedin=eximRewriteSection
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""" }}}
" 31. Retry configuration {{{
" 31.2. Retry rules for specific errors
syn keyword eximRetryCondition auth_failed refused_MX refused_A refused timeout_connect timeout_DNS timeout contained containedin=eximRetrySection
syn keyword eximRetryCondition timeout timeout_A timeout_connect_A timeout_MX timeout_connect_MX contained containedin=eximRetrySection
syn match eximRetryCondition "\<quota\(_\d\+[wdhms]\)*\>" contained containedin=eximRetrySection
syn match eximRetryCondition "\s\zs\*\ze\s" contained containedin=eximRetrySection
" 31.3. Retry rule parameters
syn match eximRetryLetter "\<[FG]\ze\s*," contained containedin=eximRetrySection
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""" }}}
" 32. SMTP authentication {{{
" 32.1. Generic options for authenticators
syn keyword eximOption driver public_name server_advertise_condition server_debug_print server_set_id server_mail_auth_condition
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""" }}}
" 33. The plaintext authenticator {{{
syn keyword eximDriverName plaintext
syn keyword eximOption server_prompts server_condition
syn keyword eximOption client_send
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""" }}}
" 34. The cram_md5 authenticator {{{
syn keyword eximDriverName cram_md5
syn keyword eximOption server_secret
syn keyword eximOption client_name client_secret
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""" }}}
" 35. The spa authenticator {{{
syn keyword eximDriverName spa
syn keyword eximOption server_password
syn keyword eximOption client_domain client_password client_username
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""" }}}
" 37. Access control lists {{{
" 37.8. Format of an ACL
syn match eximACLKeyword "^\s*\(accept\|defer\|deny\|discard\|drop\|require\|warn\)\>"
" 37.11. ACL modifiers
syn keyword eximACLModifier control delay endpass log_message message set
" 37.12. ACL conditions
syn keyword eximACLCondition acl authenticated condition dnslists domains encrypted hosts local_parts recipients sender_domains senders verify
syn keyword eximACLCondition header_sender header_syntax helo recipient reverse_host_lookup sender adderss
syn keyword eximACLParameter callout defer_ok no_cache postmaster random no_details
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""" }}}
" Define the default highlighting {{{
" For version 5.7 and earlier: Only when not done already
" For version 5.8 and later: Only when an item doesn't have highlighting yet
if version >= 508 || !exists("did_exim_syntax_inits")
  if version < 508
    let did_exim_syntax_inits = 1
    command -nargs=+ HiLink hi link <args>
  else
    command -nargs=+ HiLink hi def link <args>
  endif

  HiLink eximComment          Comment
  HiLink eximFixme            Todo
  HiLink eximSection          Keyword
  HiLink eximSectionName      Keyword
  HiLink eximRewriteFlags     Keyword
  HiLink eximRetryLetter      Keyword
  HiLink eximACLKeyword       Keyword
  HiLink eximNumber           Number
  HiLink eximDriverName       Constant
  HiLink eximConstant         Constant
  HiLink eximTime             Constant
  HiLink eximOption           Type
  HiLink eximStringOperationName Type
  HiLink eximOperationConditionName Type
  HiLink eximRetryCondition   Type
  HiLink eximACLModifier      Type
  HiLink eximACLCondition     Type
  HiLink eximACLParameter     Type
  HiLink eximSpecialChar      Special
  HiLink eximLineContinuation Special
  HiLink eximListChanger      Special
  HiLink eximHide             Special
  HiLink eximMacroName        Preproc
  HiLink eximInclude          Preproc
  HiLink eximIfThen           Preproc
  HiLink eximListDefinition   Preproc
  HiLink eximListReference    Function
  HiLink eximListName         Function
  HiLink eximLookupType       Function
  HiLink eximVariableReference Function
  HiLink eximExpansionVariable Function
  HiLink eximDriver           Title

  delcommand HiLink
endif
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""" }}}
let b:current_syntax = "exim"
