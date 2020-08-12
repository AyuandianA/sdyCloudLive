// Namespaced Header

#ifndef __NS_SYMBOL
// We need to have multiple levels of macros here so that __NAMESPACE_PREFIX_ is
// properly replaced by the time we concatenate the namespace prefix.
#define __NS_REWRITE(ns, symbol) ns ## _ ## symbol
#define __NS_BRIDGE(ns, symbol) __NS_REWRITE(ns, symbol)
#define __NS_SYMBOL(symbol) __NS_BRIDGE(AN_, symbol)
#endif


// SSL lib
// Classes
// Functions
#ifndef BIO_f_ssl
#define BIO_f_ssl __NS_SYMBOL(BIO_f_ssl)
#endif

#ifndef DTLSv1_client_method
#define DTLSv1_client_method __NS_SYMBOL(DTLSv1_client_method)
#endif

#ifndef DTLSv1_method
#define DTLSv1_method __NS_SYMBOL(DTLSv1_method)
#endif

#ifndef DTLSv1_server_method
#define DTLSv1_server_method __NS_SYMBOL(DTLSv1_server_method)
#endif

#ifndef ERR_load_SSL_strings
#define ERR_load_SSL_strings __NS_SYMBOL(ERR_load_SSL_strings)
#endif

#ifndef SSL_CTX_SRP_CTX_free
#define SSL_CTX_SRP_CTX_free __NS_SYMBOL(SSL_CTX_SRP_CTX_free)
#endif

#ifndef SSL_CTX_set_tlsext_use_srtp
#define SSL_CTX_set_tlsext_use_srtp __NS_SYMBOL(SSL_CTX_set_tlsext_use_srtp)
#endif

#ifndef SSL_SESSION_print_fp
#define SSL_SESSION_print_fp __NS_SYMBOL(SSL_SESSION_print_fp)
#endif

#ifndef SSL_get_ex_data_X509_STORE_CTX_idx
#define SSL_get_ex_data_X509_STORE_CTX_idx __NS_SYMBOL(SSL_get_ex_data_X509_STORE_CTX_idx)
#endif

#ifndef SSL_get_session
#define SSL_get_session __NS_SYMBOL(SSL_get_session)
#endif

#ifndef SSL_library_init
#define SSL_library_init __NS_SYMBOL(SSL_library_init)
#endif

#ifndef SSL_load_error_strings
#define SSL_load_error_strings __NS_SYMBOL(SSL_load_error_strings)
#endif

#ifndef SSL_state_string_long
#define SSL_state_string_long __NS_SYMBOL(SSL_state_string_long)
#endif

#ifndef SSL_use_certificate
#define SSL_use_certificate __NS_SYMBOL(SSL_use_certificate)
#endif

#ifndef SSLv23_client_method
#define SSLv23_client_method __NS_SYMBOL(SSLv23_client_method)
#endif

#ifndef SSLv23_method
#define SSLv23_method __NS_SYMBOL(SSLv23_method)
#endif

#ifndef SSLv23_server_method
#define SSLv23_server_method __NS_SYMBOL(SSLv23_server_method)
#endif

#ifndef SSLv2_client_method
#define SSLv2_client_method __NS_SYMBOL(SSLv2_client_method)
#endif

#ifndef SSLv2_method
#define SSLv2_method __NS_SYMBOL(SSLv2_method)
#endif

#ifndef SSLv2_server_method
#define SSLv2_server_method __NS_SYMBOL(SSLv2_server_method)
#endif

#ifndef SSLv3_client_method
#define SSLv3_client_method __NS_SYMBOL(SSLv3_client_method)
#endif

#ifndef SSLv3_method
#define SSLv3_method __NS_SYMBOL(SSLv3_method)
#endif

#ifndef SSLv3_server_method
#define SSLv3_server_method __NS_SYMBOL(SSLv3_server_method)
#endif

#ifndef TLSv1_2_client_method
#define TLSv1_2_client_method __NS_SYMBOL(TLSv1_2_client_method)
#endif

#ifndef TLSv1_2_method
#define TLSv1_2_method __NS_SYMBOL(TLSv1_2_method)
#endif

#ifndef TLSv1_2_server_method
#define TLSv1_2_server_method __NS_SYMBOL(TLSv1_2_server_method)
#endif

#ifndef dtls1_default_timeout
#define dtls1_default_timeout __NS_SYMBOL(dtls1_default_timeout)
#endif

#ifndef dtls1_do_write
#define dtls1_do_write __NS_SYMBOL(dtls1_do_write)
#endif

#ifndef dtls1_enc
#define dtls1_enc __NS_SYMBOL(dtls1_enc)
#endif

#ifndef dtls1_get_record
#define dtls1_get_record __NS_SYMBOL(dtls1_get_record)
#endif

#ifndef i2d_SSL_SESSION
#define i2d_SSL_SESSION __NS_SYMBOL(i2d_SSL_SESSION)
#endif

#ifndef ssl23_default_timeout
#define ssl23_default_timeout __NS_SYMBOL(ssl23_default_timeout)
#endif

#ifndef ssl23_write_bytes
#define ssl23_write_bytes __NS_SYMBOL(ssl23_write_bytes)
#endif

#ifndef ssl2_default_timeout
#define ssl2_default_timeout __NS_SYMBOL(ssl2_default_timeout)
#endif

#ifndef ssl2_enc_init
#define ssl2_enc_init __NS_SYMBOL(ssl2_enc_init)
#endif

#ifndef ssl2_read
#define ssl2_read __NS_SYMBOL(ssl2_read)
#endif

#ifndef ssl3_cbc_remove_padding
#define ssl3_cbc_remove_padding __NS_SYMBOL(ssl3_cbc_remove_padding)
#endif

#ifndef ssl3_change_cipher_state
#define ssl3_change_cipher_state __NS_SYMBOL(ssl3_change_cipher_state)
#endif

#ifndef ssl3_default_timeout
#define ssl3_default_timeout __NS_SYMBOL(ssl3_default_timeout)
#endif

#ifndef ssl3_do_write
#define ssl3_do_write __NS_SYMBOL(ssl3_do_write)
#endif

#ifndef ssl3_read_n
#define ssl3_read_n __NS_SYMBOL(ssl3_read_n)
#endif

#ifndef ssl_add_clienthello_renegotiate_ext
#define ssl_add_clienthello_renegotiate_ext __NS_SYMBOL(ssl_add_clienthello_renegotiate_ext)
#endif

#ifndef ssl_load_ciphers
#define ssl_load_ciphers __NS_SYMBOL(ssl_load_ciphers)
#endif

#ifndef ssl_undefined_function
#define ssl_undefined_function __NS_SYMBOL(ssl_undefined_function)
#endif

#ifndef tls1_change_cipher_state
#define tls1_change_cipher_state __NS_SYMBOL(tls1_change_cipher_state)
#endif

#ifndef tls1_default_timeout
#define tls1_default_timeout __NS_SYMBOL(tls1_default_timeout)
#endif

#ifndef BIO_new_buffer_ssl_connect
#define BIO_new_buffer_ssl_connect __NS_SYMBOL(BIO_new_buffer_ssl_connect)
#endif

#ifndef SSL_get1_session
#define SSL_get1_session __NS_SYMBOL(SSL_get1_session)
#endif

#ifndef dtls1_accept
#define dtls1_accept __NS_SYMBOL(dtls1_accept)
#endif

#ifndef dtls1_connect
#define dtls1_connect __NS_SYMBOL(dtls1_connect)
#endif

#ifndef dtls1_new
#define dtls1_new __NS_SYMBOL(dtls1_new)
#endif

#ifndef ssl23_accept
#define ssl23_accept __NS_SYMBOL(ssl23_accept)
#endif

#ifndef ssl23_connect
#define ssl23_connect __NS_SYMBOL(ssl23_connect)
#endif

#ifndef ssl23_num_ciphers
#define ssl23_num_ciphers __NS_SYMBOL(ssl23_num_ciphers)
#endif

#ifndef ssl2_accept
#define ssl2_accept __NS_SYMBOL(ssl2_accept)
#endif

#ifndef ssl2_connect
#define ssl2_connect __NS_SYMBOL(ssl2_connect)
#endif

#ifndef ssl2_num_ciphers
#define ssl2_num_ciphers __NS_SYMBOL(ssl2_num_ciphers)
#endif

#ifndef ssl3_accept
#define ssl3_accept __NS_SYMBOL(ssl3_accept)
#endif

#ifndef ssl3_connect
#define ssl3_connect __NS_SYMBOL(ssl3_connect)
#endif

#ifndef ssl3_num_ciphers
#define ssl3_num_ciphers __NS_SYMBOL(ssl3_num_ciphers)
#endif

#ifndef tls1_new
#define tls1_new __NS_SYMBOL(tls1_new)
#endif

#ifndef ssl2_get_cipher
#define ssl2_get_cipher __NS_SYMBOL(ssl2_get_cipher)
#endif

#ifndef ssl3_get_cipher
#define ssl3_get_cipher __NS_SYMBOL(ssl3_get_cipher)
#endif

#ifndef SSL_clear
#define SSL_clear __NS_SYMBOL(SSL_clear)
#endif

#ifndef ssl23_get_cipher
#define ssl23_get_cipher __NS_SYMBOL(ssl23_get_cipher)
#endif

#ifndef TLSv1_1_client_method
#define TLSv1_1_client_method __NS_SYMBOL(TLSv1_1_client_method)
#endif

#ifndef TLSv1_1_method
#define TLSv1_1_method __NS_SYMBOL(TLSv1_1_method)
#endif

#ifndef TLSv1_1_server_method
#define TLSv1_1_server_method __NS_SYMBOL(TLSv1_1_server_method)
#endif

#ifndef tls1_free
#define tls1_free __NS_SYMBOL(tls1_free)
#endif

#ifndef TLSv1_client_method
#define TLSv1_client_method __NS_SYMBOL(TLSv1_client_method)
#endif

#ifndef TLSv1_method
#define TLSv1_method __NS_SYMBOL(TLSv1_method)
#endif

#ifndef TLSv1_server_method
#define TLSv1_server_method __NS_SYMBOL(TLSv1_server_method)
#endif

#ifndef ssl2_pending
#define ssl2_pending __NS_SYMBOL(ssl2_pending)
#endif

#ifndef ssl3_pending
#define ssl3_pending __NS_SYMBOL(ssl3_pending)
#endif

#ifndef tls1_cbc_remove_padding
#define tls1_cbc_remove_padding __NS_SYMBOL(tls1_cbc_remove_padding)
#endif

#ifndef ssl23_get_cipher_by_char
#define ssl23_get_cipher_by_char __NS_SYMBOL(ssl23_get_cipher_by_char)
#endif

#ifndef BIO_new_ssl_connect
#define BIO_new_ssl_connect __NS_SYMBOL(BIO_new_ssl_connect)
#endif

#ifndef SSL_SESSION_get_ex_new_index
#define SSL_SESSION_get_ex_new_index __NS_SYMBOL(SSL_SESSION_get_ex_new_index)
#endif

#ifndef tls1_clear
#define tls1_clear __NS_SYMBOL(tls1_clear)
#endif

#ifndef SSL_SESSION_print
#define SSL_SESSION_print __NS_SYMBOL(SSL_SESSION_print)
#endif

#ifndef ssl2_new
#define ssl2_new __NS_SYMBOL(ssl2_new)
#endif

#ifndef ssl3_new
#define ssl3_new __NS_SYMBOL(ssl3_new)
#endif

#ifndef ssl23_put_cipher_by_char
#define ssl23_put_cipher_by_char __NS_SYMBOL(ssl23_put_cipher_by_char)
#endif

#ifndef ssl_parse_clienthello_renegotiate_ext
#define ssl_parse_clienthello_renegotiate_ext __NS_SYMBOL(ssl_parse_clienthello_renegotiate_ext)
#endif

#ifndef tls1_ec_curve_id2nid
#define tls1_ec_curve_id2nid __NS_SYMBOL(tls1_ec_curve_id2nid)
#endif

#ifndef SSL_SESSION_set_ex_data
#define SSL_SESSION_set_ex_data __NS_SYMBOL(SSL_SESSION_set_ex_data)
#endif

#ifndef ssl23_read_bytes
#define ssl23_read_bytes __NS_SYMBOL(ssl23_read_bytes)
#endif

#ifndef tls1_ec_nid2curve_id
#define tls1_ec_nid2curve_id __NS_SYMBOL(tls1_ec_nid2curve_id)
#endif

#ifndef SSL_SESSION_get_ex_data
#define SSL_SESSION_get_ex_data __NS_SYMBOL(SSL_SESSION_get_ex_data)
#endif

#ifndef ssl3_send_finished
#define ssl3_send_finished __NS_SYMBOL(ssl3_send_finished)
#endif

#ifndef ssl_cert_new
#define ssl_cert_new __NS_SYMBOL(ssl_cert_new)
#endif

#ifndef SSL_SESSION_new
#define SSL_SESSION_new __NS_SYMBOL(SSL_SESSION_new)
#endif

#ifndef ssl23_read
#define ssl23_read __NS_SYMBOL(ssl23_read)
#endif

#ifndef ssl3_free
#define ssl3_free __NS_SYMBOL(ssl3_free)
#endif

#ifndef BIO_new_ssl
#define BIO_new_ssl __NS_SYMBOL(BIO_new_ssl)
#endif

#ifndef SSL_SRP_CTX_free
#define SSL_SRP_CTX_free __NS_SYMBOL(SSL_SRP_CTX_free)
#endif

#ifndef SSL_set_tlsext_use_srtp
#define SSL_set_tlsext_use_srtp __NS_SYMBOL(SSL_set_tlsext_use_srtp)
#endif

#ifndef dtls1_free
#define dtls1_free __NS_SYMBOL(dtls1_free)
#endif

#ifndef ssl_cert_dup
#define ssl_cert_dup __NS_SYMBOL(ssl_cert_dup)
#endif

#ifndef SSL_get_srtp_profiles
#define SSL_get_srtp_profiles __NS_SYMBOL(SSL_get_srtp_profiles)
#endif

#ifndef ssl23_peek
#define ssl23_peek __NS_SYMBOL(ssl23_peek)
#endif

#ifndef ssl2_clear
#define ssl2_clear __NS_SYMBOL(ssl2_clear)
#endif

#ifndef BIO_ssl_copy_session_id
#define BIO_ssl_copy_session_id __NS_SYMBOL(BIO_ssl_copy_session_id)
#endif

#ifndef ssl_add_serverhello_renegotiate_ext
#define ssl_add_serverhello_renegotiate_ext __NS_SYMBOL(ssl_add_serverhello_renegotiate_ext)
#endif

#ifndef SSL_get_selected_srtp_profile
#define SSL_get_selected_srtp_profile __NS_SYMBOL(SSL_get_selected_srtp_profile)
#endif

#ifndef ssl_clear_cipher_ctx
#define ssl_clear_cipher_ctx __NS_SYMBOL(ssl_clear_cipher_ctx)
#endif

#ifndef SSL_use_certificate_file
#define SSL_use_certificate_file __NS_SYMBOL(SSL_use_certificate_file)
#endif

#ifndef ssl_add_clienthello_use_srtp_ext
#define ssl_add_clienthello_use_srtp_ext __NS_SYMBOL(ssl_add_clienthello_use_srtp_ext)
#endif

#ifndef ssl2_free
#define ssl2_free __NS_SYMBOL(ssl2_free)
#endif

#ifndef BIO_ssl_shutdown
#define BIO_ssl_shutdown __NS_SYMBOL(BIO_ssl_shutdown)
#endif

#ifndef SSL_SESSION_get_id
#define SSL_SESSION_get_id __NS_SYMBOL(SSL_SESSION_get_id)
#endif

#ifndef tls12_get_req_sig_algs
#define tls12_get_req_sig_algs __NS_SYMBOL(tls12_get_req_sig_algs)
#endif

#ifndef SSL_SESSION_get_compress_id
#define SSL_SESSION_get_compress_id __NS_SYMBOL(SSL_SESSION_get_compress_id)
#endif

#ifndef ssl23_write
#define ssl23_write __NS_SYMBOL(ssl23_write)
#endif

#ifndef ssl3_clear
#define ssl3_clear __NS_SYMBOL(ssl3_clear)
#endif

#ifndef ssl2_enc
#define ssl2_enc __NS_SYMBOL(ssl2_enc)
#endif

#ifndef ssl3_get_finished
#define ssl3_get_finished __NS_SYMBOL(ssl3_get_finished)
#endif

#ifndef ssl_get_new_session
#define ssl_get_new_session __NS_SYMBOL(ssl_get_new_session)
#endif

#ifndef ssl2_ctrl
#define ssl2_ctrl __NS_SYMBOL(ssl2_ctrl)
#endif

#ifndef ssl2_callback_ctrl
#define ssl2_callback_ctrl __NS_SYMBOL(ssl2_callback_ctrl)
#endif

#ifndef ssl_add_clienthello_tlsext
#define ssl_add_clienthello_tlsext __NS_SYMBOL(ssl_add_clienthello_tlsext)
#endif

#ifndef ssl_clear_hash_ctx
#define ssl_clear_hash_ctx __NS_SYMBOL(ssl_clear_hash_ctx)
#endif

#ifndef ssl_parse_serverhello_renegotiate_ext
#define ssl_parse_serverhello_renegotiate_ext __NS_SYMBOL(ssl_parse_serverhello_renegotiate_ext)
#endif

#ifndef ssl2_ctx_ctrl
#define ssl2_ctx_ctrl __NS_SYMBOL(ssl2_ctx_ctrl)
#endif

#ifndef SSL_SRP_CTX_init
#define SSL_SRP_CTX_init __NS_SYMBOL(SSL_SRP_CTX_init)
#endif

#ifndef ssl2_ctx_callback_ctrl
#define ssl2_ctx_callback_ctrl __NS_SYMBOL(ssl2_ctx_callback_ctrl)
#endif

#ifndef ssl2_mac
#define ssl2_mac __NS_SYMBOL(ssl2_mac)
#endif

#ifndef ssl_cipher_get_evp
#define ssl_cipher_get_evp __NS_SYMBOL(ssl_cipher_get_evp)
#endif

#ifndef SSL_CTX_set_ssl_version
#define SSL_CTX_set_ssl_version __NS_SYMBOL(SSL_CTX_set_ssl_version)
#endif

#ifndef ssl2_get_cipher_by_char
#define ssl2_get_cipher_by_char __NS_SYMBOL(ssl2_get_cipher_by_char)
#endif

#ifndef ssl3_cbc_copy_mac
#define ssl3_cbc_copy_mac __NS_SYMBOL(ssl3_cbc_copy_mac)
#endif

#ifndef ssl2_put_cipher_by_char
#define ssl2_put_cipher_by_char __NS_SYMBOL(ssl2_put_cipher_by_char)
#endif

#ifndef ssl_parse_clienthello_use_srtp_ext
#define ssl_parse_clienthello_use_srtp_ext __NS_SYMBOL(ssl_parse_clienthello_use_srtp_ext)
#endif

#ifndef SSL_new
#define SSL_new __NS_SYMBOL(SSL_new)
#endif

#ifndef ssl2_generate_key_material
#define ssl2_generate_key_material __NS_SYMBOL(ssl2_generate_key_material)
#endif

#ifndef SSL_use_certificate_ASN1
#define SSL_use_certificate_ASN1 __NS_SYMBOL(SSL_use_certificate_ASN1)
#endif

#ifndef ssl23_get_client_hello
#define ssl23_get_client_hello __NS_SYMBOL(ssl23_get_client_hello)
#endif

#ifndef ssl3_do_uncompress
#define ssl3_do_uncompress __NS_SYMBOL(ssl3_do_uncompress)
#endif

#ifndef dtls1_clear
#define dtls1_clear __NS_SYMBOL(dtls1_clear)
#endif

#ifndef ssl3_do_compress
#define ssl3_do_compress __NS_SYMBOL(ssl3_do_compress)
#endif

#ifndef ssl3_ctrl
#define ssl3_ctrl __NS_SYMBOL(ssl3_ctrl)
#endif

#ifndef ssl3_send_change_cipher_spec
#define ssl3_send_change_cipher_spec __NS_SYMBOL(ssl3_send_change_cipher_spec)
#endif

#ifndef SSL_use_RSAPrivateKey
#define SSL_use_RSAPrivateKey __NS_SYMBOL(SSL_use_RSAPrivateKey)
#endif

#ifndef ssl3_write_bytes
#define ssl3_write_bytes __NS_SYMBOL(ssl3_write_bytes)
#endif

#ifndef ssl2_peek
#define ssl2_peek __NS_SYMBOL(ssl2_peek)
#endif

#ifndef dtls1_ctrl
#define dtls1_ctrl __NS_SYMBOL(dtls1_ctrl)
#endif

#ifndef ssl2_write
#define ssl2_write __NS_SYMBOL(ssl2_write)
#endif

#ifndef ssl3_cbc_record_digest_supported
#define ssl3_cbc_record_digest_supported __NS_SYMBOL(ssl3_cbc_record_digest_supported)
#endif

#ifndef ssl3_output_cert_chain
#define ssl3_output_cert_chain __NS_SYMBOL(ssl3_output_cert_chain)
#endif

#ifndef ssl3_cbc_digest_record
#define ssl3_cbc_digest_record __NS_SYMBOL(ssl3_cbc_digest_record)
#endif

#ifndef ssl2_return_error
#define ssl2_return_error __NS_SYMBOL(ssl2_return_error)
#endif

#ifndef dtls1_get_timeout
#define dtls1_get_timeout __NS_SYMBOL(dtls1_get_timeout)
#endif

#ifndef SSL_CTX_SRP_CTX_init
#define SSL_CTX_SRP_CTX_init __NS_SYMBOL(SSL_CTX_SRP_CTX_init)
#endif

#ifndef ssl_add_serverhello_use_srtp_ext
#define ssl_add_serverhello_use_srtp_ext __NS_SYMBOL(ssl_add_serverhello_use_srtp_ext)
#endif

#ifndef ssl_cert_free
#define ssl_cert_free __NS_SYMBOL(ssl_cert_free)
#endif

#ifndef ssl2_write_error
#define ssl2_write_error __NS_SYMBOL(ssl2_write_error)
#endif

#ifndef SSL_use_RSAPrivateKey_file
#define SSL_use_RSAPrivateKey_file __NS_SYMBOL(SSL_use_RSAPrivateKey_file)
#endif

#ifndef dtls1_handle_timeout
#define dtls1_handle_timeout __NS_SYMBOL(dtls1_handle_timeout)
#endif

#ifndef ssl3_setup_key_block
#define ssl3_setup_key_block __NS_SYMBOL(ssl3_setup_key_block)
#endif

#ifndef dtls1_min_mtu
#define dtls1_min_mtu __NS_SYMBOL(dtls1_min_mtu)
#endif

#ifndef ssl_parse_serverhello_use_srtp_ext
#define ssl_parse_serverhello_use_srtp_ext __NS_SYMBOL(ssl_parse_serverhello_use_srtp_ext)
#endif

#ifndef dtls1_get_message
#define dtls1_get_message __NS_SYMBOL(dtls1_get_message)
#endif

#ifndef SSL_srp_server_param_with_username
#define SSL_srp_server_param_with_username __NS_SYMBOL(SSL_srp_server_param_with_username)
#endif

#ifndef SSL_CTX_free
#define SSL_CTX_free __NS_SYMBOL(SSL_CTX_free)
#endif

#ifndef ssl2_shutdown
#define ssl2_shutdown __NS_SYMBOL(ssl2_shutdown)
#endif

#ifndef ssl_cert_inst
#define ssl_cert_inst __NS_SYMBOL(ssl_cert_inst)
#endif

#ifndef SSL_SESSION_free
#define SSL_SESSION_free __NS_SYMBOL(SSL_SESSION_free)
#endif

#ifndef SSL_use_RSAPrivateKey_ASN1
#define SSL_use_RSAPrivateKey_ASN1 __NS_SYMBOL(SSL_use_RSAPrivateKey_ASN1)
#endif

#ifndef SSL_set_srp_server_param_pw
#define SSL_set_srp_server_param_pw __NS_SYMBOL(SSL_set_srp_server_param_pw)
#endif

#ifndef ssl_sess_cert_new
#define ssl_sess_cert_new __NS_SYMBOL(ssl_sess_cert_new)
#endif

#ifndef SSL_use_PrivateKey
#define SSL_use_PrivateKey __NS_SYMBOL(SSL_use_PrivateKey)
#endif

#ifndef ssl3_get_message
#define ssl3_get_message __NS_SYMBOL(ssl3_get_message)
#endif

#ifndef dtls1_listen
#define dtls1_listen __NS_SYMBOL(dtls1_listen)
#endif

#ifndef ssl_sess_cert_free
#define ssl_sess_cert_free __NS_SYMBOL(ssl_sess_cert_free)
#endif

#ifndef SSL_CTX_set_session_id_context
#define SSL_CTX_set_session_id_context __NS_SYMBOL(SSL_CTX_set_session_id_context)
#endif

#ifndef ssl_get_handshake_digest
#define ssl_get_handshake_digest __NS_SYMBOL(ssl_get_handshake_digest)
#endif

#ifndef SSL_set_srp_server_param
#define SSL_set_srp_server_param __NS_SYMBOL(SSL_set_srp_server_param)
#endif

#ifndef SSL_use_PrivateKey_file
#define SSL_use_PrivateKey_file __NS_SYMBOL(SSL_use_PrivateKey_file)
#endif

#ifndef dtls1_get_cipher
#define dtls1_get_cipher __NS_SYMBOL(dtls1_get_cipher)
#endif

#ifndef ssl2_part_read
#define ssl2_part_read __NS_SYMBOL(ssl2_part_read)
#endif

#ifndef dtls1_start_timer
#define dtls1_start_timer __NS_SYMBOL(dtls1_start_timer)
#endif

#ifndef ssl_create_cipher_list
#define ssl_create_cipher_list __NS_SYMBOL(ssl_create_cipher_list)
#endif

#ifndef SSL_set_session_id_context
#define SSL_set_session_id_context __NS_SYMBOL(SSL_set_session_id_context)
#endif

#ifndef ssl_get_prev_session
#define ssl_get_prev_session __NS_SYMBOL(ssl_get_prev_session)
#endif

#ifndef SSL_CTX_set_generate_session_id
#define SSL_CTX_set_generate_session_id __NS_SYMBOL(SSL_CTX_set_generate_session_id)
#endif

#ifndef dtls1_is_timer_expired
#define dtls1_is_timer_expired __NS_SYMBOL(dtls1_is_timer_expired)
#endif

#ifndef ssl2_do_write
#define ssl2_do_write __NS_SYMBOL(ssl2_do_write)
#endif

#ifndef SSL_set_generate_session_id
#define SSL_set_generate_session_id __NS_SYMBOL(SSL_set_generate_session_id)
#endif

#ifndef dtls1_double_timeout
#define dtls1_double_timeout __NS_SYMBOL(dtls1_double_timeout)
#endif

#ifndef ssl_set_peer_cert_type
#define ssl_set_peer_cert_type __NS_SYMBOL(ssl_set_peer_cert_type)
#endif

#ifndef ssl_verify_cert_chain
#define ssl_verify_cert_chain __NS_SYMBOL(ssl_verify_cert_chain)
#endif

#ifndef SSL_has_matching_session_id
#define SSL_has_matching_session_id __NS_SYMBOL(SSL_has_matching_session_id)
#endif

#ifndef SSL_use_PrivateKey_ASN1
#define SSL_use_PrivateKey_ASN1 __NS_SYMBOL(SSL_use_PrivateKey_ASN1)
#endif

#ifndef SRP_generate_server_master_secret
#define SRP_generate_server_master_secret __NS_SYMBOL(SRP_generate_server_master_secret)
#endif

#ifndef dtls1_stop_timer
#define dtls1_stop_timer __NS_SYMBOL(dtls1_stop_timer)
#endif

#ifndef dtls1_check_timeout_num
#define dtls1_check_timeout_num __NS_SYMBOL(dtls1_check_timeout_num)
#endif

#ifndef ssl3_cleanup_key_block
#define ssl3_cleanup_key_block __NS_SYMBOL(ssl3_cleanup_key_block)
#endif

#ifndef SSL_CTX_use_certificate
#define SSL_CTX_use_certificate __NS_SYMBOL(SSL_CTX_use_certificate)
#endif

#ifndef SSL_CTX_set_purpose
#define SSL_CTX_set_purpose __NS_SYMBOL(SSL_CTX_set_purpose)
#endif

#ifndef SSL_dup_CA_list
#define SSL_dup_CA_list __NS_SYMBOL(SSL_dup_CA_list)
#endif

#ifndef SSL_set_purpose
#define SSL_set_purpose __NS_SYMBOL(SSL_set_purpose)
#endif

#ifndef ssl3_enc
#define ssl3_enc __NS_SYMBOL(ssl3_enc)
#endif

#ifndef SSL_CTX_set_trust
#define SSL_CTX_set_trust __NS_SYMBOL(SSL_CTX_set_trust)
#endif

#ifndef SSL_CTX_use_certificate_file
#define SSL_CTX_use_certificate_file __NS_SYMBOL(SSL_CTX_use_certificate_file)
#endif

#ifndef SSL_set_trust
#define SSL_set_trust __NS_SYMBOL(SSL_set_trust)
#endif

#ifndef ssl3_callback_ctrl
#define ssl3_callback_ctrl __NS_SYMBOL(ssl3_callback_ctrl)
#endif

#ifndef d2i_SSL_SESSION
#define d2i_SSL_SESSION __NS_SYMBOL(d2i_SSL_SESSION)
#endif

#ifndef ssl3_write_pending
#define ssl3_write_pending __NS_SYMBOL(ssl3_write_pending)
#endif

#ifndef SSL_CTX_set1_param
#define SSL_CTX_set1_param __NS_SYMBOL(SSL_CTX_set1_param)
#endif

#ifndef SRP_generate_client_master_secret
#define SRP_generate_client_master_secret __NS_SYMBOL(SRP_generate_client_master_secret)
#endif

#ifndef SSL_set_client_CA_list
#define SSL_set_client_CA_list __NS_SYMBOL(SSL_set_client_CA_list)
#endif

#ifndef SSL_set1_param
#define SSL_set1_param __NS_SYMBOL(SSL_set1_param)
#endif

#ifndef SSL_free
#define SSL_free __NS_SYMBOL(SSL_free)
#endif

#ifndef SSL_CTX_set_client_CA_list
#define SSL_CTX_set_client_CA_list __NS_SYMBOL(SSL_CTX_set_client_CA_list)
#endif

#ifndef SSL_CTX_get_client_CA_list
#define SSL_CTX_get_client_CA_list __NS_SYMBOL(SSL_CTX_get_client_CA_list)
#endif

#ifndef ssl3_ctx_ctrl
#define ssl3_ctx_ctrl __NS_SYMBOL(ssl3_ctx_ctrl)
#endif

#ifndef SSL_get_client_CA_list
#define SSL_get_client_CA_list __NS_SYMBOL(SSL_get_client_CA_list)
#endif

#ifndef SSL_rstate_string_long
#define SSL_rstate_string_long __NS_SYMBOL(SSL_rstate_string_long)
#endif

#ifndef dtls1_read_bytes
#define dtls1_read_bytes __NS_SYMBOL(dtls1_read_bytes)
#endif

#ifndef SSL_state_string
#define SSL_state_string __NS_SYMBOL(SSL_state_string)
#endif

#ifndef SSL_add_client_CA
#define SSL_add_client_CA __NS_SYMBOL(SSL_add_client_CA)
#endif

#ifndef ssl_cert_type
#define ssl_cert_type __NS_SYMBOL(ssl_cert_type)
#endif

#ifndef ssl_add_serverhello_tlsext
#define ssl_add_serverhello_tlsext __NS_SYMBOL(ssl_add_serverhello_tlsext)
#endif

#ifndef SSL_CTX_use_certificate_ASN1
#define SSL_CTX_use_certificate_ASN1 __NS_SYMBOL(SSL_CTX_use_certificate_ASN1)
#endif

#ifndef ssl3_client_hello
#define ssl3_client_hello __NS_SYMBOL(ssl3_client_hello)
#endif

#ifndef ssl3_init_finished_mac
#define ssl3_init_finished_mac __NS_SYMBOL(ssl3_init_finished_mac)
#endif

#ifndef ssl3_read_bytes
#define ssl3_read_bytes __NS_SYMBOL(ssl3_read_bytes)
#endif

#ifndef SSL_CTX_add_client_CA
#define SSL_CTX_add_client_CA __NS_SYMBOL(SSL_CTX_add_client_CA)
#endif

#ifndef ssl_verify_alarm_type
#define ssl_verify_alarm_type __NS_SYMBOL(ssl_verify_alarm_type)
#endif

#ifndef ssl3_setup_read_buffer
#define ssl3_setup_read_buffer __NS_SYMBOL(ssl3_setup_read_buffer)
#endif

#ifndef dtls1_client_hello
#define dtls1_client_hello __NS_SYMBOL(dtls1_client_hello)
#endif

#ifndef ssl3_free_digest_list
#define ssl3_free_digest_list __NS_SYMBOL(ssl3_free_digest_list)
#endif

#ifndef SSL_CTX_add_session
#define SSL_CTX_add_session __NS_SYMBOL(SSL_CTX_add_session)
#endif

#ifndef srp_verify_server_param
#define srp_verify_server_param __NS_SYMBOL(srp_verify_server_param)
#endif

#ifndef SSL_CTX_use_RSAPrivateKey
#define SSL_CTX_use_RSAPrivateKey __NS_SYMBOL(SSL_CTX_use_RSAPrivateKey)
#endif

#ifndef SSL_load_client_CA_file
#define SSL_load_client_CA_file __NS_SYMBOL(SSL_load_client_CA_file)
#endif

#ifndef SSL_set_bio
#define SSL_set_bio __NS_SYMBOL(SSL_set_bio)
#endif

#ifndef SRP_Calc_A_param
#define SRP_Calc_A_param __NS_SYMBOL(SRP_Calc_A_param)
#endif

#ifndef SSL_CTX_use_RSAPrivateKey_file
#define SSL_CTX_use_RSAPrivateKey_file __NS_SYMBOL(SSL_CTX_use_RSAPrivateKey_file)
#endif

#ifndef ssl3_finish_mac
#define ssl3_finish_mac __NS_SYMBOL(ssl3_finish_mac)
#endif

#ifndef SSL_get_rbio
#define SSL_get_rbio __NS_SYMBOL(SSL_get_rbio)
#endif

#ifndef SSL_get_wbio
#define SSL_get_wbio __NS_SYMBOL(SSL_get_wbio)
#endif

#ifndef SSL_get_fd
#define SSL_get_fd __NS_SYMBOL(SSL_get_fd)
#endif

#ifndef ssl3_setup_write_buffer
#define ssl3_setup_write_buffer __NS_SYMBOL(ssl3_setup_write_buffer)
#endif

#ifndef SSL_get_srp_g
#define SSL_get_srp_g __NS_SYMBOL(SSL_get_srp_g)
#endif

#ifndef SSL_get_srp_N
#define SSL_get_srp_N __NS_SYMBOL(SSL_get_srp_N)
#endif

#ifndef SSL_get_rfd
#define SSL_get_rfd __NS_SYMBOL(SSL_get_rfd)
#endif

#ifndef SSL_get_srp_username
#define SSL_get_srp_username __NS_SYMBOL(SSL_get_srp_username)
#endif

#ifndef SSL_get_srp_userinfo
#define SSL_get_srp_userinfo __NS_SYMBOL(SSL_get_srp_userinfo)
#endif

#ifndef SSL_CTX_set_srp_username
#define SSL_CTX_set_srp_username __NS_SYMBOL(SSL_CTX_set_srp_username)
#endif

#ifndef SSL_get_wfd
#define SSL_get_wfd __NS_SYMBOL(SSL_get_wfd)
#endif

#ifndef ssl_fill_hello_random
#define ssl_fill_hello_random __NS_SYMBOL(ssl_fill_hello_random)
#endif

#ifndef SSL_add_file_cert_subjects_to_stack
#define SSL_add_file_cert_subjects_to_stack __NS_SYMBOL(SSL_add_file_cert_subjects_to_stack)
#endif

#ifndef SSL_CTX_set_srp_password
#define SSL_CTX_set_srp_password __NS_SYMBOL(SSL_CTX_set_srp_password)
#endif

#ifndef ssl3_digest_cached_records
#define ssl3_digest_cached_records __NS_SYMBOL(ssl3_digest_cached_records)
#endif

#ifndef SSL_CTX_set_srp_strength
#define SSL_CTX_set_srp_strength __NS_SYMBOL(SSL_CTX_set_srp_strength)
#endif

#ifndef SSL_CTX_use_RSAPrivateKey_ASN1
#define SSL_CTX_use_RSAPrivateKey_ASN1 __NS_SYMBOL(SSL_CTX_use_RSAPrivateKey_ASN1)
#endif

#ifndef SSL_set_fd
#define SSL_set_fd __NS_SYMBOL(SSL_set_fd)
#endif

#ifndef SSL_CTX_set_srp_verify_param_callback
#define SSL_CTX_set_srp_verify_param_callback __NS_SYMBOL(SSL_CTX_set_srp_verify_param_callback)
#endif

#ifndef SSL_CTX_set_srp_cb_arg
#define SSL_CTX_set_srp_cb_arg __NS_SYMBOL(SSL_CTX_set_srp_cb_arg)
#endif

#ifndef SSL_CTX_remove_session
#define SSL_CTX_remove_session __NS_SYMBOL(SSL_CTX_remove_session)
#endif

#ifndef SSL_CTX_set_srp_username_callback
#define SSL_CTX_set_srp_username_callback __NS_SYMBOL(SSL_CTX_set_srp_username_callback)
#endif

#ifndef ssl3_get_server_hello
#define ssl3_get_server_hello __NS_SYMBOL(ssl3_get_server_hello)
#endif

#ifndef SSL_CTX_use_PrivateKey
#define SSL_CTX_use_PrivateKey __NS_SYMBOL(SSL_CTX_use_PrivateKey)
#endif

#ifndef SSL_CTX_set_srp_client_pwd_callback
#define SSL_CTX_set_srp_client_pwd_callback __NS_SYMBOL(SSL_CTX_set_srp_client_pwd_callback)
#endif

#ifndef dtls1_send_hello_request
#define dtls1_send_hello_request __NS_SYMBOL(dtls1_send_hello_request)
#endif

#ifndef ssl3_setup_buffers
#define ssl3_setup_buffers __NS_SYMBOL(ssl3_setup_buffers)
#endif

#ifndef SSL_set_wfd
#define SSL_set_wfd __NS_SYMBOL(SSL_set_wfd)
#endif

#ifndef ssl3_release_write_buffer
#define ssl3_release_write_buffer __NS_SYMBOL(ssl3_release_write_buffer)
#endif

#ifndef SSL_CTX_use_PrivateKey_file
#define SSL_CTX_use_PrivateKey_file __NS_SYMBOL(SSL_CTX_use_PrivateKey_file)
#endif

#ifndef dtls1_send_server_hello
#define dtls1_send_server_hello __NS_SYMBOL(dtls1_send_server_hello)
#endif

#ifndef SSL_add_dir_cert_subjects_to_stack
#define SSL_add_dir_cert_subjects_to_stack __NS_SYMBOL(SSL_add_dir_cert_subjects_to_stack)
#endif

#ifndef dtls1_send_finished
#define dtls1_send_finished __NS_SYMBOL(dtls1_send_finished)
#endif

#ifndef tls1_setup_key_block
#define tls1_setup_key_block __NS_SYMBOL(tls1_setup_key_block)
#endif

#ifndef dtls1_send_client_certificate
#define dtls1_send_client_certificate __NS_SYMBOL(dtls1_send_client_certificate)
#endif

#ifndef ssl3_send_hello_request
#define ssl3_send_hello_request __NS_SYMBOL(ssl3_send_hello_request)
#endif

#ifndef ssl3_cert_verify_mac
#define ssl3_cert_verify_mac __NS_SYMBOL(ssl3_cert_verify_mac)
#endif

#ifndef SSL_set_session
#define SSL_set_session __NS_SYMBOL(SSL_set_session)
#endif

#ifndef ssl3_get_client_hello
#define ssl3_get_client_hello __NS_SYMBOL(ssl3_get_client_hello)
#endif

#ifndef ssl_parse_clienthello_tlsext
#define ssl_parse_clienthello_tlsext __NS_SYMBOL(ssl_parse_clienthello_tlsext)
#endif

#ifndef ssl3_ctx_callback_ctrl
#define ssl3_ctx_callback_ctrl __NS_SYMBOL(ssl3_ctx_callback_ctrl)
#endif

#ifndef SSL_set_rfd
#define SSL_set_rfd __NS_SYMBOL(SSL_set_rfd)
#endif

#ifndef ssl3_release_read_buffer
#define ssl3_release_read_buffer __NS_SYMBOL(ssl3_release_read_buffer)
#endif

#ifndef SSL_CTX_use_PrivateKey_ASN1
#define SSL_CTX_use_PrivateKey_ASN1 __NS_SYMBOL(SSL_CTX_use_PrivateKey_ASN1)
#endif

#ifndef ssl3_get_cipher_by_char
#define ssl3_get_cipher_by_char __NS_SYMBOL(ssl3_get_cipher_by_char)
#endif

#ifndef dtls1_set_message_header
#define dtls1_set_message_header __NS_SYMBOL(dtls1_set_message_header)
#endif

#ifndef SSL_SESSION_set_timeout
#define SSL_SESSION_set_timeout __NS_SYMBOL(SSL_SESSION_set_timeout)
#endif

#ifndef ssl3_put_cipher_by_char
#define ssl3_put_cipher_by_char __NS_SYMBOL(ssl3_put_cipher_by_char)
#endif

#ifndef SSL_CTX_use_certificate_chain_file
#define SSL_CTX_use_certificate_chain_file __NS_SYMBOL(SSL_CTX_use_certificate_chain_file)
#endif

#ifndef SSL_SESSION_get_timeout
#define SSL_SESSION_get_timeout __NS_SYMBOL(SSL_SESSION_get_timeout)
#endif

#ifndef dtls1_send_server_certificate
#define dtls1_send_server_certificate __NS_SYMBOL(dtls1_send_server_certificate)
#endif

#ifndef SSL_SESSION_get_time
#define SSL_SESSION_get_time __NS_SYMBOL(SSL_SESSION_get_time)
#endif

#ifndef ssl3_choose_cipher
#define ssl3_choose_cipher __NS_SYMBOL(ssl3_choose_cipher)
#endif

#ifndef SSL_SESSION_set_time
#define SSL_SESSION_set_time __NS_SYMBOL(SSL_SESSION_set_time)
#endif

#ifndef dtls1_buffer_message
#define dtls1_buffer_message __NS_SYMBOL(dtls1_buffer_message)
#endif

#ifndef SSL_get_finished
#define SSL_get_finished __NS_SYMBOL(SSL_get_finished)
#endif

#ifndef dtls1_send_client_key_exchange
#define dtls1_send_client_key_exchange __NS_SYMBOL(dtls1_send_client_key_exchange)
#endif

#ifndef SSL_SESSION_get0_peer
#define SSL_SESSION_get0_peer __NS_SYMBOL(SSL_SESSION_get0_peer)
#endif

#ifndef SSL_SESSION_set1_id_context
#define SSL_SESSION_set1_id_context __NS_SYMBOL(SSL_SESSION_set1_id_context)
#endif

#ifndef SSL_get_peer_finished
#define SSL_get_peer_finished __NS_SYMBOL(SSL_get_peer_finished)
#endif

#ifndef tls1_enc
#define tls1_enc __NS_SYMBOL(tls1_enc)
#endif

#ifndef dtls1_send_server_key_exchange
#define dtls1_send_server_key_exchange __NS_SYMBOL(dtls1_send_server_key_exchange)
#endif

#ifndef SSL_CTX_set_timeout
#define SSL_CTX_set_timeout __NS_SYMBOL(SSL_CTX_set_timeout)
#endif

#ifndef SSL_get_verify_mode
#define SSL_get_verify_mode __NS_SYMBOL(SSL_get_verify_mode)
#endif

#ifndef SSL_CTX_get_timeout
#define SSL_CTX_get_timeout __NS_SYMBOL(SSL_CTX_get_timeout)
#endif

#ifndef SSL_get_verify_depth
#define SSL_get_verify_depth __NS_SYMBOL(SSL_get_verify_depth)
#endif

#ifndef SSL_get_verify_callback
#define SSL_get_verify_callback __NS_SYMBOL(SSL_get_verify_callback)
#endif

#ifndef SSL_set_session_secret_cb
#define SSL_set_session_secret_cb __NS_SYMBOL(SSL_set_session_secret_cb)
#endif

#ifndef ssl3_final_finish_mac
#define ssl3_final_finish_mac __NS_SYMBOL(ssl3_final_finish_mac)
#endif

#ifndef SSL_CTX_get_verify_mode
#define SSL_CTX_get_verify_mode __NS_SYMBOL(SSL_CTX_get_verify_mode)
#endif

#ifndef SSL_CTX_get_verify_depth
#define SSL_CTX_get_verify_depth __NS_SYMBOL(SSL_CTX_get_verify_depth)
#endif

#ifndef SSL_set_session_ticket_ext_cb
#define SSL_set_session_ticket_ext_cb __NS_SYMBOL(SSL_set_session_ticket_ext_cb)
#endif

#ifndef SSL_CTX_get_verify_callback
#define SSL_CTX_get_verify_callback __NS_SYMBOL(SSL_CTX_get_verify_callback)
#endif

#ifndef SSL_set_session_ticket_ext
#define SSL_set_session_ticket_ext __NS_SYMBOL(SSL_set_session_ticket_ext)
#endif

#ifndef SSL_set_verify
#define SSL_set_verify __NS_SYMBOL(SSL_set_verify)
#endif

#ifndef SSL_set_verify_depth
#define SSL_set_verify_depth __NS_SYMBOL(SSL_set_verify_depth)
#endif

#ifndef n_ssl3_mac
#define n_ssl3_mac __NS_SYMBOL(n_ssl3_mac)
#endif

#ifndef SSL_set_read_ahead
#define SSL_set_read_ahead __NS_SYMBOL(SSL_set_read_ahead)
#endif

#ifndef SSL_get_read_ahead
#define SSL_get_read_ahead __NS_SYMBOL(SSL_get_read_ahead)
#endif

#ifndef SSL_pending
#define SSL_pending __NS_SYMBOL(SSL_pending)
#endif

#ifndef SSL_get_peer_certificate
#define SSL_get_peer_certificate __NS_SYMBOL(SSL_get_peer_certificate)
#endif

#ifndef SSL_CTX_flush_sessions
#define SSL_CTX_flush_sessions __NS_SYMBOL(SSL_CTX_flush_sessions)
#endif

#ifndef SSL_get_peer_cert_chain
#define SSL_get_peer_cert_chain __NS_SYMBOL(SSL_get_peer_cert_chain)
#endif

#ifndef SSL_copy_session_id
#define SSL_copy_session_id __NS_SYMBOL(SSL_copy_session_id)
#endif

#ifndef dtls1_send_change_cipher_spec
#define dtls1_send_change_cipher_spec __NS_SYMBOL(dtls1_send_change_cipher_spec)
#endif

#ifndef dtls1_output_cert_chain
#define dtls1_output_cert_chain __NS_SYMBOL(dtls1_output_cert_chain)
#endif

#ifndef SSL_CTX_check_private_key
#define SSL_CTX_check_private_key __NS_SYMBOL(SSL_CTX_check_private_key)
#endif

#ifndef ssl_clear_bad_session
#define ssl_clear_bad_session __NS_SYMBOL(ssl_clear_bad_session)
#endif

#ifndef SSL_CTX_sess_set_new_cb
#define SSL_CTX_sess_set_new_cb __NS_SYMBOL(SSL_CTX_sess_set_new_cb)
#endif

#ifndef SSL_check_private_key
#define SSL_check_private_key __NS_SYMBOL(SSL_check_private_key)
#endif

#ifndef SSL_CTX_sess_get_new_cb
#define SSL_CTX_sess_get_new_cb __NS_SYMBOL(SSL_CTX_sess_get_new_cb)
#endif

#ifndef SSL_CTX_sess_set_remove_cb
#define SSL_CTX_sess_set_remove_cb __NS_SYMBOL(SSL_CTX_sess_set_remove_cb)
#endif

#ifndef SSL_CTX_sess_get_remove_cb
#define SSL_CTX_sess_get_remove_cb __NS_SYMBOL(SSL_CTX_sess_get_remove_cb)
#endif

#ifndef SSL_CTX_sess_set_get_cb
#define SSL_CTX_sess_set_get_cb __NS_SYMBOL(SSL_CTX_sess_set_get_cb)
#endif

#ifndef SSL_CTX_sess_get_get_cb
#define SSL_CTX_sess_get_get_cb __NS_SYMBOL(SSL_CTX_sess_get_get_cb)
#endif

#ifndef ssl3_check_finished
#define ssl3_check_finished __NS_SYMBOL(ssl3_check_finished)
#endif

#ifndef SSL_CTX_set_info_callback
#define SSL_CTX_set_info_callback __NS_SYMBOL(SSL_CTX_set_info_callback)
#endif

#ifndef SSL_CTX_get_info_callback
#define SSL_CTX_get_info_callback __NS_SYMBOL(SSL_CTX_get_info_callback)
#endif

#ifndef SSL_CTX_set_client_cert_cb
#define SSL_CTX_set_client_cert_cb __NS_SYMBOL(SSL_CTX_set_client_cert_cb)
#endif

#ifndef SSL_alert_type_string_long
#define SSL_alert_type_string_long __NS_SYMBOL(SSL_alert_type_string_long)
#endif

#ifndef SSL_CTX_get_client_cert_cb
#define SSL_CTX_get_client_cert_cb __NS_SYMBOL(SSL_CTX_get_client_cert_cb)
#endif

#ifndef SSL_CTX_set_client_cert_engine
#define SSL_CTX_set_client_cert_engine __NS_SYMBOL(SSL_CTX_set_client_cert_engine)
#endif

#ifndef SSL_accept
#define SSL_accept __NS_SYMBOL(SSL_accept)
#endif

#ifndef SSL_alert_type_string
#define SSL_alert_type_string __NS_SYMBOL(SSL_alert_type_string)
#endif

#ifndef ssl3_get_server_certificate
#define ssl3_get_server_certificate __NS_SYMBOL(ssl3_get_server_certificate)
#endif

#ifndef SSL_alert_desc_string
#define SSL_alert_desc_string __NS_SYMBOL(SSL_alert_desc_string)
#endif

#ifndef SSL_CTX_set_cookie_generate_cb
#define SSL_CTX_set_cookie_generate_cb __NS_SYMBOL(SSL_CTX_set_cookie_generate_cb)
#endif

#ifndef ssl3_record_sequence_update
#define ssl3_record_sequence_update __NS_SYMBOL(ssl3_record_sequence_update)
#endif

#ifndef SSL_CTX_set_cookie_verify_cb
#define SSL_CTX_set_cookie_verify_cb __NS_SYMBOL(SSL_CTX_set_cookie_verify_cb)
#endif

#ifndef SSL_set_accept_state
#define SSL_set_accept_state __NS_SYMBOL(SSL_set_accept_state)
#endif

#ifndef PEM_read_bio_SSL_SESSION
#define PEM_read_bio_SSL_SESSION __NS_SYMBOL(PEM_read_bio_SSL_SESSION)
#endif

#ifndef ssl3_generate_master_secret
#define ssl3_generate_master_secret __NS_SYMBOL(ssl3_generate_master_secret)
#endif

#ifndef PEM_read_SSL_SESSION
#define PEM_read_SSL_SESSION __NS_SYMBOL(PEM_read_SSL_SESSION)
#endif

#ifndef tls1_cert_verify_mac
#define tls1_cert_verify_mac __NS_SYMBOL(tls1_cert_verify_mac)
#endif

#ifndef PEM_write_bio_SSL_SESSION
#define PEM_write_bio_SSL_SESSION __NS_SYMBOL(PEM_write_bio_SSL_SESSION)
#endif

#ifndef SSL_connect
#define SSL_connect __NS_SYMBOL(SSL_connect)
#endif

#ifndef PEM_write_SSL_SESSION
#define PEM_write_SSL_SESSION __NS_SYMBOL(PEM_write_SSL_SESSION)
#endif

#ifndef SSL_set_connect_state
#define SSL_set_connect_state __NS_SYMBOL(SSL_set_connect_state)
#endif

#ifndef dtls1_read_failed
#define dtls1_read_failed __NS_SYMBOL(dtls1_read_failed)
#endif

#ifndef SSL_get_default_timeout
#define SSL_get_default_timeout __NS_SYMBOL(SSL_get_default_timeout)
#endif

#ifndef tls1_final_finish_mac
#define tls1_final_finish_mac __NS_SYMBOL(tls1_final_finish_mac)
#endif

#ifndef SSL_read
#define SSL_read __NS_SYMBOL(SSL_read)
#endif

#ifndef ssl2_set_certificate
#define ssl2_set_certificate __NS_SYMBOL(ssl2_set_certificate)
#endif

#ifndef SSL_peek
#define SSL_peek __NS_SYMBOL(SSL_peek)
#endif

#ifndef dtls1_get_queue_priority
#define dtls1_get_queue_priority __NS_SYMBOL(dtls1_get_queue_priority)
#endif

#ifndef dtls1_retransmit_buffered_messages
#define dtls1_retransmit_buffered_messages __NS_SYMBOL(dtls1_retransmit_buffered_messages)
#endif

#ifndef ssl3_alert_code
#define ssl3_alert_code __NS_SYMBOL(ssl3_alert_code)
#endif

#ifndef ssl3_get_req_cert_type
#define ssl3_get_req_cert_type __NS_SYMBOL(ssl3_get_req_cert_type)
#endif

#ifndef SSL_alert_desc_string_long
#define SSL_alert_desc_string_long __NS_SYMBOL(SSL_alert_desc_string_long)
#endif

#ifndef SSL_write
#define SSL_write __NS_SYMBOL(SSL_write)
#endif

#ifndef dtls1_reset_seq_numbers
#define dtls1_reset_seq_numbers __NS_SYMBOL(dtls1_reset_seq_numbers)
#endif

#ifndef SSL_shutdown
#define SSL_shutdown __NS_SYMBOL(SSL_shutdown)
#endif

#ifndef ssl3_shutdown
#define ssl3_shutdown __NS_SYMBOL(ssl3_shutdown)
#endif

#ifndef dtls1_retransmit_message
#define dtls1_retransmit_message __NS_SYMBOL(dtls1_retransmit_message)
#endif

#ifndef SSL_state
#define SSL_state __NS_SYMBOL(SSL_state)
#endif

#ifndef SSL_renegotiate
#define SSL_renegotiate __NS_SYMBOL(SSL_renegotiate)
#endif

#ifndef dtls1_write_app_data_bytes
#define dtls1_write_app_data_bytes __NS_SYMBOL(dtls1_write_app_data_bytes)
#endif

#ifndef SSL_renegotiate_abbreviated
#define SSL_renegotiate_abbreviated __NS_SYMBOL(SSL_renegotiate_abbreviated)
#endif

#ifndef SSL_renegotiate_pending
#define SSL_renegotiate_pending __NS_SYMBOL(SSL_renegotiate_pending)
#endif

#ifndef SSL_ctrl
#define SSL_ctrl __NS_SYMBOL(SSL_ctrl)
#endif

#ifndef ssl3_write
#define ssl3_write __NS_SYMBOL(ssl3_write)
#endif

#ifndef dtls1_write_bytes
#define dtls1_write_bytes __NS_SYMBOL(dtls1_write_bytes)
#endif

#ifndef tls1_mac
#define tls1_mac __NS_SYMBOL(tls1_mac)
#endif

#ifndef tls1_process_sigalgs
#define tls1_process_sigalgs __NS_SYMBOL(tls1_process_sigalgs)
#endif

#ifndef do_dtls1_write
#define do_dtls1_write __NS_SYMBOL(do_dtls1_write)
#endif

#ifndef SSL_rstate_string
#define SSL_rstate_string __NS_SYMBOL(SSL_rstate_string)
#endif

#ifndef ssl3_renegotiate_check
#define ssl3_renegotiate_check __NS_SYMBOL(ssl3_renegotiate_check)
#endif

#ifndef ssl3_get_key_exchange
#define ssl3_get_key_exchange __NS_SYMBOL(ssl3_get_key_exchange)
#endif

#ifndef ssl3_read
#define ssl3_read __NS_SYMBOL(ssl3_read)
#endif

#ifndef SSL_version
#define SSL_version __NS_SYMBOL(SSL_version)
#endif

#ifndef SSL_callback_ctrl
#define SSL_callback_ctrl __NS_SYMBOL(SSL_callback_ctrl)
#endif

#ifndef ssl3_send_server_hello
#define ssl3_send_server_hello __NS_SYMBOL(ssl3_send_server_hello)
#endif

#ifndef SSL_CTX_sessions
#define SSL_CTX_sessions __NS_SYMBOL(SSL_CTX_sessions)
#endif

#ifndef SSL_CTX_ctrl
#define SSL_CTX_ctrl __NS_SYMBOL(SSL_CTX_ctrl)
#endif

#ifndef ssl_parse_serverhello_tlsext
#define ssl_parse_serverhello_tlsext __NS_SYMBOL(ssl_parse_serverhello_tlsext)
#endif

#ifndef dtls1_clear_record_buffer
#define dtls1_clear_record_buffer __NS_SYMBOL(dtls1_clear_record_buffer)
#endif

#ifndef ssl3_peek
#define ssl3_peek __NS_SYMBOL(ssl3_peek)
#endif

#ifndef dtls1_send_client_verify
#define dtls1_send_client_verify __NS_SYMBOL(dtls1_send_client_verify)
#endif

#ifndef dtls1_get_message_header
#define dtls1_get_message_header __NS_SYMBOL(dtls1_get_message_header)
#endif

#ifndef tls1_generate_master_secret
#define tls1_generate_master_secret __NS_SYMBOL(tls1_generate_master_secret)
#endif

#ifndef ssl3_renegotiate
#define ssl3_renegotiate __NS_SYMBOL(ssl3_renegotiate)
#endif

#ifndef dtls1_get_ccs_header
#define dtls1_get_ccs_header __NS_SYMBOL(dtls1_get_ccs_header)
#endif

#ifndef ssl_get_algorithm2
#define ssl_get_algorithm2 __NS_SYMBOL(ssl_get_algorithm2)
#endif

#ifndef dtls1_shutdown
#define dtls1_shutdown __NS_SYMBOL(dtls1_shutdown)
#endif

#ifndef dtls1_dispatch_alert
#define dtls1_dispatch_alert __NS_SYMBOL(dtls1_dispatch_alert)
#endif

#ifndef dtls1_process_heartbeat
#define dtls1_process_heartbeat __NS_SYMBOL(dtls1_process_heartbeat)
#endif

#ifndef ssl3_send_server_certificate
#define ssl3_send_server_certificate __NS_SYMBOL(ssl3_send_server_certificate)
#endif

#ifndef tls1_export_keying_material
#define tls1_export_keying_material __NS_SYMBOL(tls1_export_keying_material)
#endif

#ifndef SSL_CTX_callback_ctrl
#define SSL_CTX_callback_ctrl __NS_SYMBOL(SSL_CTX_callback_ctrl)
#endif

#ifndef ssl3_send_server_key_exchange
#define ssl3_send_server_key_exchange __NS_SYMBOL(ssl3_send_server_key_exchange)
#endif

#ifndef ssl3_send_alert
#define ssl3_send_alert __NS_SYMBOL(ssl3_send_alert)
#endif

#ifndef ssl_cipher_id_cmp
#define ssl_cipher_id_cmp __NS_SYMBOL(ssl_cipher_id_cmp)
#endif

#ifndef ssl_cipher_ptr_id_cmp
#define ssl_cipher_ptr_id_cmp __NS_SYMBOL(ssl_cipher_ptr_id_cmp)
#endif

#ifndef SSL_get_ciphers
#define SSL_get_ciphers __NS_SYMBOL(SSL_get_ciphers)
#endif

#ifndef ssl_get_ciphers_by_id
#define ssl_get_ciphers_by_id __NS_SYMBOL(ssl_get_ciphers_by_id)
#endif

#ifndef SSL_get_cipher_list
#define SSL_get_cipher_list __NS_SYMBOL(SSL_get_cipher_list)
#endif

#ifndef ssl3_do_change_cipher_spec
#define ssl3_do_change_cipher_spec __NS_SYMBOL(ssl3_do_change_cipher_spec)
#endif

#ifndef dtls1_heartbeat
#define dtls1_heartbeat __NS_SYMBOL(dtls1_heartbeat)
#endif

#ifndef SSL_CTX_set_cipher_list
#define SSL_CTX_set_cipher_list __NS_SYMBOL(SSL_CTX_set_cipher_list)
#endif

#ifndef SSL_CIPHER_description
#define SSL_CIPHER_description __NS_SYMBOL(SSL_CIPHER_description)
#endif

#ifndef dtls1_send_certificate_request
#define dtls1_send_certificate_request __NS_SYMBOL(dtls1_send_certificate_request)
#endif

#ifndef SSL_set_cipher_list
#define SSL_set_cipher_list __NS_SYMBOL(SSL_set_cipher_list)
#endif

#ifndef ssl3_dispatch_alert
#define ssl3_dispatch_alert __NS_SYMBOL(ssl3_dispatch_alert)
#endif

#ifndef SSL_get_shared_ciphers
#define SSL_get_shared_ciphers __NS_SYMBOL(SSL_get_shared_ciphers)
#endif

#ifndef tls1_alert_code
#define tls1_alert_code __NS_SYMBOL(tls1_alert_code)
#endif

#ifndef ssl_cipher_list_to_bytes
#define ssl_cipher_list_to_bytes __NS_SYMBOL(ssl_cipher_list_to_bytes)
#endif

#ifndef ssl_prepare_clienthello_tlsext
#define ssl_prepare_clienthello_tlsext __NS_SYMBOL(ssl_prepare_clienthello_tlsext)
#endif

#ifndef dtls1_send_server_done
#define dtls1_send_server_done __NS_SYMBOL(dtls1_send_server_done)
#endif

#ifndef dtls1_send_newsession_ticket
#define dtls1_send_newsession_ticket __NS_SYMBOL(dtls1_send_newsession_ticket)
#endif

#ifndef ssl_bytes_to_cipher_list
#define ssl_bytes_to_cipher_list __NS_SYMBOL(ssl_bytes_to_cipher_list)
#endif

#ifndef ssl_prepare_serverhello_tlsext
#define ssl_prepare_serverhello_tlsext __NS_SYMBOL(ssl_prepare_serverhello_tlsext)
#endif

#ifndef SSL_get_servername
#define SSL_get_servername __NS_SYMBOL(SSL_get_servername)
#endif

#ifndef ssl_check_clienthello_tlsext_early
#define ssl_check_clienthello_tlsext_early __NS_SYMBOL(ssl_check_clienthello_tlsext_early)
#endif

#ifndef SSL_get_servername_type
#define SSL_get_servername_type __NS_SYMBOL(SSL_get_servername_type)
#endif

#ifndef SSL_select_next_proto
#define SSL_select_next_proto __NS_SYMBOL(SSL_select_next_proto)
#endif

#ifndef SSL_CIPHER_get_version
#define SSL_CIPHER_get_version __NS_SYMBOL(SSL_CIPHER_get_version)
#endif

#ifndef ssl_check_clienthello_tlsext_late
#define ssl_check_clienthello_tlsext_late __NS_SYMBOL(ssl_check_clienthello_tlsext_late)
#endif

#ifndef SSL_CIPHER_get_name
#define SSL_CIPHER_get_name __NS_SYMBOL(SSL_CIPHER_get_name)
#endif

#ifndef SSL_CIPHER_get_bits
#define SSL_CIPHER_get_bits __NS_SYMBOL(SSL_CIPHER_get_bits)
#endif

#ifndef SSL_CIPHER_get_id
#define SSL_CIPHER_get_id __NS_SYMBOL(SSL_CIPHER_get_id)
#endif

#ifndef ssl3_comp_find
#define ssl3_comp_find __NS_SYMBOL(ssl3_comp_find)
#endif

#ifndef SSL_get0_next_proto_negotiated
#define SSL_get0_next_proto_negotiated __NS_SYMBOL(SSL_get0_next_proto_negotiated)
#endif

#ifndef SSL_CTX_set_next_protos_advertised_cb
#define SSL_CTX_set_next_protos_advertised_cb __NS_SYMBOL(SSL_CTX_set_next_protos_advertised_cb)
#endif

#ifndef ssl_check_serverhello_tlsext
#define ssl_check_serverhello_tlsext __NS_SYMBOL(ssl_check_serverhello_tlsext)
#endif

#ifndef SSL_CTX_set_next_proto_select_cb
#define SSL_CTX_set_next_proto_select_cb __NS_SYMBOL(SSL_CTX_set_next_proto_select_cb)
#endif

#ifndef SSL_COMP_get_compression_methods
#define SSL_COMP_get_compression_methods __NS_SYMBOL(SSL_COMP_get_compression_methods)
#endif

#ifndef SSL_export_keying_material
#define SSL_export_keying_material __NS_SYMBOL(SSL_export_keying_material)
#endif

#ifndef SSL_COMP_add_compression_method
#define SSL_COMP_add_compression_method __NS_SYMBOL(SSL_COMP_add_compression_method)
#endif

#ifndef SSL_CTX_new
#define SSL_CTX_new __NS_SYMBOL(SSL_CTX_new)
#endif

#ifndef SSL_COMP_get_name
#define SSL_COMP_get_name __NS_SYMBOL(SSL_COMP_get_name)
#endif

#ifndef tls1_process_ticket
#define tls1_process_ticket __NS_SYMBOL(tls1_process_ticket)
#endif

#ifndef SSL_CTX_set_default_passwd_cb
#define SSL_CTX_set_default_passwd_cb __NS_SYMBOL(SSL_CTX_set_default_passwd_cb)
#endif

#ifndef SSL_CTX_set_default_passwd_cb_userdata
#define SSL_CTX_set_default_passwd_cb_userdata __NS_SYMBOL(SSL_CTX_set_default_passwd_cb_userdata)
#endif

#ifndef SSL_CTX_set_cert_verify_callback
#define SSL_CTX_set_cert_verify_callback __NS_SYMBOL(SSL_CTX_set_cert_verify_callback)
#endif

#ifndef SSL_CTX_set_verify
#define SSL_CTX_set_verify __NS_SYMBOL(SSL_CTX_set_verify)
#endif

#ifndef ssl3_send_certificate_request
#define ssl3_send_certificate_request __NS_SYMBOL(ssl3_send_certificate_request)
#endif

#ifndef SSL_CTX_set_verify_depth
#define SSL_CTX_set_verify_depth __NS_SYMBOL(SSL_CTX_set_verify_depth)
#endif

#ifndef ssl_set_cert_masks
#define ssl_set_cert_masks __NS_SYMBOL(ssl_set_cert_masks)
#endif

#ifndef tls12_get_sigandhash
#define tls12_get_sigandhash __NS_SYMBOL(tls12_get_sigandhash)
#endif

#ifndef tls12_get_sigid
#define tls12_get_sigid __NS_SYMBOL(tls12_get_sigid)
#endif

#ifndef tls12_get_hash
#define tls12_get_hash __NS_SYMBOL(tls12_get_hash)
#endif

#ifndef tls1_process_heartbeat
#define tls1_process_heartbeat __NS_SYMBOL(tls1_process_heartbeat)
#endif

#ifndef ssl3_check_cert_and_algorithm
#define ssl3_check_cert_and_algorithm __NS_SYMBOL(ssl3_check_cert_and_algorithm)
#endif

#ifndef ssl3_send_server_done
#define ssl3_send_server_done __NS_SYMBOL(ssl3_send_server_done)
#endif

#ifndef ssl3_check_client_hello
#define ssl3_check_client_hello __NS_SYMBOL(ssl3_check_client_hello)
#endif

#ifndef tls1_heartbeat
#define tls1_heartbeat __NS_SYMBOL(tls1_heartbeat)
#endif

#ifndef ssl3_get_client_certificate
#define ssl3_get_client_certificate __NS_SYMBOL(ssl3_get_client_certificate)
#endif

#ifndef ssl_check_srvr_ecc_cert_and_alg
#define ssl_check_srvr_ecc_cert_and_alg __NS_SYMBOL(ssl_check_srvr_ecc_cert_and_alg)
#endif

#ifndef ssl3_get_certificate_request
#define ssl3_get_certificate_request __NS_SYMBOL(ssl3_get_certificate_request)
#endif

#ifndef ssl_get_server_send_pkey
#define ssl_get_server_send_pkey __NS_SYMBOL(ssl_get_server_send_pkey)
#endif

#ifndef ssl_get_server_send_cert
#define ssl_get_server_send_cert __NS_SYMBOL(ssl_get_server_send_cert)
#endif

#ifndef ssl_get_sign_pkey
#define ssl_get_sign_pkey __NS_SYMBOL(ssl_get_sign_pkey)
#endif

#ifndef ssl_update_cache
#define ssl_update_cache __NS_SYMBOL(ssl_update_cache)
#endif

#ifndef ssl3_get_client_key_exchange
#define ssl3_get_client_key_exchange __NS_SYMBOL(ssl3_get_client_key_exchange)
#endif

#ifndef SSL_get_ssl_method
#define SSL_get_ssl_method __NS_SYMBOL(SSL_get_ssl_method)
#endif

#ifndef SSL_set_ssl_method
#define SSL_set_ssl_method __NS_SYMBOL(SSL_set_ssl_method)
#endif

#ifndef SSL_get_error
#define SSL_get_error __NS_SYMBOL(SSL_get_error)
#endif

#ifndef ssl3_get_server_done
#define ssl3_get_server_done __NS_SYMBOL(ssl3_get_server_done)
#endif

#ifndef ssl3_send_client_certificate
#define ssl3_send_client_certificate __NS_SYMBOL(ssl3_send_client_certificate)
#endif

#ifndef SSL_want
#define SSL_want __NS_SYMBOL(SSL_want)
#endif

#ifndef SSL_do_handshake
#define SSL_do_handshake __NS_SYMBOL(SSL_do_handshake)
#endif

#ifndef ssl_undefined_void_function
#define ssl_undefined_void_function __NS_SYMBOL(ssl_undefined_void_function)
#endif

#ifndef ssl_undefined_const_function
#define ssl_undefined_const_function __NS_SYMBOL(ssl_undefined_const_function)
#endif

#ifndef ssl_bad_method
#define ssl_bad_method __NS_SYMBOL(ssl_bad_method)
#endif

#ifndef SSL_get_version
#define SSL_get_version __NS_SYMBOL(SSL_get_version)
#endif

#ifndef SSL_dup
#define SSL_dup __NS_SYMBOL(SSL_dup)
#endif

#ifndef ssl3_send_client_key_exchange
#define ssl3_send_client_key_exchange __NS_SYMBOL(ssl3_send_client_key_exchange)
#endif

#ifndef SSL_get_SSL_CTX
#define SSL_get_SSL_CTX __NS_SYMBOL(SSL_get_SSL_CTX)
#endif

#ifndef SSL_set_info_callback
#define SSL_set_info_callback __NS_SYMBOL(SSL_set_info_callback)
#endif

#ifndef SSL_get_info_callback
#define SSL_get_info_callback __NS_SYMBOL(SSL_get_info_callback)
#endif

#ifndef SSL_get_certificate
#define SSL_get_certificate __NS_SYMBOL(SSL_get_certificate)
#endif

#ifndef SSL_get_privatekey
#define SSL_get_privatekey __NS_SYMBOL(SSL_get_privatekey)
#endif

#ifndef SSL_get_current_cipher
#define SSL_get_current_cipher __NS_SYMBOL(SSL_get_current_cipher)
#endif

#ifndef SSL_get_current_compression
#define SSL_get_current_compression __NS_SYMBOL(SSL_get_current_compression)
#endif

#ifndef SSL_get_current_expansion
#define SSL_get_current_expansion __NS_SYMBOL(SSL_get_current_expansion)
#endif

#ifndef ssl_init_wbio_buffer
#define ssl_init_wbio_buffer __NS_SYMBOL(ssl_init_wbio_buffer)
#endif

#ifndef ssl_free_wbio_buffer
#define ssl_free_wbio_buffer __NS_SYMBOL(ssl_free_wbio_buffer)
#endif

#ifndef SSL_CTX_set_quiet_shutdown
#define SSL_CTX_set_quiet_shutdown __NS_SYMBOL(SSL_CTX_set_quiet_shutdown)
#endif

#ifndef SSL_CTX_get_quiet_shutdown
#define SSL_CTX_get_quiet_shutdown __NS_SYMBOL(SSL_CTX_get_quiet_shutdown)
#endif

#ifndef SSL_set_quiet_shutdown
#define SSL_set_quiet_shutdown __NS_SYMBOL(SSL_set_quiet_shutdown)
#endif

#ifndef SSL_get_quiet_shutdown
#define SSL_get_quiet_shutdown __NS_SYMBOL(SSL_get_quiet_shutdown)
#endif

#ifndef SSL_set_shutdown
#define SSL_set_shutdown __NS_SYMBOL(SSL_set_shutdown)
#endif

#ifndef SSL_get_shutdown
#define SSL_get_shutdown __NS_SYMBOL(SSL_get_shutdown)
#endif

#ifndef SSL_set_SSL_CTX
#define SSL_set_SSL_CTX __NS_SYMBOL(SSL_set_SSL_CTX)
#endif

#ifndef SSL_CTX_set_default_verify_paths
#define SSL_CTX_set_default_verify_paths __NS_SYMBOL(SSL_CTX_set_default_verify_paths)
#endif

#ifndef SSL_CTX_load_verify_locations
#define SSL_CTX_load_verify_locations __NS_SYMBOL(SSL_CTX_load_verify_locations)
#endif

#ifndef SSL_set_state
#define SSL_set_state __NS_SYMBOL(SSL_set_state)
#endif

#ifndef SSL_set_verify_result
#define SSL_set_verify_result __NS_SYMBOL(SSL_set_verify_result)
#endif

#ifndef SSL_get_verify_result
#define SSL_get_verify_result __NS_SYMBOL(SSL_get_verify_result)
#endif

#ifndef SSL_get_ex_new_index
#define SSL_get_ex_new_index __NS_SYMBOL(SSL_get_ex_new_index)
#endif

#ifndef SSL_set_ex_data
#define SSL_set_ex_data __NS_SYMBOL(SSL_set_ex_data)
#endif

#ifndef SSL_get_ex_data
#define SSL_get_ex_data __NS_SYMBOL(SSL_get_ex_data)
#endif

#ifndef SSL_CTX_get_ex_new_index
#define SSL_CTX_get_ex_new_index __NS_SYMBOL(SSL_CTX_get_ex_new_index)
#endif

#ifndef SSL_CTX_set_ex_data
#define SSL_CTX_set_ex_data __NS_SYMBOL(SSL_CTX_set_ex_data)
#endif

#ifndef SSL_CTX_get_ex_data
#define SSL_CTX_get_ex_data __NS_SYMBOL(SSL_CTX_get_ex_data)
#endif

#ifndef ssl_ok
#define ssl_ok __NS_SYMBOL(ssl_ok)
#endif

#ifndef SSL_CTX_get_cert_store
#define SSL_CTX_get_cert_store __NS_SYMBOL(SSL_CTX_get_cert_store)
#endif

#ifndef SSL_CTX_set_cert_store
#define SSL_CTX_set_cert_store __NS_SYMBOL(SSL_CTX_set_cert_store)
#endif

#ifndef SSL_CTX_set_tmp_rsa_callback
#define SSL_CTX_set_tmp_rsa_callback __NS_SYMBOL(SSL_CTX_set_tmp_rsa_callback)
#endif

#ifndef SSL_set_tmp_rsa_callback
#define SSL_set_tmp_rsa_callback __NS_SYMBOL(SSL_set_tmp_rsa_callback)
#endif

#ifndef SSL_CTX_set_tmp_dh_callback
#define SSL_CTX_set_tmp_dh_callback __NS_SYMBOL(SSL_CTX_set_tmp_dh_callback)
#endif

#ifndef SSL_set_tmp_dh_callback
#define SSL_set_tmp_dh_callback __NS_SYMBOL(SSL_set_tmp_dh_callback)
#endif

#ifndef SSL_CTX_set_tmp_ecdh_callback
#define SSL_CTX_set_tmp_ecdh_callback __NS_SYMBOL(SSL_CTX_set_tmp_ecdh_callback)
#endif

#ifndef SSL_set_tmp_ecdh_callback
#define SSL_set_tmp_ecdh_callback __NS_SYMBOL(SSL_set_tmp_ecdh_callback)
#endif

#ifndef SSL_CTX_use_psk_identity_hint
#define SSL_CTX_use_psk_identity_hint __NS_SYMBOL(SSL_CTX_use_psk_identity_hint)
#endif

#ifndef SSL_use_psk_identity_hint
#define SSL_use_psk_identity_hint __NS_SYMBOL(SSL_use_psk_identity_hint)
#endif

#ifndef SSL_get_psk_identity_hint
#define SSL_get_psk_identity_hint __NS_SYMBOL(SSL_get_psk_identity_hint)
#endif

#ifndef SSL_get_psk_identity
#define SSL_get_psk_identity __NS_SYMBOL(SSL_get_psk_identity)
#endif

#ifndef SSL_set_psk_client_callback
#define SSL_set_psk_client_callback __NS_SYMBOL(SSL_set_psk_client_callback)
#endif

#ifndef SSL_CTX_set_psk_client_callback
#define SSL_CTX_set_psk_client_callback __NS_SYMBOL(SSL_CTX_set_psk_client_callback)
#endif

#ifndef SSL_set_psk_server_callback
#define SSL_set_psk_server_callback __NS_SYMBOL(SSL_set_psk_server_callback)
#endif

#ifndef SSL_CTX_set_psk_server_callback
#define SSL_CTX_set_psk_server_callback __NS_SYMBOL(SSL_CTX_set_psk_server_callback)
#endif

#ifndef SSL_CTX_set_msg_callback
#define SSL_CTX_set_msg_callback __NS_SYMBOL(SSL_CTX_set_msg_callback)
#endif

#ifndef SSL_set_msg_callback
#define SSL_set_msg_callback __NS_SYMBOL(SSL_set_msg_callback)
#endif

#ifndef ssl_replace_hash
#define ssl_replace_hash __NS_SYMBOL(ssl_replace_hash)
#endif

#ifndef SSL_set_debug
#define SSL_set_debug __NS_SYMBOL(SSL_set_debug)
#endif

#ifndef SSL_cache_hit
#define SSL_cache_hit __NS_SYMBOL(SSL_cache_hit)
#endif

#ifndef OBJ_bsearch_ssl_cipher_id
#define OBJ_bsearch_ssl_cipher_id __NS_SYMBOL(OBJ_bsearch_ssl_cipher_id)
#endif

#ifndef ssl3_get_cert_verify
#define ssl3_get_cert_verify __NS_SYMBOL(ssl3_get_cert_verify)
#endif

#ifndef ssl3_send_client_verify
#define ssl3_send_client_verify __NS_SYMBOL(ssl3_send_client_verify)
#endif

#ifndef ssl3_get_next_proto
#define ssl3_get_next_proto __NS_SYMBOL(ssl3_get_next_proto)
#endif

#ifndef ssl3_send_newsession_ticket
#define ssl3_send_newsession_ticket __NS_SYMBOL(ssl3_send_newsession_ticket)
#endif

#ifndef ssl3_send_next_proto
#define ssl3_send_next_proto __NS_SYMBOL(ssl3_send_next_proto)
#endif

#ifndef ssl3_get_new_session_ticket
#define ssl3_get_new_session_ticket __NS_SYMBOL(ssl3_get_new_session_ticket)
#endif

#ifndef ssl3_get_cert_status
#define ssl3_get_cert_status __NS_SYMBOL(ssl3_get_cert_status)
#endif

#ifndef ssl3_send_cert_status
#define ssl3_send_cert_status __NS_SYMBOL(ssl3_send_cert_status)
#endif

#ifndef ssl_do_client_cert_cb
#define ssl_do_client_cert_cb __NS_SYMBOL(ssl_do_client_cert_cb)
#endif

// Externs
#ifndef DTLSv1_enc_data
#define DTLSv1_enc_data __NS_SYMBOL(DTLSv1_enc_data)
#endif

#ifndef ssl3_ciphers
#define ssl3_ciphers __NS_SYMBOL(ssl3_ciphers)
#endif

#ifndef TLSv1_enc_data
#define TLSv1_enc_data __NS_SYMBOL(TLSv1_enc_data)
#endif

#ifndef SSL_version_str
#define SSL_version_str __NS_SYMBOL(SSL_version_str)
#endif

#ifndef ssl3_undef_enc_method
#define ssl3_undef_enc_method __NS_SYMBOL(ssl3_undef_enc_method)
#endif

#ifndef SSLv3_enc_data
#define SSLv3_enc_data __NS_SYMBOL(SSLv3_enc_data)
#endif

#ifndef ssl2_version_str
#define ssl2_version_str __NS_SYMBOL(ssl2_version_str)
#endif

#ifndef ssl2_ciphers
#define ssl2_ciphers __NS_SYMBOL(ssl2_ciphers)
#endif

#ifndef dtls1_version_str
#define dtls1_version_str __NS_SYMBOL(dtls1_version_str)
#endif

#ifndef ssl3_version_str
#define ssl3_version_str __NS_SYMBOL(ssl3_version_str)
#endif

#ifndef tls1_version_str
#define tls1_version_str __NS_SYMBOL(tls1_version_str)
#endif

// Crypto lib
// Classes
// Functions
#ifndef AES_cfb128_encrypt
#define AES_cfb128_encrypt __NS_SYMBOL(AES_cfb128_encrypt)
#endif

#ifndef AES_ctr128_encrypt
#define AES_ctr128_encrypt __NS_SYMBOL(AES_ctr128_encrypt)
#endif

#ifndef AES_ecb_encrypt
#define AES_ecb_encrypt __NS_SYMBOL(AES_ecb_encrypt)
#endif

#ifndef AES_ige_encrypt
#define AES_ige_encrypt __NS_SYMBOL(AES_ige_encrypt)
#endif

#ifndef AES_ofb128_encrypt
#define AES_ofb128_encrypt __NS_SYMBOL(AES_ofb128_encrypt)
#endif

#ifndef AES_options
#define AES_options __NS_SYMBOL(AES_options)
#endif

#ifndef AES_wrap_key
#define AES_wrap_key __NS_SYMBOL(AES_wrap_key)
#endif

#ifndef ASN1_BIT_STRING_name_print
#define ASN1_BIT_STRING_name_print __NS_SYMBOL(ASN1_BIT_STRING_name_print)
#endif

#ifndef ASN1_BIT_STRING_set
#define ASN1_BIT_STRING_set __NS_SYMBOL(ASN1_BIT_STRING_set)
#endif

#ifndef ASN1_ENUMERATED_set
#define ASN1_ENUMERATED_set __NS_SYMBOL(ASN1_ENUMERATED_set)
#endif

#ifndef ASN1_GENERALIZEDTIME_check
#define ASN1_GENERALIZEDTIME_check __NS_SYMBOL(ASN1_GENERALIZEDTIME_check)
#endif

#ifndef ASN1_INTEGER_dup
#define ASN1_INTEGER_dup __NS_SYMBOL(ASN1_INTEGER_dup)
#endif

#ifndef ASN1_OCTET_STRING_dup
#define ASN1_OCTET_STRING_dup __NS_SYMBOL(ASN1_OCTET_STRING_dup)
#endif

#ifndef ASN1_PCTX_new
#define ASN1_PCTX_new __NS_SYMBOL(ASN1_PCTX_new)
#endif

#ifndef ASN1_PRINTABLE_type
#define ASN1_PRINTABLE_type __NS_SYMBOL(ASN1_PRINTABLE_type)
#endif

#ifndef ASN1_STRING_set_default_mask
#define ASN1_STRING_set_default_mask __NS_SYMBOL(ASN1_STRING_set_default_mask)
#endif

#ifndef ASN1_TYPE_get
#define ASN1_TYPE_get __NS_SYMBOL(ASN1_TYPE_get)
#endif

#ifndef ASN1_TYPE_set_octetstring
#define ASN1_TYPE_set_octetstring __NS_SYMBOL(ASN1_TYPE_set_octetstring)
#endif

#ifndef ASN1_UTCTIME_check
#define ASN1_UTCTIME_check __NS_SYMBOL(ASN1_UTCTIME_check)
#endif

#ifndef ASN1_add_oid_module
#define ASN1_add_oid_module __NS_SYMBOL(ASN1_add_oid_module)
#endif

#ifndef ASN1_bn_print
#define ASN1_bn_print __NS_SYMBOL(ASN1_bn_print)
#endif

#ifndef ASN1_check_infinite_end
#define ASN1_check_infinite_end __NS_SYMBOL(ASN1_check_infinite_end)
#endif

#ifndef ASN1_d2i_fp
#define ASN1_d2i_fp __NS_SYMBOL(ASN1_d2i_fp)
#endif

#ifndef ASN1_digest
#define ASN1_digest __NS_SYMBOL(ASN1_digest)
#endif

#ifndef ASN1_dup
#define ASN1_dup __NS_SYMBOL(ASN1_dup)
#endif

#ifndef ASN1_generate_nconf
#define ASN1_generate_nconf __NS_SYMBOL(ASN1_generate_nconf)
#endif

#ifndef ASN1_i2d_fp
#define ASN1_i2d_fp __NS_SYMBOL(ASN1_i2d_fp)
#endif

#ifndef ASN1_item_free
#define ASN1_item_free __NS_SYMBOL(ASN1_item_free)
#endif

#ifndef ASN1_item_ndef_i2d
#define ASN1_item_ndef_i2d __NS_SYMBOL(ASN1_item_ndef_i2d)
#endif

#ifndef ASN1_item_new
#define ASN1_item_new __NS_SYMBOL(ASN1_item_new)
#endif

#ifndef ASN1_mbstring_copy
#define ASN1_mbstring_copy __NS_SYMBOL(ASN1_mbstring_copy)
#endif

#ifndef ASN1_parse
#define ASN1_parse __NS_SYMBOL(ASN1_parse)
#endif

#ifndef ASN1_seq_unpack
#define ASN1_seq_unpack __NS_SYMBOL(ASN1_seq_unpack)
#endif

#ifndef ASN1_sign
#define ASN1_sign __NS_SYMBOL(ASN1_sign)
#endif

#ifndef ASN1_tag2bit
#define ASN1_tag2bit __NS_SYMBOL(ASN1_tag2bit)
#endif

#ifndef ASN1_verify
#define ASN1_verify __NS_SYMBOL(ASN1_verify)
#endif

#ifndef BF_cfb64_encrypt
#define BF_cfb64_encrypt __NS_SYMBOL(BF_cfb64_encrypt)
#endif

#ifndef BF_encrypt
#define BF_encrypt __NS_SYMBOL(BF_encrypt)
#endif

#ifndef BF_ofb64_encrypt
#define BF_ofb64_encrypt __NS_SYMBOL(BF_ofb64_encrypt)
#endif

#ifndef BF_options
#define BF_options __NS_SYMBOL(BF_options)
#endif

#ifndef BF_set_key
#define BF_set_key __NS_SYMBOL(BF_set_key)
#endif

#ifndef BIO_CONNECT_new
#define BIO_CONNECT_new __NS_SYMBOL(BIO_CONNECT_new)
#endif

#ifndef BIO_debug_callback
#define BIO_debug_callback __NS_SYMBOL(BIO_debug_callback)
#endif

#ifndef BIO_dump_cb
#define BIO_dump_cb __NS_SYMBOL(BIO_dump_cb)
#endif

#ifndef BIO_f_asn1
#define BIO_f_asn1 __NS_SYMBOL(BIO_f_asn1)
#endif

#ifndef BIO_f_base64
#define BIO_f_base64 __NS_SYMBOL(BIO_f_base64)
#endif

#ifndef BIO_f_buffer
#define BIO_f_buffer __NS_SYMBOL(BIO_f_buffer)
#endif

#ifndef BIO_f_cipher
#define BIO_f_cipher __NS_SYMBOL(BIO_f_cipher)
#endif

#ifndef BIO_f_md
#define BIO_f_md __NS_SYMBOL(BIO_f_md)
#endif

#ifndef BIO_f_nbio_test
#define BIO_f_nbio_test __NS_SYMBOL(BIO_f_nbio_test)
#endif

#ifndef BIO_f_null
#define BIO_f_null __NS_SYMBOL(BIO_f_null)
#endif

#ifndef BIO_f_reliable
#define BIO_f_reliable __NS_SYMBOL(BIO_f_reliable)
#endif

#ifndef BIO_get_host_ip
#define BIO_get_host_ip __NS_SYMBOL(BIO_get_host_ip)
#endif

#ifndef BIO_new
#define BIO_new __NS_SYMBOL(BIO_new)
#endif

#ifndef BIO_new_NDEF
#define BIO_new_NDEF __NS_SYMBOL(BIO_new_NDEF)
#endif

#ifndef BIO_new_PKCS7
#define BIO_new_PKCS7 __NS_SYMBOL(BIO_new_PKCS7)
#endif

#ifndef BIO_new_file
#define BIO_new_file __NS_SYMBOL(BIO_new_file)
#endif

#ifndef BIO_printf
#define BIO_printf __NS_SYMBOL(BIO_printf)
#endif

#ifndef BIO_s_accept
#define BIO_s_accept __NS_SYMBOL(BIO_s_accept)
#endif

#ifndef BIO_s_bio
#define BIO_s_bio __NS_SYMBOL(BIO_s_bio)
#endif

#ifndef BIO_s_datagram
#define BIO_s_datagram __NS_SYMBOL(BIO_s_datagram)
#endif

#ifndef BIO_s_fd
#define BIO_s_fd __NS_SYMBOL(BIO_s_fd)
#endif

#ifndef BIO_s_log
#define BIO_s_log __NS_SYMBOL(BIO_s_log)
#endif

#ifndef BIO_s_mem
#define BIO_s_mem __NS_SYMBOL(BIO_s_mem)
#endif

#ifndef BIO_s_null
#define BIO_s_null __NS_SYMBOL(BIO_s_null)
#endif

#ifndef BIO_s_socket
#define BIO_s_socket __NS_SYMBOL(BIO_s_socket)
#endif

#ifndef BN_BLINDING_new
#define BN_BLINDING_new __NS_SYMBOL(BN_BLINDING_new)
#endif

#ifndef BN_CTX_init
#define BN_CTX_init __NS_SYMBOL(BN_CTX_init)
#endif

#ifndef BN_GENCB_call
#define BN_GENCB_call __NS_SYMBOL(BN_GENCB_call)
#endif

#ifndef BN_GF2m_add
#define BN_GF2m_add __NS_SYMBOL(BN_GF2m_add)
#endif

#ifndef BN_RECP_CTX_init
#define BN_RECP_CTX_init __NS_SYMBOL(BN_RECP_CTX_init)
#endif

#ifndef BN_X931_derive_prime_ex
#define BN_X931_derive_prime_ex __NS_SYMBOL(BN_X931_derive_prime_ex)
#endif

#ifndef BN_add
#define BN_add __NS_SYMBOL(BN_add)
#endif

#ifndef BN_bn2hex
#define BN_bn2hex __NS_SYMBOL(BN_bn2hex)
#endif

#ifndef BN_bn2mpi
#define BN_bn2mpi __NS_SYMBOL(BN_bn2mpi)
#endif

#ifndef BN_div
#define BN_div __NS_SYMBOL(BN_div)
#endif

#ifndef BN_exp
#define BN_exp __NS_SYMBOL(BN_exp)
#endif

#ifndef BN_gcd
#define BN_gcd __NS_SYMBOL(BN_gcd)
#endif

#ifndef BN_generate_prime
#define BN_generate_prime __NS_SYMBOL(BN_generate_prime)
#endif

#ifndef BN_get0_nist_prime_192
#define BN_get0_nist_prime_192 __NS_SYMBOL(BN_get0_nist_prime_192)
#endif

#ifndef BN_kronecker
#define BN_kronecker __NS_SYMBOL(BN_kronecker)
#endif

#ifndef BN_lshift1
#define BN_lshift1 __NS_SYMBOL(BN_lshift1)
#endif

#ifndef BN_mod_exp2_mont
#define BN_mod_exp2_mont __NS_SYMBOL(BN_mod_exp2_mont)
#endif

#ifndef BN_mod_mul_montgomery
#define BN_mod_mul_montgomery __NS_SYMBOL(BN_mod_mul_montgomery)
#endif

#ifndef BN_mod_sqrt
#define BN_mod_sqrt __NS_SYMBOL(BN_mod_sqrt)
#endif

#ifndef BN_mod_word
#define BN_mod_word __NS_SYMBOL(BN_mod_word)
#endif

#ifndef BN_nnmod
#define BN_nnmod __NS_SYMBOL(BN_nnmod)
#endif

#ifndef BN_rand
#define BN_rand __NS_SYMBOL(BN_rand)
#endif

#ifndef BN_set_params
#define BN_set_params __NS_SYMBOL(BN_set_params)
#endif

#ifndef BN_sqr
#define BN_sqr __NS_SYMBOL(BN_sqr)
#endif

#ifndef BUF_MEM_new
#define BUF_MEM_new __NS_SYMBOL(BUF_MEM_new)
#endif

#ifndef BUF_strdup
#define BUF_strdup __NS_SYMBOL(BUF_strdup)
#endif

#ifndef CAST_cfb64_encrypt
#define CAST_cfb64_encrypt __NS_SYMBOL(CAST_cfb64_encrypt)
#endif

#ifndef CAST_ecb_encrypt
#define CAST_ecb_encrypt __NS_SYMBOL(CAST_ecb_encrypt)
#endif

#ifndef CAST_encrypt
#define CAST_encrypt __NS_SYMBOL(CAST_encrypt)
#endif

#ifndef CAST_ofb64_encrypt
#define CAST_ofb64_encrypt __NS_SYMBOL(CAST_ofb64_encrypt)
#endif

#ifndef CAST_set_key
#define CAST_set_key __NS_SYMBOL(CAST_set_key)
#endif

#ifndef CMAC_CTX_new
#define CMAC_CTX_new __NS_SYMBOL(CMAC_CTX_new)
#endif

#ifndef CMS_RecipientInfo_set0_password
#define CMS_RecipientInfo_set0_password __NS_SYMBOL(CMS_RecipientInfo_set0_password)
#endif

#ifndef CMS_SignedData_init
#define CMS_SignedData_init __NS_SYMBOL(CMS_SignedData_init)
#endif

#ifndef CMS_data
#define CMS_data __NS_SYMBOL(CMS_data)
#endif

#ifndef CMS_signed_get_attr_count
#define CMS_signed_get_attr_count __NS_SYMBOL(CMS_signed_get_attr_count)
#endif

#ifndef CMS_stream
#define CMS_stream __NS_SYMBOL(CMS_stream)
#endif

#ifndef COMP_CTX_new
#define COMP_CTX_new __NS_SYMBOL(COMP_CTX_new)
#endif

#ifndef COMP_rle
#define COMP_rle __NS_SYMBOL(COMP_rle)
#endif

#ifndef COMP_zlib
#define COMP_zlib __NS_SYMBOL(COMP_zlib)
#endif

#ifndef CONF_modules_load
#define CONF_modules_load __NS_SYMBOL(CONF_modules_load)
#endif

#ifndef CONF_set_nconf
#define CONF_set_nconf __NS_SYMBOL(CONF_set_nconf)
#endif

#ifndef CRYPTO_cbc128_encrypt
#define CRYPTO_cbc128_encrypt __NS_SYMBOL(CRYPTO_cbc128_encrypt)
#endif

#ifndef CRYPTO_ccm128_init
#define CRYPTO_ccm128_init __NS_SYMBOL(CRYPTO_ccm128_init)
#endif

#ifndef CRYPTO_cfb128_encrypt
#define CRYPTO_cfb128_encrypt __NS_SYMBOL(CRYPTO_cfb128_encrypt)
#endif

#ifndef CRYPTO_ctr128_encrypt
#define CRYPTO_ctr128_encrypt __NS_SYMBOL(CRYPTO_ctr128_encrypt)
#endif

#ifndef CRYPTO_cts128_encrypt_block
#define CRYPTO_cts128_encrypt_block __NS_SYMBOL(CRYPTO_cts128_encrypt_block)
#endif

#ifndef CRYPTO_gcm128_init
#define CRYPTO_gcm128_init __NS_SYMBOL(CRYPTO_gcm128_init)
#endif

#ifndef CRYPTO_get_ex_data_implementation
#define CRYPTO_get_ex_data_implementation __NS_SYMBOL(CRYPTO_get_ex_data_implementation)
#endif

#ifndef CRYPTO_get_new_lockid
#define CRYPTO_get_new_lockid __NS_SYMBOL(CRYPTO_get_new_lockid)
#endif

#ifndef CRYPTO_mem_ctrl
#define CRYPTO_mem_ctrl __NS_SYMBOL(CRYPTO_mem_ctrl)
#endif

#ifndef CRYPTO_ofb128_encrypt
#define CRYPTO_ofb128_encrypt __NS_SYMBOL(CRYPTO_ofb128_encrypt)
#endif

#ifndef CRYPTO_set_mem_functions
#define CRYPTO_set_mem_functions __NS_SYMBOL(CRYPTO_set_mem_functions)
#endif

#ifndef CRYPTO_xts128_encrypt
#define CRYPTO_xts128_encrypt __NS_SYMBOL(CRYPTO_xts128_encrypt)
#endif

#ifndef Camellia_EncryptBlock
#define Camellia_EncryptBlock __NS_SYMBOL(Camellia_EncryptBlock)
#endif

#ifndef Camellia_cfb128_encrypt
#define Camellia_cfb128_encrypt __NS_SYMBOL(Camellia_cfb128_encrypt)
#endif

#ifndef Camellia_ctr128_encrypt
#define Camellia_ctr128_encrypt __NS_SYMBOL(Camellia_ctr128_encrypt)
#endif

#ifndef Camellia_ecb_encrypt
#define Camellia_ecb_encrypt __NS_SYMBOL(Camellia_ecb_encrypt)
#endif

#ifndef Camellia_ofb128_encrypt
#define Camellia_ofb128_encrypt __NS_SYMBOL(Camellia_ofb128_encrypt)
#endif

#ifndef Camellia_set_key
#define Camellia_set_key __NS_SYMBOL(Camellia_set_key)
#endif

#ifndef DES_cbc_cksum
#define DES_cbc_cksum __NS_SYMBOL(DES_cbc_cksum)
#endif

#ifndef DES_cbc_encrypt
#define DES_cbc_encrypt __NS_SYMBOL(DES_cbc_encrypt)
#endif

#ifndef DES_cfb64_encrypt
#define DES_cfb64_encrypt __NS_SYMBOL(DES_cfb64_encrypt)
#endif

#ifndef DES_cfb_encrypt
#define DES_cfb_encrypt __NS_SYMBOL(DES_cfb_encrypt)
#endif

#ifndef DES_crypt
#define DES_crypt __NS_SYMBOL(DES_crypt)
#endif

#ifndef DES_ecb3_encrypt
#define DES_ecb3_encrypt __NS_SYMBOL(DES_ecb3_encrypt)
#endif

#ifndef DES_ede3_cbcm_encrypt
#define DES_ede3_cbcm_encrypt __NS_SYMBOL(DES_ede3_cbcm_encrypt)
#endif

#ifndef DES_ede3_cfb64_encrypt
#define DES_ede3_cfb64_encrypt __NS_SYMBOL(DES_ede3_cfb64_encrypt)
#endif

#ifndef DES_ede3_ofb64_encrypt
#define DES_ede3_ofb64_encrypt __NS_SYMBOL(DES_ede3_ofb64_encrypt)
#endif

#ifndef DES_enc_read
#define DES_enc_read __NS_SYMBOL(DES_enc_read)
#endif

#ifndef DES_enc_write
#define DES_enc_write __NS_SYMBOL(DES_enc_write)
#endif

#ifndef DES_encrypt1
#define DES_encrypt1 __NS_SYMBOL(DES_encrypt1)
#endif

#ifndef DES_ofb64_encrypt
#define DES_ofb64_encrypt __NS_SYMBOL(DES_ofb64_encrypt)
#endif

#ifndef DES_ofb_encrypt
#define DES_ofb_encrypt __NS_SYMBOL(DES_ofb_encrypt)
#endif

#ifndef DES_options
#define DES_options __NS_SYMBOL(DES_options)
#endif

#ifndef DES_pcbc_encrypt
#define DES_pcbc_encrypt __NS_SYMBOL(DES_pcbc_encrypt)
#endif

#ifndef DES_quad_cksum
#define DES_quad_cksum __NS_SYMBOL(DES_quad_cksum)
#endif

#ifndef DES_random_key
#define DES_random_key __NS_SYMBOL(DES_random_key)
#endif

#ifndef DES_read_password
#define DES_read_password __NS_SYMBOL(DES_read_password)
#endif

#ifndef DES_set_odd_parity
#define DES_set_odd_parity __NS_SYMBOL(DES_set_odd_parity)
#endif

#ifndef DES_string_to_key
#define DES_string_to_key __NS_SYMBOL(DES_string_to_key)
#endif

#ifndef DES_xcbc_encrypt
#define DES_xcbc_encrypt __NS_SYMBOL(DES_xcbc_encrypt)
#endif

#ifndef DH_check
#define DH_check __NS_SYMBOL(DH_check)
#endif

#ifndef DH_generate_key
#define DH_generate_key __NS_SYMBOL(DH_generate_key)
#endif

#ifndef DH_generate_parameters
#define DH_generate_parameters __NS_SYMBOL(DH_generate_parameters)
#endif

#ifndef DH_generate_parameters_ex
#define DH_generate_parameters_ex __NS_SYMBOL(DH_generate_parameters_ex)
#endif

#ifndef DH_set_default_method
#define DH_set_default_method __NS_SYMBOL(DH_set_default_method)
#endif

#ifndef DHparams_print
#define DHparams_print __NS_SYMBOL(DHparams_print)
#endif

#ifndef DHparams_print_fp
#define DHparams_print_fp __NS_SYMBOL(DHparams_print_fp)
#endif

#ifndef DSA_OpenSSL
#define DSA_OpenSSL __NS_SYMBOL(DSA_OpenSSL)
#endif

#ifndef DSA_do_sign
#define DSA_do_sign __NS_SYMBOL(DSA_do_sign)
#endif

#ifndef DSA_do_verify
#define DSA_do_verify __NS_SYMBOL(DSA_do_verify)
#endif

#ifndef DSA_generate_key
#define DSA_generate_key __NS_SYMBOL(DSA_generate_key)
#endif

#ifndef DSA_generate_parameters
#define DSA_generate_parameters __NS_SYMBOL(DSA_generate_parameters)
#endif

#ifndef DSA_generate_parameters_ex
#define DSA_generate_parameters_ex __NS_SYMBOL(DSA_generate_parameters_ex)
#endif

#ifndef DSA_print_fp
#define DSA_print_fp __NS_SYMBOL(DSA_print_fp)
#endif

#ifndef DSA_set_default_method
#define DSA_set_default_method __NS_SYMBOL(DSA_set_default_method)
#endif

#ifndef DSO_METHOD_beos
#define DSO_METHOD_beos __NS_SYMBOL(DSO_METHOD_beos)
#endif

#ifndef DSO_METHOD_dl
#define DSO_METHOD_dl __NS_SYMBOL(DSO_METHOD_dl)
#endif

#ifndef DSO_METHOD_dlfcn
#define DSO_METHOD_dlfcn __NS_SYMBOL(DSO_METHOD_dlfcn)
#endif

#ifndef DSO_METHOD_null
#define DSO_METHOD_null __NS_SYMBOL(DSO_METHOD_null)
#endif

#ifndef DSO_METHOD_openssl
#define DSO_METHOD_openssl __NS_SYMBOL(DSO_METHOD_openssl)
#endif

#ifndef DSO_METHOD_vms
#define DSO_METHOD_vms __NS_SYMBOL(DSO_METHOD_vms)
#endif

#ifndef DSO_METHOD_win32
#define DSO_METHOD_win32 __NS_SYMBOL(DSO_METHOD_win32)
#endif

#ifndef DSO_new
#define DSO_new __NS_SYMBOL(DSO_new)
#endif

#ifndef ECDH_OpenSSL
#define ECDH_OpenSSL __NS_SYMBOL(ECDH_OpenSSL)
#endif

#ifndef ECDH_compute_key
#define ECDH_compute_key __NS_SYMBOL(ECDH_compute_key)
#endif

#ifndef ECDH_set_default_method
#define ECDH_set_default_method __NS_SYMBOL(ECDH_set_default_method)
#endif

#ifndef ECDSA_OpenSSL
#define ECDSA_OpenSSL __NS_SYMBOL(ECDSA_OpenSSL)
#endif

#ifndef ECDSA_do_sign
#define ECDSA_do_sign __NS_SYMBOL(ECDSA_do_sign)
#endif

#ifndef ECDSA_do_verify
#define ECDSA_do_verify __NS_SYMBOL(ECDSA_do_verify)
#endif

#ifndef ECDSA_set_default_method
#define ECDSA_set_default_method __NS_SYMBOL(ECDSA_set_default_method)
#endif

#ifndef ECPKParameters_print_fp
#define ECPKParameters_print_fp __NS_SYMBOL(ECPKParameters_print_fp)
#endif

#ifndef EC_GF2m_simple_method
#define EC_GF2m_simple_method __NS_SYMBOL(EC_GF2m_simple_method)
#endif

#ifndef EC_GFp_mont_method
#define EC_GFp_mont_method __NS_SYMBOL(EC_GFp_mont_method)
#endif

#ifndef EC_GFp_nist_method
#define EC_GFp_nist_method __NS_SYMBOL(EC_GFp_nist_method)
#endif

#ifndef EC_GFp_simple_method
#define EC_GFp_simple_method __NS_SYMBOL(EC_GFp_simple_method)
#endif

#ifndef EC_GROUP_check
#define EC_GROUP_check __NS_SYMBOL(EC_GROUP_check)
#endif

#ifndef EC_GROUP_get_basis_type
#define EC_GROUP_get_basis_type __NS_SYMBOL(EC_GROUP_get_basis_type)
#endif

#ifndef EC_GROUP_new
#define EC_GROUP_new __NS_SYMBOL(EC_GROUP_new)
#endif

#ifndef EC_GROUP_new_by_curve_name
#define EC_GROUP_new_by_curve_name __NS_SYMBOL(EC_GROUP_new_by_curve_name)
#endif

#ifndef EC_GROUP_new_curve_GFp
#define EC_GROUP_new_curve_GFp __NS_SYMBOL(EC_GROUP_new_curve_GFp)
#endif

#ifndef EC_KEY_new
#define EC_KEY_new __NS_SYMBOL(EC_KEY_new)
#endif

#ifndef EC_POINT_point2bn
#define EC_POINT_point2bn __NS_SYMBOL(EC_POINT_point2bn)
#endif

#ifndef EC_POINT_set_compressed_coordinates_GFp
#define EC_POINT_set_compressed_coordinates_GFp __NS_SYMBOL(EC_POINT_set_compressed_coordinates_GFp)
#endif

#ifndef ENGINE_add_conf_module
#define ENGINE_add_conf_module __NS_SYMBOL(ENGINE_add_conf_module)
#endif

#ifndef ENGINE_ctrl
#define ENGINE_ctrl __NS_SYMBOL(ENGINE_ctrl)
#endif

#ifndef ENGINE_get_first
#define ENGINE_get_first __NS_SYMBOL(ENGINE_get_first)
#endif

#ifndef ENGINE_get_table_flags
#define ENGINE_get_table_flags __NS_SYMBOL(ENGINE_get_table_flags)
#endif

#ifndef ENGINE_load_4758cca
#define ENGINE_load_4758cca __NS_SYMBOL(ENGINE_load_4758cca)
#endif

#ifndef ENGINE_load_aep
#define ENGINE_load_aep __NS_SYMBOL(ENGINE_load_aep)
#endif

#ifndef ENGINE_load_atalla
#define ENGINE_load_atalla __NS_SYMBOL(ENGINE_load_atalla)
#endif

#ifndef ENGINE_load_builtin_engines
#define ENGINE_load_builtin_engines __NS_SYMBOL(ENGINE_load_builtin_engines)
#endif

#ifndef ENGINE_load_capi
#define ENGINE_load_capi __NS_SYMBOL(ENGINE_load_capi)
#endif

#ifndef ENGINE_load_chil
#define ENGINE_load_chil __NS_SYMBOL(ENGINE_load_chil)
#endif

#ifndef ENGINE_load_cryptodev
#define ENGINE_load_cryptodev __NS_SYMBOL(ENGINE_load_cryptodev)
#endif

#ifndef ENGINE_load_cswift
#define ENGINE_load_cswift __NS_SYMBOL(ENGINE_load_cswift)
#endif

#ifndef ENGINE_load_dynamic
#define ENGINE_load_dynamic __NS_SYMBOL(ENGINE_load_dynamic)
#endif

#ifndef ENGINE_load_gost
#define ENGINE_load_gost __NS_SYMBOL(ENGINE_load_gost)
#endif

#ifndef ENGINE_load_nuron
#define ENGINE_load_nuron __NS_SYMBOL(ENGINE_load_nuron)
#endif

#ifndef ENGINE_load_openssl
#define ENGINE_load_openssl __NS_SYMBOL(ENGINE_load_openssl)
#endif

#ifndef ENGINE_load_padlock
#define ENGINE_load_padlock __NS_SYMBOL(ENGINE_load_padlock)
#endif

#ifndef ENGINE_load_rdrand
#define ENGINE_load_rdrand __NS_SYMBOL(ENGINE_load_rdrand)
#endif

#ifndef ENGINE_load_rsax
#define ENGINE_load_rsax __NS_SYMBOL(ENGINE_load_rsax)
#endif

#ifndef ENGINE_load_sureware
#define ENGINE_load_sureware __NS_SYMBOL(ENGINE_load_sureware)
#endif

#ifndef ENGINE_load_ubsec
#define ENGINE_load_ubsec __NS_SYMBOL(ENGINE_load_ubsec)
#endif

#ifndef ENGINE_new
#define ENGINE_new __NS_SYMBOL(ENGINE_new)
#endif

#ifndef ENGINE_set_default
#define ENGINE_set_default __NS_SYMBOL(ENGINE_set_default)
#endif

#ifndef ENGINE_set_load_privkey_function
#define ENGINE_set_load_privkey_function __NS_SYMBOL(ENGINE_set_load_privkey_function)
#endif

#ifndef ENGINE_unregister_DH
#define ENGINE_unregister_DH __NS_SYMBOL(ENGINE_unregister_DH)
#endif

#ifndef ENGINE_unregister_DSA
#define ENGINE_unregister_DSA __NS_SYMBOL(ENGINE_unregister_DSA)
#endif

#ifndef ENGINE_unregister_ECDH
#define ENGINE_unregister_ECDH __NS_SYMBOL(ENGINE_unregister_ECDH)
#endif

#ifndef ENGINE_unregister_ECDSA
#define ENGINE_unregister_ECDSA __NS_SYMBOL(ENGINE_unregister_ECDSA)
#endif

#ifndef ENGINE_unregister_RAND
#define ENGINE_unregister_RAND __NS_SYMBOL(ENGINE_unregister_RAND)
#endif

#ifndef ENGINE_unregister_RSA
#define ENGINE_unregister_RSA __NS_SYMBOL(ENGINE_unregister_RSA)
#endif

#ifndef ENGINE_unregister_STORE
#define ENGINE_unregister_STORE __NS_SYMBOL(ENGINE_unregister_STORE)
#endif

#ifndef ENGINE_unregister_ciphers
#define ENGINE_unregister_ciphers __NS_SYMBOL(ENGINE_unregister_ciphers)
#endif

#ifndef ENGINE_unregister_digests
#define ENGINE_unregister_digests __NS_SYMBOL(ENGINE_unregister_digests)
#endif

#ifndef ENGINE_unregister_pkey_asn1_meths
#define ENGINE_unregister_pkey_asn1_meths __NS_SYMBOL(ENGINE_unregister_pkey_asn1_meths)
#endif

#ifndef ENGINE_unregister_pkey_meths
#define ENGINE_unregister_pkey_meths __NS_SYMBOL(ENGINE_unregister_pkey_meths)
#endif

#ifndef ERR_get_implementation
#define ERR_get_implementation __NS_SYMBOL(ERR_get_implementation)
#endif

#ifndef ERR_load_ASN1_strings
#define ERR_load_ASN1_strings __NS_SYMBOL(ERR_load_ASN1_strings)
#endif

#ifndef ERR_load_BIO_strings
#define ERR_load_BIO_strings __NS_SYMBOL(ERR_load_BIO_strings)
#endif

#ifndef ERR_load_BN_strings
#define ERR_load_BN_strings __NS_SYMBOL(ERR_load_BN_strings)
#endif

#ifndef ERR_load_BUF_strings
#define ERR_load_BUF_strings __NS_SYMBOL(ERR_load_BUF_strings)
#endif

#ifndef ERR_load_CMS_strings
#define ERR_load_CMS_strings __NS_SYMBOL(ERR_load_CMS_strings)
#endif

#ifndef ERR_load_COMP_strings
#define ERR_load_COMP_strings __NS_SYMBOL(ERR_load_COMP_strings)
#endif

#ifndef ERR_load_CONF_strings
#define ERR_load_CONF_strings __NS_SYMBOL(ERR_load_CONF_strings)
#endif

#ifndef ERR_load_CRYPTO_strings
#define ERR_load_CRYPTO_strings __NS_SYMBOL(ERR_load_CRYPTO_strings)
#endif

#ifndef ERR_load_DH_strings
#define ERR_load_DH_strings __NS_SYMBOL(ERR_load_DH_strings)
#endif

#ifndef ERR_load_DSA_strings
#define ERR_load_DSA_strings __NS_SYMBOL(ERR_load_DSA_strings)
#endif

#ifndef ERR_load_DSO_strings
#define ERR_load_DSO_strings __NS_SYMBOL(ERR_load_DSO_strings)
#endif

#ifndef ERR_load_ECDH_strings
#define ERR_load_ECDH_strings __NS_SYMBOL(ERR_load_ECDH_strings)
#endif

#ifndef ERR_load_ECDSA_strings
#define ERR_load_ECDSA_strings __NS_SYMBOL(ERR_load_ECDSA_strings)
#endif

#ifndef ERR_load_EC_strings
#define ERR_load_EC_strings __NS_SYMBOL(ERR_load_EC_strings)
#endif

#ifndef ERR_load_ENGINE_strings
#define ERR_load_ENGINE_strings __NS_SYMBOL(ERR_load_ENGINE_strings)
#endif

#ifndef ERR_load_EVP_strings
#define ERR_load_EVP_strings __NS_SYMBOL(ERR_load_EVP_strings)
#endif

#ifndef ERR_load_GOST_strings
#define ERR_load_GOST_strings __NS_SYMBOL(ERR_load_GOST_strings)
#endif

#ifndef ERR_load_OBJ_strings
#define ERR_load_OBJ_strings __NS_SYMBOL(ERR_load_OBJ_strings)
#endif

#ifndef ERR_load_OCSP_strings
#define ERR_load_OCSP_strings __NS_SYMBOL(ERR_load_OCSP_strings)
#endif

#ifndef ERR_load_PEM_strings
#define ERR_load_PEM_strings __NS_SYMBOL(ERR_load_PEM_strings)
#endif

#ifndef ERR_load_PKCS12_strings
#define ERR_load_PKCS12_strings __NS_SYMBOL(ERR_load_PKCS12_strings)
#endif

#ifndef ERR_load_PKCS7_strings
#define ERR_load_PKCS7_strings __NS_SYMBOL(ERR_load_PKCS7_strings)
#endif

#ifndef ERR_load_RAND_strings
#define ERR_load_RAND_strings __NS_SYMBOL(ERR_load_RAND_strings)
#endif

#ifndef ERR_load_RSA_strings
#define ERR_load_RSA_strings __NS_SYMBOL(ERR_load_RSA_strings)
#endif

#ifndef ERR_load_TS_strings
#define ERR_load_TS_strings __NS_SYMBOL(ERR_load_TS_strings)
#endif

#ifndef ERR_load_UI_strings
#define ERR_load_UI_strings __NS_SYMBOL(ERR_load_UI_strings)
#endif

#ifndef ERR_load_X509V3_strings
#define ERR_load_X509V3_strings __NS_SYMBOL(ERR_load_X509V3_strings)
#endif

#ifndef ERR_load_X509_strings
#define ERR_load_X509_strings __NS_SYMBOL(ERR_load_X509_strings)
#endif

#ifndef ERR_load_crypto_strings
#define ERR_load_crypto_strings __NS_SYMBOL(ERR_load_crypto_strings)
#endif

#ifndef ERR_print_errors_cb
#define ERR_print_errors_cb __NS_SYMBOL(ERR_print_errors_cb)
#endif

#ifndef EVP_CIPHER_CTX_init
#define EVP_CIPHER_CTX_init __NS_SYMBOL(EVP_CIPHER_CTX_init)
#endif

#ifndef EVP_CIPHER_param_to_asn1
#define EVP_CIPHER_param_to_asn1 __NS_SYMBOL(EVP_CIPHER_param_to_asn1)
#endif

#ifndef EVP_DigestSignInit
#define EVP_DigestSignInit __NS_SYMBOL(EVP_DigestSignInit)
#endif

#ifndef EVP_EncodeInit
#define EVP_EncodeInit __NS_SYMBOL(EVP_EncodeInit)
#endif

#ifndef EVP_MD_CTX_init
#define EVP_MD_CTX_init __NS_SYMBOL(EVP_MD_CTX_init)
#endif

#ifndef EVP_OpenInit
#define EVP_OpenInit __NS_SYMBOL(EVP_OpenInit)
#endif

#ifndef EVP_PBE_CipherInit
#define EVP_PBE_CipherInit __NS_SYMBOL(EVP_PBE_CipherInit)
#endif

#ifndef EVP_PKCS82PKEY
#define EVP_PKCS82PKEY __NS_SYMBOL(EVP_PKCS82PKEY)
#endif

#ifndef EVP_PKEY_asn1_get_count
#define EVP_PKEY_asn1_get_count __NS_SYMBOL(EVP_PKEY_asn1_get_count)
#endif

#ifndef EVP_PKEY_bits
#define EVP_PKEY_bits __NS_SYMBOL(EVP_PKEY_bits)
#endif

#ifndef EVP_PKEY_decrypt_old
#define EVP_PKEY_decrypt_old __NS_SYMBOL(EVP_PKEY_decrypt_old)
#endif

#ifndef EVP_PKEY_encrypt_old
#define EVP_PKEY_encrypt_old __NS_SYMBOL(EVP_PKEY_encrypt_old)
#endif

#ifndef EVP_PKEY_meth_find
#define EVP_PKEY_meth_find __NS_SYMBOL(EVP_PKEY_meth_find)
#endif

#ifndef EVP_PKEY_paramgen_init
#define EVP_PKEY_paramgen_init __NS_SYMBOL(EVP_PKEY_paramgen_init)
#endif

#ifndef EVP_PKEY_sign_init
#define EVP_PKEY_sign_init __NS_SYMBOL(EVP_PKEY_sign_init)
#endif

#ifndef EVP_SealInit
#define EVP_SealInit __NS_SYMBOL(EVP_SealInit)
#endif

#ifndef EVP_SignFinal
#define EVP_SignFinal __NS_SYMBOL(EVP_SignFinal)
#endif

#ifndef EVP_VerifyFinal
#define EVP_VerifyFinal __NS_SYMBOL(EVP_VerifyFinal)
#endif

#ifndef EVP_add_alg_module
#define EVP_add_alg_module __NS_SYMBOL(EVP_add_alg_module)
#endif

#ifndef EVP_add_cipher
#define EVP_add_cipher __NS_SYMBOL(EVP_add_cipher)
#endif

#ifndef EVP_aes_128_cbc
#define EVP_aes_128_cbc __NS_SYMBOL(EVP_aes_128_cbc)
#endif

#ifndef EVP_aes_128_cbc_hmac_sha1
#define EVP_aes_128_cbc_hmac_sha1 __NS_SYMBOL(EVP_aes_128_cbc_hmac_sha1)
#endif

#ifndef EVP_bf_cbc
#define EVP_bf_cbc __NS_SYMBOL(EVP_bf_cbc)
#endif

#ifndef EVP_bf_cfb
#define EVP_bf_cfb __NS_SYMBOL(EVP_bf_cfb)
#endif

#ifndef EVP_camellia_128_cbc
#define EVP_camellia_128_cbc __NS_SYMBOL(EVP_camellia_128_cbc)
#endif

#ifndef EVP_cast5_cbc
#define EVP_cast5_cbc __NS_SYMBOL(EVP_cast5_cbc)
#endif

#ifndef EVP_des_cbc
#define EVP_des_cbc __NS_SYMBOL(EVP_des_cbc)
#endif

#ifndef EVP_des_ede_cbc
#define EVP_des_ede_cbc __NS_SYMBOL(EVP_des_ede_cbc)
#endif

#ifndef EVP_desx_cbc
#define EVP_desx_cbc __NS_SYMBOL(EVP_desx_cbc)
#endif

#ifndef EVP_dss
#define EVP_dss __NS_SYMBOL(EVP_dss)
#endif

#ifndef EVP_dss1
#define EVP_dss1 __NS_SYMBOL(EVP_dss1)
#endif

#ifndef EVP_ecdsa
#define EVP_ecdsa __NS_SYMBOL(EVP_ecdsa)
#endif

#ifndef EVP_enc_null
#define EVP_enc_null __NS_SYMBOL(EVP_enc_null)
#endif

#ifndef EVP_idea_cbc
#define EVP_idea_cbc __NS_SYMBOL(EVP_idea_cbc)
#endif

#ifndef EVP_md4
#define EVP_md4 __NS_SYMBOL(EVP_md4)
#endif

#ifndef EVP_md5
#define EVP_md5 __NS_SYMBOL(EVP_md5)
#endif

#ifndef EVP_md_null
#define EVP_md_null __NS_SYMBOL(EVP_md_null)
#endif

#ifndef EVP_mdc2
#define EVP_mdc2 __NS_SYMBOL(EVP_mdc2)
#endif

#ifndef EVP_rc2_cbc
#define EVP_rc2_cbc __NS_SYMBOL(EVP_rc2_cbc)
#endif

#ifndef EVP_rc4
#define EVP_rc4 __NS_SYMBOL(EVP_rc4)
#endif

#ifndef EVP_rc4_hmac_md5
#define EVP_rc4_hmac_md5 __NS_SYMBOL(EVP_rc4_hmac_md5)
#endif

#ifndef EVP_ripemd160
#define EVP_ripemd160 __NS_SYMBOL(EVP_ripemd160)
#endif

#ifndef EVP_seed_cbc
#define EVP_seed_cbc __NS_SYMBOL(EVP_seed_cbc)
#endif

#ifndef EVP_set_pw_prompt
#define EVP_set_pw_prompt __NS_SYMBOL(EVP_set_pw_prompt)
#endif

#ifndef EVP_sha
#define EVP_sha __NS_SYMBOL(EVP_sha)
#endif

#ifndef EVP_sha1
#define EVP_sha1 __NS_SYMBOL(EVP_sha1)
#endif

#ifndef EVP_whirlpool
#define EVP_whirlpool __NS_SYMBOL(EVP_whirlpool)
#endif

#ifndef FIPS_mode
#define FIPS_mode __NS_SYMBOL(FIPS_mode)
#endif

#ifndef HMAC_Init_ex
#define HMAC_Init_ex __NS_SYMBOL(HMAC_Init_ex)
#endif

#ifndef MD4
#define MD4 __NS_SYMBOL(MD4)
#endif

#ifndef MD4_Update
#define MD4_Update __NS_SYMBOL(MD4_Update)
#endif

#ifndef MD5
#define MD5 __NS_SYMBOL(MD5)
#endif

#ifndef MD5_Update
#define MD5_Update __NS_SYMBOL(MD5_Update)
#endif

#ifndef MDC2
#define MDC2 __NS_SYMBOL(MDC2)
#endif

#ifndef MDC2_Init
#define MDC2_Init __NS_SYMBOL(MDC2_Init)
#endif

#ifndef NCONF_default
#define NCONF_default __NS_SYMBOL(NCONF_default)
#endif

#ifndef NETSCAPE_SPKI_print
#define NETSCAPE_SPKI_print __NS_SYMBOL(NETSCAPE_SPKI_print)
#endif

#ifndef NETSCAPE_SPKI_set_pubkey
#define NETSCAPE_SPKI_set_pubkey __NS_SYMBOL(NETSCAPE_SPKI_set_pubkey)
#endif

#ifndef OBJ_NAME_init
#define OBJ_NAME_init __NS_SYMBOL(OBJ_NAME_init)
#endif

#ifndef OBJ_dup
#define OBJ_dup __NS_SYMBOL(OBJ_dup)
#endif

#ifndef OBJ_find_sigid_algs
#define OBJ_find_sigid_algs __NS_SYMBOL(OBJ_find_sigid_algs)
#endif

#ifndef OCSP_REQUEST_get_ext_count
#define OCSP_REQUEST_get_ext_count __NS_SYMBOL(OCSP_REQUEST_get_ext_count)
#endif

#ifndef OCSP_REQ_CTX_free
#define OCSP_REQ_CTX_free __NS_SYMBOL(OCSP_REQ_CTX_free)
#endif

#ifndef OCSP_basic_verify
#define OCSP_basic_verify __NS_SYMBOL(OCSP_basic_verify)
#endif

#ifndef OCSP_cert_to_id
#define OCSP_cert_to_id __NS_SYMBOL(OCSP_cert_to_id)
#endif

#ifndef OCSP_request_add0_id
#define OCSP_request_add0_id __NS_SYMBOL(OCSP_request_add0_id)
#endif

#ifndef OCSP_request_onereq_count
#define OCSP_request_onereq_count __NS_SYMBOL(OCSP_request_onereq_count)
#endif

#ifndef OCSP_response_status_str
#define OCSP_response_status_str __NS_SYMBOL(OCSP_response_status_str)
#endif

#ifndef OPENSSL_DIR_read
#define OPENSSL_DIR_read __NS_SYMBOL(OPENSSL_DIR_read)
#endif

#ifndef OPENSSL_add_all_algorithms_conf
#define OPENSSL_add_all_algorithms_conf __NS_SYMBOL(OPENSSL_add_all_algorithms_conf)
#endif

#ifndef OPENSSL_add_all_algorithms_noconf
#define OPENSSL_add_all_algorithms_noconf __NS_SYMBOL(OPENSSL_add_all_algorithms_noconf)
#endif

#ifndef OPENSSL_asc2uni
#define OPENSSL_asc2uni __NS_SYMBOL(OPENSSL_asc2uni)
#endif

#ifndef OPENSSL_atomic_add
#define OPENSSL_atomic_add __NS_SYMBOL(OPENSSL_atomic_add)
#endif

#ifndef OPENSSL_config
#define OPENSSL_config __NS_SYMBOL(OPENSSL_config)
#endif

#ifndef OPENSSL_gmtime
#define OPENSSL_gmtime __NS_SYMBOL(OPENSSL_gmtime)
#endif

#ifndef OPENSSL_init
#define OPENSSL_init __NS_SYMBOL(OPENSSL_init)
#endif

#ifndef OPENSSL_issetugid
#define OPENSSL_issetugid __NS_SYMBOL(OPENSSL_issetugid)
#endif

#ifndef OPENSSL_load_builtin_modules
#define OPENSSL_load_builtin_modules __NS_SYMBOL(OPENSSL_load_builtin_modules)
#endif

#ifndef OPENSSL_strncasecmp
#define OPENSSL_strncasecmp __NS_SYMBOL(OPENSSL_strncasecmp)
#endif

#ifndef OpenSSL_add_all_ciphers
#define OpenSSL_add_all_ciphers __NS_SYMBOL(OpenSSL_add_all_ciphers)
#endif

#ifndef OpenSSL_add_all_digests
#define OpenSSL_add_all_digests __NS_SYMBOL(OpenSSL_add_all_digests)
#endif

#ifndef PEM_ASN1_read_bio
#define PEM_ASN1_read_bio __NS_SYMBOL(PEM_ASN1_read_bio)
#endif

#ifndef PEM_SealInit
#define PEM_SealInit __NS_SYMBOL(PEM_SealInit)
#endif

#ifndef PEM_SignInit
#define PEM_SignInit __NS_SYMBOL(PEM_SignInit)
#endif

#ifndef PEM_X509_INFO_read
#define PEM_X509_INFO_read __NS_SYMBOL(PEM_X509_INFO_read)
#endif

#ifndef PEM_def_callback
#define PEM_def_callback __NS_SYMBOL(PEM_def_callback)
#endif

#ifndef PEM_read_bio_PrivateKey
#define PEM_read_bio_PrivateKey __NS_SYMBOL(PEM_read_bio_PrivateKey)
#endif

#ifndef PEM_read_bio_X509
#define PEM_read_bio_X509 __NS_SYMBOL(PEM_read_bio_X509)
#endif

#ifndef PEM_read_bio_X509_AUX
#define PEM_read_bio_X509_AUX __NS_SYMBOL(PEM_read_bio_X509_AUX)
#endif

#ifndef PEM_read_bio_X509_REQ
#define PEM_read_bio_X509_REQ __NS_SYMBOL(PEM_read_bio_X509_REQ)
#endif

#ifndef PEM_write_bio_PKCS8PrivateKey_nid
#define PEM_write_bio_PKCS8PrivateKey_nid __NS_SYMBOL(PEM_write_bio_PKCS8PrivateKey_nid)
#endif

#ifndef PKCS12_PBE_add
#define PKCS12_PBE_add __NS_SYMBOL(PKCS12_PBE_add)
#endif

#ifndef PKCS12_add_localkeyid
#define PKCS12_add_localkeyid __NS_SYMBOL(PKCS12_add_localkeyid)
#endif

#ifndef PKCS12_create
#define PKCS12_create __NS_SYMBOL(PKCS12_create)
#endif

#ifndef PKCS12_gen_mac
#define PKCS12_gen_mac __NS_SYMBOL(PKCS12_gen_mac)
#endif

#ifndef PKCS12_init
#define PKCS12_init __NS_SYMBOL(PKCS12_init)
#endif

#ifndef PKCS12_item_pack_safebag
#define PKCS12_item_pack_safebag __NS_SYMBOL(PKCS12_item_pack_safebag)
#endif

#ifndef PKCS12_key_gen_asc
#define PKCS12_key_gen_asc __NS_SYMBOL(PKCS12_key_gen_asc)
#endif

#ifndef PKCS12_newpass
#define PKCS12_newpass __NS_SYMBOL(PKCS12_newpass)
#endif

#ifndef PKCS12_parse
#define PKCS12_parse __NS_SYMBOL(PKCS12_parse)
#endif

#ifndef PKCS12_pbe_crypt
#define PKCS12_pbe_crypt __NS_SYMBOL(PKCS12_pbe_crypt)
#endif

#ifndef PKCS5_PBE_add
#define PKCS5_PBE_add __NS_SYMBOL(PKCS5_PBE_add)
#endif

#ifndef PKCS5_PBKDF2_HMAC
#define PKCS5_PBKDF2_HMAC __NS_SYMBOL(PKCS5_PBKDF2_HMAC)
#endif

#ifndef PKCS7_add_attrib_smimecap
#define PKCS7_add_attrib_smimecap __NS_SYMBOL(PKCS7_add_attrib_smimecap)
#endif

#ifndef PKCS7_ctrl
#define PKCS7_ctrl __NS_SYMBOL(PKCS7_ctrl)
#endif

#ifndef PKCS7_dataInit
#define PKCS7_dataInit __NS_SYMBOL(PKCS7_dataInit)
#endif

#ifndef PKCS7_sign
#define PKCS7_sign __NS_SYMBOL(PKCS7_sign)
#endif

#ifndef PKCS8_decrypt
#define PKCS8_decrypt __NS_SYMBOL(PKCS8_decrypt)
#endif

#ifndef PKCS8_encrypt
#define PKCS8_encrypt __NS_SYMBOL(PKCS8_encrypt)
#endif

#ifndef RAND_load_file
#define RAND_load_file __NS_SYMBOL(RAND_load_file)
#endif

#ifndef RAND_poll
#define RAND_poll __NS_SYMBOL(RAND_poll)
#endif

#ifndef RAND_query_egd_bytes
#define RAND_query_egd_bytes __NS_SYMBOL(RAND_query_egd_bytes)
#endif

#ifndef RAND_set_rand_method
#define RAND_set_rand_method __NS_SYMBOL(RAND_set_rand_method)
#endif

#ifndef RC2_cbc_encrypt
#define RC2_cbc_encrypt __NS_SYMBOL(RC2_cbc_encrypt)
#endif

#ifndef RC2_cfb64_encrypt
#define RC2_cfb64_encrypt __NS_SYMBOL(RC2_cfb64_encrypt)
#endif

#ifndef RC2_ecb_encrypt
#define RC2_ecb_encrypt __NS_SYMBOL(RC2_ecb_encrypt)
#endif

#ifndef RC2_ofb64_encrypt
#define RC2_ofb64_encrypt __NS_SYMBOL(RC2_ofb64_encrypt)
#endif

#ifndef RC2_set_key
#define RC2_set_key __NS_SYMBOL(RC2_set_key)
#endif

#ifndef RC4
#define RC4 __NS_SYMBOL(RC4)
#endif

#ifndef RC4_options
#define RC4_options __NS_SYMBOL(RC4_options)
#endif

#ifndef RC4_set_key
#define RC4_set_key __NS_SYMBOL(RC4_set_key)
#endif

#ifndef RIPEMD160
#define RIPEMD160 __NS_SYMBOL(RIPEMD160)
#endif

#ifndef RIPEMD160_Update
#define RIPEMD160_Update __NS_SYMBOL(RIPEMD160_Update)
#endif

#ifndef RSA_PKCS1_SSLeay
#define RSA_PKCS1_SSLeay __NS_SYMBOL(RSA_PKCS1_SSLeay)
#endif

#ifndef RSA_check_key
#define RSA_check_key __NS_SYMBOL(RSA_check_key)
#endif

#ifndef RSA_generate_key
#define RSA_generate_key __NS_SYMBOL(RSA_generate_key)
#endif

#ifndef RSA_generate_key_ex
#define RSA_generate_key_ex __NS_SYMBOL(RSA_generate_key_ex)
#endif

#ifndef RSA_new
#define RSA_new __NS_SYMBOL(RSA_new)
#endif

#ifndef RSA_null_method
#define RSA_null_method __NS_SYMBOL(RSA_null_method)
#endif

#ifndef RSA_padding_add_PKCS1_OAEP
#define RSA_padding_add_PKCS1_OAEP __NS_SYMBOL(RSA_padding_add_PKCS1_OAEP)
#endif

#ifndef RSA_padding_add_PKCS1_type_1
#define RSA_padding_add_PKCS1_type_1 __NS_SYMBOL(RSA_padding_add_PKCS1_type_1)
#endif

#ifndef RSA_padding_add_SSLv23
#define RSA_padding_add_SSLv23 __NS_SYMBOL(RSA_padding_add_SSLv23)
#endif

#ifndef RSA_padding_add_X931
#define RSA_padding_add_X931 __NS_SYMBOL(RSA_padding_add_X931)
#endif

#ifndef RSA_padding_add_none
#define RSA_padding_add_none __NS_SYMBOL(RSA_padding_add_none)
#endif

#ifndef RSA_print_fp
#define RSA_print_fp __NS_SYMBOL(RSA_print_fp)
#endif

#ifndef RSA_sign
#define RSA_sign __NS_SYMBOL(RSA_sign)
#endif

#ifndef RSA_sign_ASN1_OCTET_STRING
#define RSA_sign_ASN1_OCTET_STRING __NS_SYMBOL(RSA_sign_ASN1_OCTET_STRING)
#endif

#ifndef RSA_size
#define RSA_size __NS_SYMBOL(RSA_size)
#endif

#ifndef RSA_verify_PKCS1_PSS
#define RSA_verify_PKCS1_PSS __NS_SYMBOL(RSA_verify_PKCS1_PSS)
#endif

#ifndef SEED_cbc_encrypt
#define SEED_cbc_encrypt __NS_SYMBOL(SEED_cbc_encrypt)
#endif

#ifndef SEED_cfb128_encrypt
#define SEED_cfb128_encrypt __NS_SYMBOL(SEED_cfb128_encrypt)
#endif

#ifndef SEED_ecb_encrypt
#define SEED_ecb_encrypt __NS_SYMBOL(SEED_ecb_encrypt)
#endif

#ifndef SEED_ofb128_encrypt
#define SEED_ofb128_encrypt __NS_SYMBOL(SEED_ofb128_encrypt)
#endif

#ifndef SEED_set_key
#define SEED_set_key __NS_SYMBOL(SEED_set_key)
#endif

#ifndef SHA
#define SHA __NS_SYMBOL(SHA)
#endif

#ifndef SHA1
#define SHA1 __NS_SYMBOL(SHA1)
#endif

#ifndef SHA1_Update
#define SHA1_Update __NS_SYMBOL(SHA1_Update)
#endif

#ifndef SHA224_Init
#define SHA224_Init __NS_SYMBOL(SHA224_Init)
#endif

#ifndef SHA384_Init
#define SHA384_Init __NS_SYMBOL(SHA384_Init)
#endif

#ifndef SHA_Update
#define SHA_Update __NS_SYMBOL(SHA_Update)
#endif

#ifndef SRP_Calc_u
#define SRP_Calc_u __NS_SYMBOL(SRP_Calc_u)
#endif

#ifndef SRP_VBASE_new
#define SRP_VBASE_new __NS_SYMBOL(SRP_VBASE_new)
#endif

#ifndef SSLeay_version
#define SSLeay_version __NS_SYMBOL(SSLeay_version)
#endif

#ifndef TS_ASN1_INTEGER_print_bio
#define TS_ASN1_INTEGER_print_bio __NS_SYMBOL(TS_ASN1_INTEGER_print_bio)
#endif

#ifndef TS_CONF_load_cert
#define TS_CONF_load_cert __NS_SYMBOL(TS_CONF_load_cert)
#endif

#ifndef TS_REQ_print_bio
#define TS_REQ_print_bio __NS_SYMBOL(TS_REQ_print_bio)
#endif

#ifndef TS_REQ_set_version
#define TS_REQ_set_version __NS_SYMBOL(TS_REQ_set_version)
#endif

#ifndef TS_RESP_CTX_new
#define TS_RESP_CTX_new __NS_SYMBOL(TS_RESP_CTX_new)
#endif

#ifndef TS_RESP_print_bio
#define TS_RESP_print_bio __NS_SYMBOL(TS_RESP_print_bio)
#endif

#ifndef TS_RESP_set_status_info
#define TS_RESP_set_status_info __NS_SYMBOL(TS_RESP_set_status_info)
#endif

#ifndef TS_RESP_verify_signature
#define TS_RESP_verify_signature __NS_SYMBOL(TS_RESP_verify_signature)
#endif

#ifndef TS_VERIFY_CTX_new
#define TS_VERIFY_CTX_new __NS_SYMBOL(TS_VERIFY_CTX_new)
#endif

#ifndef TXT_DB_read
#define TXT_DB_read __NS_SYMBOL(TXT_DB_read)
#endif

#ifndef UI_OpenSSL
#define UI_OpenSSL __NS_SYMBOL(UI_OpenSSL)
#endif

#ifndef UI_UTIL_read_pw_string
#define UI_UTIL_read_pw_string __NS_SYMBOL(UI_UTIL_read_pw_string)
#endif

#ifndef UI_new
#define UI_new __NS_SYMBOL(UI_new)
#endif

#ifndef UTF8_getc
#define UTF8_getc __NS_SYMBOL(UTF8_getc)
#endif

#ifndef WHIRLPOOL_Init
#define WHIRLPOOL_Init __NS_SYMBOL(WHIRLPOOL_Init)
#endif

#ifndef X509V3_EXT_add
#define X509V3_EXT_add __NS_SYMBOL(X509V3_EXT_add)
#endif

#ifndef X509V3_EXT_nconf
#define X509V3_EXT_nconf __NS_SYMBOL(X509V3_EXT_nconf)
#endif

#ifndef X509V3_EXT_val_prn
#define X509V3_EXT_val_prn __NS_SYMBOL(X509V3_EXT_val_prn)
#endif

#ifndef X509V3_add_value
#define X509V3_add_value __NS_SYMBOL(X509V3_add_value)
#endif

#ifndef X509_CERT_AUX_print
#define X509_CERT_AUX_print __NS_SYMBOL(X509_CERT_AUX_print)
#endif

#ifndef X509_CRL_get_ext_count
#define X509_CRL_get_ext_count __NS_SYMBOL(X509_CRL_get_ext_count)
#endif

#ifndef X509_CRL_print_fp
#define X509_CRL_print_fp __NS_SYMBOL(X509_CRL_print_fp)
#endif

#ifndef X509_CRL_set_version
#define X509_CRL_set_version __NS_SYMBOL(X509_CRL_set_version)
#endif

#ifndef X509_INFO_new
#define X509_INFO_new __NS_SYMBOL(X509_INFO_new)
#endif

#ifndef X509_LOOKUP_new
#define X509_LOOKUP_new __NS_SYMBOL(X509_LOOKUP_new)
#endif

#ifndef X509_NAME_get_text_by_NID
#define X509_NAME_get_text_by_NID __NS_SYMBOL(X509_NAME_get_text_by_NID)
#endif

#ifndef X509_NAME_oneline
#define X509_NAME_oneline __NS_SYMBOL(X509_NAME_oneline)
#endif

#ifndef X509_NAME_print_ex
#define X509_NAME_print_ex __NS_SYMBOL(X509_NAME_print_ex)
#endif

#ifndef X509_REQ_print_fp
#define X509_REQ_print_fp __NS_SYMBOL(X509_REQ_print_fp)
#endif

#ifndef X509_REQ_set_version
#define X509_REQ_set_version __NS_SYMBOL(X509_REQ_set_version)
#endif

#ifndef X509_REQ_to_X509
#define X509_REQ_to_X509 __NS_SYMBOL(X509_REQ_to_X509)
#endif

#ifndef X509_STORE_set_default_paths
#define X509_STORE_set_default_paths __NS_SYMBOL(X509_STORE_set_default_paths)
#endif

#ifndef X509_TRUST_set_default
#define X509_TRUST_set_default __NS_SYMBOL(X509_TRUST_set_default)
#endif

#ifndef X509_VERIFY_PARAM_new
#define X509_VERIFY_PARAM_new __NS_SYMBOL(X509_VERIFY_PARAM_new)
#endif

#ifndef X509_certificate_type
#define X509_certificate_type __NS_SYMBOL(X509_certificate_type)
#endif

#ifndef X509_check_purpose
#define X509_check_purpose __NS_SYMBOL(X509_check_purpose)
#endif

#ifndef X509_get_default_private_dir
#define X509_get_default_private_dir __NS_SYMBOL(X509_get_default_private_dir)
#endif

#ifndef X509_issuer_and_serial_cmp
#define X509_issuer_and_serial_cmp __NS_SYMBOL(X509_issuer_and_serial_cmp)
#endif

#ifndef X509_policy_tree_free
#define X509_policy_tree_free __NS_SYMBOL(X509_policy_tree_free)
#endif

#ifndef X509_policy_tree_level_count
#define X509_policy_tree_level_count __NS_SYMBOL(X509_policy_tree_level_count)
#endif

#ifndef X509_print_fp
#define X509_print_fp __NS_SYMBOL(X509_print_fp)
#endif

#ifndef X509_set_version
#define X509_set_version __NS_SYMBOL(X509_set_version)
#endif

#ifndef X509_to_X509_REQ
#define X509_to_X509_REQ __NS_SYMBOL(X509_to_X509_REQ)
#endif

#ifndef X509_verify
#define X509_verify __NS_SYMBOL(X509_verify)
#endif

#ifndef X509_verify_cert
#define X509_verify_cert __NS_SYMBOL(X509_verify_cert)
#endif

#ifndef X509_verify_cert_error_string
#define X509_verify_cert_error_string __NS_SYMBOL(X509_verify_cert_error_string)
#endif

#ifndef X509at_get_attr_count
#define X509at_get_attr_count __NS_SYMBOL(X509at_get_attr_count)
#endif

#ifndef X509v3_get_ext_count
#define X509v3_get_ext_count __NS_SYMBOL(X509v3_get_ext_count)
#endif

#ifndef _CONF_get_section
#define _CONF_get_section __NS_SYMBOL(_CONF_get_section)
#endif

#ifndef _des_crypt
#define _des_crypt __NS_SYMBOL(_des_crypt)
#endif

#ifndef _ossl_096_des_random_seed
#define _ossl_096_des_random_seed __NS_SYMBOL(_ossl_096_des_random_seed)
#endif

#ifndef _ossl_old_des_options
#define _ossl_old_des_options __NS_SYMBOL(_ossl_old_des_options)
#endif

#ifndef _ossl_old_des_read_pw_string
#define _ossl_old_des_read_pw_string __NS_SYMBOL(_ossl_old_des_read_pw_string)
#endif

#ifndef aesni_cbc_sha1_enc
#define aesni_cbc_sha1_enc __NS_SYMBOL(aesni_cbc_sha1_enc)
#endif

#ifndef aesni_encrypt
#define aesni_encrypt __NS_SYMBOL(aesni_encrypt)
#endif

#ifndef asn1_get_choice_selector
#define asn1_get_choice_selector __NS_SYMBOL(asn1_get_choice_selector)
#endif

#ifndef b2i_PrivateKey
#define b2i_PrivateKey __NS_SYMBOL(b2i_PrivateKey)
#endif

#ifndef bn_mul_add_words
#define bn_mul_add_words __NS_SYMBOL(bn_mul_add_words)
#endif

#ifndef bn_mul_mont
#define bn_mul_mont __NS_SYMBOL(bn_mul_mont)
#endif

#ifndef bn_mul_mont_gather5
#define bn_mul_mont_gather5 __NS_SYMBOL(bn_mul_mont_gather5)
#endif

#ifndef bn_sub_part_words
#define bn_sub_part_words __NS_SYMBOL(bn_sub_part_words)
#endif

#ifndef check_defer
#define check_defer __NS_SYMBOL(check_defer)
#endif

#ifndef cms_DigestedData_create
#define cms_DigestedData_create __NS_SYMBOL(cms_DigestedData_create)
#endif

#ifndef cms_EncryptedContent_init_bio
#define cms_EncryptedContent_init_bio __NS_SYMBOL(cms_EncryptedContent_init_bio)
#endif

#ifndef cms_get0_enveloped
#define cms_get0_enveloped __NS_SYMBOL(cms_get0_enveloped)
#endif

#ifndef d2i_ASN1_INTEGER
#define d2i_ASN1_INTEGER __NS_SYMBOL(d2i_ASN1_INTEGER)
#endif

#ifndef d2i_ASN1_TIME
#define d2i_ASN1_TIME __NS_SYMBOL(d2i_ASN1_TIME)
#endif

#ifndef d2i_ASN1_type_bytes
#define d2i_ASN1_type_bytes __NS_SYMBOL(d2i_ASN1_type_bytes)
#endif

#ifndef d2i_AUTHORITY_KEYID
#define d2i_AUTHORITY_KEYID __NS_SYMBOL(d2i_AUTHORITY_KEYID)
#endif

#ifndef d2i_CMS_ContentInfo
#define d2i_CMS_ContentInfo __NS_SYMBOL(d2i_CMS_ContentInfo)
#endif

#ifndef d2i_CMS_ReceiptRequest
#define d2i_CMS_ReceiptRequest __NS_SYMBOL(d2i_CMS_ReceiptRequest)
#endif

#ifndef d2i_DHparams
#define d2i_DHparams __NS_SYMBOL(d2i_DHparams)
#endif

#ifndef d2i_DSA_SIG
#define d2i_DSA_SIG __NS_SYMBOL(d2i_DSA_SIG)
#endif

#ifndef d2i_ECDSA_SIG
#define d2i_ECDSA_SIG __NS_SYMBOL(d2i_ECDSA_SIG)
#endif

#ifndef d2i_GOST_KEY_TRANSPORT
#define d2i_GOST_KEY_TRANSPORT __NS_SYMBOL(d2i_GOST_KEY_TRANSPORT)
#endif

#ifndef d2i_KRB5_ENCDATA
#define d2i_KRB5_ENCDATA __NS_SYMBOL(d2i_KRB5_ENCDATA)
#endif

#ifndef d2i_NETSCAPE_CERT_SEQUENCE
#define d2i_NETSCAPE_CERT_SEQUENCE __NS_SYMBOL(d2i_NETSCAPE_CERT_SEQUENCE)
#endif

#ifndef d2i_NETSCAPE_ENCRYPTED_PKEY
#define d2i_NETSCAPE_ENCRYPTED_PKEY __NS_SYMBOL(d2i_NETSCAPE_ENCRYPTED_PKEY)
#endif

#ifndef d2i_NETSCAPE_SPKAC
#define d2i_NETSCAPE_SPKAC __NS_SYMBOL(d2i_NETSCAPE_SPKAC)
#endif

#ifndef d2i_NETSCAPE_X509
#define d2i_NETSCAPE_X509 __NS_SYMBOL(d2i_NETSCAPE_X509)
#endif

#ifndef d2i_OCSP_SIGNATURE
#define d2i_OCSP_SIGNATURE __NS_SYMBOL(d2i_OCSP_SIGNATURE)
#endif

#ifndef d2i_OTHERNAME
#define d2i_OTHERNAME __NS_SYMBOL(d2i_OTHERNAME)
#endif

#ifndef d2i_PBE2PARAM
#define d2i_PBE2PARAM __NS_SYMBOL(d2i_PBE2PARAM)
#endif

#ifndef d2i_PBEPARAM
#define d2i_PBEPARAM __NS_SYMBOL(d2i_PBEPARAM)
#endif

#ifndef d2i_PKCS12
#define d2i_PKCS12 __NS_SYMBOL(d2i_PKCS12)
#endif

#ifndef d2i_PKCS7
#define d2i_PKCS7 __NS_SYMBOL(d2i_PKCS7)
#endif

#ifndef d2i_PKCS8_PRIV_KEY_INFO
#define d2i_PKCS8_PRIV_KEY_INFO __NS_SYMBOL(d2i_PKCS8_PRIV_KEY_INFO)
#endif

#ifndef d2i_PROXY_POLICY
#define d2i_PROXY_POLICY __NS_SYMBOL(d2i_PROXY_POLICY)
#endif

#ifndef d2i_PrivateKey
#define d2i_PrivateKey __NS_SYMBOL(d2i_PrivateKey)
#endif

#ifndef d2i_PublicKey
#define d2i_PublicKey __NS_SYMBOL(d2i_PublicKey)
#endif

#ifndef d2i_RSA_PSS_PARAMS
#define d2i_RSA_PSS_PARAMS __NS_SYMBOL(d2i_RSA_PSS_PARAMS)
#endif

#ifndef d2i_TS_MSG_IMPRINT
#define d2i_TS_MSG_IMPRINT __NS_SYMBOL(d2i_TS_MSG_IMPRINT)
#endif

#ifndef d2i_X509_ALGOR
#define d2i_X509_ALGOR __NS_SYMBOL(d2i_X509_ALGOR)
#endif

#ifndef d2i_X509_ATTRIBUTE
#define d2i_X509_ATTRIBUTE __NS_SYMBOL(d2i_X509_ATTRIBUTE)
#endif

#ifndef d2i_X509_CERT_AUX
#define d2i_X509_CERT_AUX __NS_SYMBOL(d2i_X509_CERT_AUX)
#endif

#ifndef d2i_X509_CINF
#define d2i_X509_CINF __NS_SYMBOL(d2i_X509_CINF)
#endif

#ifndef d2i_X509_EXTENSION
#define d2i_X509_EXTENSION __NS_SYMBOL(d2i_X509_EXTENSION)
#endif

#ifndef d2i_X509_NAME_ENTRY
#define d2i_X509_NAME_ENTRY __NS_SYMBOL(d2i_X509_NAME_ENTRY)
#endif

#ifndef d2i_X509_PUBKEY
#define d2i_X509_PUBKEY __NS_SYMBOL(d2i_X509_PUBKEY)
#endif

#ifndef d2i_X509_REQ_INFO
#define d2i_X509_REQ_INFO __NS_SYMBOL(d2i_X509_REQ_INFO)
#endif

#ifndef d2i_X509_REVOKED
#define d2i_X509_REVOKED __NS_SYMBOL(d2i_X509_REVOKED)
#endif

#ifndef d2i_X509_SIG
#define d2i_X509_SIG __NS_SYMBOL(d2i_X509_SIG)
#endif

#ifndef d2i_X509_VAL
#define d2i_X509_VAL __NS_SYMBOL(d2i_X509_VAL)
#endif

#ifndef ec_GF2m_simple_mul
#define ec_GF2m_simple_mul __NS_SYMBOL(ec_GF2m_simple_mul)
#endif

#ifndef ec_GF2m_simple_set_compressed_coordinates
#define ec_GF2m_simple_set_compressed_coordinates __NS_SYMBOL(ec_GF2m_simple_set_compressed_coordinates)
#endif

#ifndef ec_GFp_simple_set_compressed_coordinates
#define ec_GFp_simple_set_compressed_coordinates __NS_SYMBOL(ec_GFp_simple_set_compressed_coordinates)
#endif

#ifndef ec_wNAF_mul
#define ec_wNAF_mul __NS_SYMBOL(ec_wNAF_mul)
#endif

#ifndef engine_unlocked_init
#define engine_unlocked_init __NS_SYMBOL(engine_unlocked_init)
#endif

#ifndef fcrypt_body
#define fcrypt_body __NS_SYMBOL(fcrypt_body)
#endif

#ifndef fill_GOST2001_params
#define fill_GOST2001_params __NS_SYMBOL(fill_GOST2001_params)
#endif

#ifndef gcm_gmult_4bit
#define gcm_gmult_4bit __NS_SYMBOL(gcm_gmult_4bit)
#endif

#ifndef get_rfc2409_prime_768
#define get_rfc2409_prime_768 __NS_SYMBOL(get_rfc2409_prime_768)
#endif

#ifndef gost94_nid_by_params
#define gost94_nid_by_params __NS_SYMBOL(gost94_nid_by_params)
#endif

#ifndef gost_do_sign
#define gost_do_sign __NS_SYMBOL(gost_do_sign)
#endif

#ifndef gost_param_free
#define gost_param_free __NS_SYMBOL(gost_param_free)
#endif

#ifndef gostcrypt
#define gostcrypt __NS_SYMBOL(gostcrypt)
#endif

#ifndef i2a_ASN1_ENUMERATED
#define i2a_ASN1_ENUMERATED __NS_SYMBOL(i2a_ASN1_ENUMERATED)
#endif

#ifndef i2a_ASN1_INTEGER
#define i2a_ASN1_INTEGER __NS_SYMBOL(i2a_ASN1_INTEGER)
#endif

#ifndef i2a_ASN1_STRING
#define i2a_ASN1_STRING __NS_SYMBOL(i2a_ASN1_STRING)
#endif

#ifndef i2d_ASN1_BOOLEAN
#define i2d_ASN1_BOOLEAN __NS_SYMBOL(i2d_ASN1_BOOLEAN)
#endif

#ifndef i2d_ASN1_OBJECT
#define i2d_ASN1_OBJECT __NS_SYMBOL(i2d_ASN1_OBJECT)
#endif

#ifndef i2d_ASN1_SET
#define i2d_ASN1_SET __NS_SYMBOL(i2d_ASN1_SET)
#endif

#ifndef i2d_ASN1_bio_stream
#define i2d_ASN1_bio_stream __NS_SYMBOL(i2d_ASN1_bio_stream)
#endif

#ifndef i2d_PKCS7_bio_stream
#define i2d_PKCS7_bio_stream __NS_SYMBOL(i2d_PKCS7_bio_stream)
#endif

#ifndef i2d_PrivateKey
#define i2d_PrivateKey __NS_SYMBOL(i2d_PrivateKey)
#endif

#ifndef i2d_PublicKey
#define i2d_PublicKey __NS_SYMBOL(i2d_PublicKey)
#endif

#ifndef i2d_X509_PKEY
#define i2d_X509_PKEY __NS_SYMBOL(i2d_X509_PKEY)
#endif

#ifndef i2s_ASN1_ENUMERATED_TABLE
#define i2s_ASN1_ENUMERATED_TABLE __NS_SYMBOL(i2s_ASN1_ENUMERATED_TABLE)
#endif

#ifndef i2s_ASN1_OCTET_STRING
#define i2s_ASN1_OCTET_STRING __NS_SYMBOL(i2s_ASN1_OCTET_STRING)
#endif

#ifndef i2v_ASN1_BIT_STRING
#define i2v_ASN1_BIT_STRING __NS_SYMBOL(i2v_ASN1_BIT_STRING)
#endif

#ifndef i2v_GENERAL_NAMES
#define i2v_GENERAL_NAMES __NS_SYMBOL(i2v_GENERAL_NAMES)
#endif

#ifndef idea_cbc_encrypt
#define idea_cbc_encrypt __NS_SYMBOL(idea_cbc_encrypt)
#endif

#ifndef idea_cfb64_encrypt
#define idea_cfb64_encrypt __NS_SYMBOL(idea_cfb64_encrypt)
#endif

#ifndef idea_ofb64_encrypt
#define idea_ofb64_encrypt __NS_SYMBOL(idea_ofb64_encrypt)
#endif

#ifndef idea_options
#define idea_options __NS_SYMBOL(idea_options)
#endif

#ifndef idea_set_encrypt_key
#define idea_set_encrypt_key __NS_SYMBOL(idea_set_encrypt_key)
#endif

#ifndef init_gost_hash_ctx
#define init_gost_hash_ctx __NS_SYMBOL(init_gost_hash_ctx)
#endif

#ifndef keyDiversifyCryptoPro
#define keyDiversifyCryptoPro __NS_SYMBOL(keyDiversifyCryptoPro)
#endif

#ifndef lh_new
#define lh_new __NS_SYMBOL(lh_new)
#endif

#ifndef lh_stats
#define lh_stats __NS_SYMBOL(lh_stats)
#endif

#ifndef md5_block_asm_data_order
#define md5_block_asm_data_order __NS_SYMBOL(md5_block_asm_data_order)
#endif

#ifndef pitem_new
#define pitem_new __NS_SYMBOL(pitem_new)
#endif

#ifndef pkey_gost2001_derive
#define pkey_gost2001_derive __NS_SYMBOL(pkey_gost2001_derive)
#endif

#ifndef pkey_gost94_derive
#define pkey_gost94_derive __NS_SYMBOL(pkey_gost94_derive)
#endif

#ifndef policy_cache_free
#define policy_cache_free __NS_SYMBOL(policy_cache_free)
#endif

#ifndef policy_cache_set_mapping
#define policy_cache_set_mapping __NS_SYMBOL(policy_cache_set_mapping)
#endif

#ifndef policy_data_free
#define policy_data_free __NS_SYMBOL(policy_data_free)
#endif

#ifndef policy_node_cmp_new
#define policy_node_cmp_new __NS_SYMBOL(policy_node_cmp_new)
#endif

#ifndef private_Camellia_set_key
#define private_Camellia_set_key __NS_SYMBOL(private_Camellia_set_key)
#endif

#ifndef register_pmeth_gost
#define register_pmeth_gost __NS_SYMBOL(register_pmeth_gost)
#endif

#ifndef sha1_block_data_order
#define sha1_block_data_order __NS_SYMBOL(sha1_block_data_order)
#endif

#ifndef sha256_block_data_order
#define sha256_block_data_order __NS_SYMBOL(sha256_block_data_order)
#endif

#ifndef sha512_block_data_order
#define sha512_block_data_order __NS_SYMBOL(sha512_block_data_order)
#endif

#ifndef sk_set_cmp_func
#define sk_set_cmp_func __NS_SYMBOL(sk_set_cmp_func)
#endif

#ifndef whirlpool_block
#define whirlpool_block __NS_SYMBOL(whirlpool_block)
#endif

#ifndef AES_set_encrypt_key
#define AES_set_encrypt_key __NS_SYMBOL(AES_set_encrypt_key)
#endif

#ifndef ASN1_INTEGER_cmp
#define ASN1_INTEGER_cmp __NS_SYMBOL(ASN1_INTEGER_cmp)
#endif

#ifndef ASN1_OCTET_STRING_cmp
#define ASN1_OCTET_STRING_cmp __NS_SYMBOL(ASN1_OCTET_STRING_cmp)
#endif

#ifndef ASN1_STRING_get_default_mask
#define ASN1_STRING_get_default_mask __NS_SYMBOL(ASN1_STRING_get_default_mask)
#endif

#ifndef BF_ecb_encrypt
#define BF_ecb_encrypt __NS_SYMBOL(BF_ecb_encrypt)
#endif

#ifndef BIO_asn1_set_prefix
#define BIO_asn1_set_prefix __NS_SYMBOL(BIO_asn1_set_prefix)
#endif

#ifndef BIO_dump_indent_cb
#define BIO_dump_indent_cb __NS_SYMBOL(BIO_dump_indent_cb)
#endif

#ifndef BIO_new_accept
#define BIO_new_accept __NS_SYMBOL(BIO_new_accept)
#endif

#ifndef BIO_new_bio_pair
#define BIO_new_bio_pair __NS_SYMBOL(BIO_new_bio_pair)
#endif

#ifndef BIO_new_dgram
#define BIO_new_dgram __NS_SYMBOL(BIO_new_dgram)
#endif

#ifndef BIO_new_fd
#define BIO_new_fd __NS_SYMBOL(BIO_new_fd)
#endif

#ifndef BIO_new_mem_buf
#define BIO_new_mem_buf __NS_SYMBOL(BIO_new_mem_buf)
#endif

#ifndef BIO_new_socket
#define BIO_new_socket __NS_SYMBOL(BIO_new_socket)
#endif

#ifndef BIO_set_cipher
#define BIO_set_cipher __NS_SYMBOL(BIO_set_cipher)
#endif

#ifndef BN_get0_nist_prime_224
#define BN_get0_nist_prime_224 __NS_SYMBOL(BN_get0_nist_prime_224)
#endif

#ifndef CMS_signed_get_attr_by_NID
#define CMS_signed_get_attr_by_NID __NS_SYMBOL(CMS_signed_get_attr_by_NID)
#endif

#ifndef COMP_zlib_cleanup
#define COMP_zlib_cleanup __NS_SYMBOL(COMP_zlib_cleanup)
#endif

#ifndef DH_compute_key
#define DH_compute_key __NS_SYMBOL(DH_compute_key)
#endif

#ifndef DH_get_default_method
#define DH_get_default_method __NS_SYMBOL(DH_get_default_method)
#endif

#ifndef DSA_get_default_method
#define DSA_get_default_method __NS_SYMBOL(DSA_get_default_method)
#endif

#ifndef DSA_sign_setup
#define DSA_sign_setup __NS_SYMBOL(DSA_sign_setup)
#endif

#ifndef DSO_new_method
#define DSO_new_method __NS_SYMBOL(DSO_new_method)
#endif

#ifndef ECDH_get_default_method
#define ECDH_get_default_method __NS_SYMBOL(ECDH_get_default_method)
#endif

#ifndef ECDSA_get_default_method
#define ECDSA_get_default_method __NS_SYMBOL(ECDSA_get_default_method)
#endif

#ifndef ENGINE_set_table_flags
#define ENGINE_set_table_flags __NS_SYMBOL(ENGINE_set_table_flags)
#endif

#ifndef EVP_bf_cfb64
#define EVP_bf_cfb64 __NS_SYMBOL(EVP_bf_cfb64)
#endif

#ifndef EVP_camellia_128_cfb128
#define EVP_camellia_128_cfb128 __NS_SYMBOL(EVP_camellia_128_cfb128)
#endif

#ifndef EVP_cast5_cfb64
#define EVP_cast5_cfb64 __NS_SYMBOL(EVP_cast5_cfb64)
#endif

#ifndef EVP_des_cfb
#define EVP_des_cfb __NS_SYMBOL(EVP_des_cfb)
#endif

#ifndef EVP_des_cfb64
#define EVP_des_cfb64 __NS_SYMBOL(EVP_des_cfb64)
#endif

#ifndef EVP_des_ede_cfb64
#define EVP_des_ede_cfb64 __NS_SYMBOL(EVP_des_ede_cfb64)
#endif

#ifndef EVP_idea_cfb64
#define EVP_idea_cfb64 __NS_SYMBOL(EVP_idea_cfb64)
#endif

#ifndef EVP_rc2_cfb64
#define EVP_rc2_cfb64 __NS_SYMBOL(EVP_rc2_cfb64)
#endif

#ifndef EVP_rc4_40
#define EVP_rc4_40 __NS_SYMBOL(EVP_rc4_40)
#endif

#ifndef EVP_seed_cfb128
#define EVP_seed_cfb128 __NS_SYMBOL(EVP_seed_cfb128)
#endif

#ifndef EVP_sha224
#define EVP_sha224 __NS_SYMBOL(EVP_sha224)
#endif

#ifndef FIPS_mode_set
#define FIPS_mode_set __NS_SYMBOL(FIPS_mode_set)
#endif

#ifndef NCONF_WIN32
#define NCONF_WIN32 __NS_SYMBOL(NCONF_WIN32)
#endif

#ifndef OPENSSL_strcasecmp
#define OPENSSL_strcasecmp __NS_SYMBOL(OPENSSL_strcasecmp)
#endif

#ifndef PEM_SignUpdate
#define PEM_SignUpdate __NS_SYMBOL(PEM_SignUpdate)
#endif

#ifndef PKCS12_PBE_keyivgen
#define PKCS12_PBE_keyivgen __NS_SYMBOL(PKCS12_PBE_keyivgen)
#endif

#ifndef PKCS5_PBE_keyivgen
#define PKCS5_PBE_keyivgen __NS_SYMBOL(PKCS5_PBE_keyivgen)
#endif

#ifndef RSA_new_method
#define RSA_new_method __NS_SYMBOL(RSA_new_method)
#endif

#ifndef TS_REQ_get_version
#define TS_REQ_get_version __NS_SYMBOL(TS_REQ_get_version)
#endif

#ifndef X509_get_default_cert_area
#define X509_get_default_cert_area __NS_SYMBOL(X509_get_default_cert_area)
#endif

#ifndef X509_policy_tree_get0_level
#define X509_policy_tree_get0_level __NS_SYMBOL(X509_policy_tree_get0_level)
#endif

#ifndef X509at_get_attr_by_NID
#define X509at_get_attr_by_NID __NS_SYMBOL(X509at_get_attr_by_NID)
#endif

#ifndef _ossl_old_des_ecb3_encrypt
#define _ossl_old_des_ecb3_encrypt __NS_SYMBOL(_ossl_old_des_ecb3_encrypt)
#endif

#ifndef _ossl_old_des_read_pw
#define _ossl_old_des_read_pw __NS_SYMBOL(_ossl_old_des_read_pw)
#endif

#ifndef asn1_set_choice_selector
#define asn1_set_choice_selector __NS_SYMBOL(asn1_set_choice_selector)
#endif

#ifndef d2i_X509_PKEY
#define d2i_X509_PKEY __NS_SYMBOL(d2i_X509_PKEY)
#endif

#ifndef ec_GF2m_simple_group_init
#define ec_GF2m_simple_group_init __NS_SYMBOL(ec_GF2m_simple_group_init)
#endif

#ifndef ec_GFp_mont_group_init
#define ec_GFp_mont_group_init __NS_SYMBOL(ec_GFp_mont_group_init)
#endif

#ifndef ec_GFp_nist_group_copy
#define ec_GFp_nist_group_copy __NS_SYMBOL(ec_GFp_nist_group_copy)
#endif

#ifndef ec_GFp_simple_group_init
#define ec_GFp_simple_group_init __NS_SYMBOL(ec_GFp_simple_group_init)
#endif

#ifndef i2c_ASN1_BIT_STRING
#define i2c_ASN1_BIT_STRING __NS_SYMBOL(i2c_ASN1_BIT_STRING)
#endif

#ifndef idea_ecb_encrypt
#define idea_ecb_encrypt __NS_SYMBOL(idea_ecb_encrypt)
#endif

#ifndef private_RC4_set_key
#define private_RC4_set_key __NS_SYMBOL(private_RC4_set_key)
#endif

#ifndef AES_set_decrypt_key
#define AES_set_decrypt_key __NS_SYMBOL(AES_set_decrypt_key)
#endif

#ifndef ASN1_OCTET_STRING_set
#define ASN1_OCTET_STRING_set __NS_SYMBOL(ASN1_OCTET_STRING_set)
#endif

#ifndef ASN1_STRING_set_default_mask_asc
#define ASN1_STRING_set_default_mask_asc __NS_SYMBOL(ASN1_STRING_set_default_mask_asc)
#endif

#ifndef ASN1_TYPE_set
#define ASN1_TYPE_set __NS_SYMBOL(ASN1_TYPE_set)
#endif

#ifndef ASN1_item_d2i
#define ASN1_item_d2i __NS_SYMBOL(ASN1_item_d2i)
#endif

#ifndef ASN1_mbstring_ncopy
#define ASN1_mbstring_ncopy __NS_SYMBOL(ASN1_mbstring_ncopy)
#endif

#ifndef BN_get0_nist_prime_256
#define BN_get0_nist_prime_256 __NS_SYMBOL(BN_get0_nist_prime_256)
#endif

#ifndef CMS_signed_get_attr_by_OBJ
#define CMS_signed_get_attr_by_OBJ __NS_SYMBOL(CMS_signed_get_attr_by_OBJ)
#endif

#ifndef Camellia_EncryptBlock_Rounds
#define Camellia_EncryptBlock_Rounds __NS_SYMBOL(Camellia_EncryptBlock_Rounds)
#endif

#ifndef DES_fcrypt
#define DES_fcrypt __NS_SYMBOL(DES_fcrypt)
#endif

#ifndef DSA_SIG_new
#define DSA_SIG_new __NS_SYMBOL(DSA_SIG_new)
#endif

#ifndef ENGINE_register_DH
#define ENGINE_register_DH __NS_SYMBOL(ENGINE_register_DH)
#endif

#ifndef ENGINE_register_DSA
#define ENGINE_register_DSA __NS_SYMBOL(ENGINE_register_DSA)
#endif

#ifndef ENGINE_register_ECDH
#define ENGINE_register_ECDH __NS_SYMBOL(ENGINE_register_ECDH)
#endif

#ifndef ENGINE_register_ECDSA
#define ENGINE_register_ECDSA __NS_SYMBOL(ENGINE_register_ECDSA)
#endif

#ifndef ENGINE_register_RAND
#define ENGINE_register_RAND __NS_SYMBOL(ENGINE_register_RAND)
#endif

#ifndef ENGINE_register_RSA
#define ENGINE_register_RSA __NS_SYMBOL(ENGINE_register_RSA)
#endif

#ifndef ENGINE_register_STORE
#define ENGINE_register_STORE __NS_SYMBOL(ENGINE_register_STORE)
#endif

#ifndef ENGINE_register_ciphers
#define ENGINE_register_ciphers __NS_SYMBOL(ENGINE_register_ciphers)
#endif

#ifndef ENGINE_register_digests
#define ENGINE_register_digests __NS_SYMBOL(ENGINE_register_digests)
#endif

#ifndef ENGINE_register_pkey_asn1_meths
#define ENGINE_register_pkey_asn1_meths __NS_SYMBOL(ENGINE_register_pkey_asn1_meths)
#endif

#ifndef ENGINE_register_pkey_meths
#define ENGINE_register_pkey_meths __NS_SYMBOL(ENGINE_register_pkey_meths)
#endif

#ifndef ENGINE_set_load_pubkey_function
#define ENGINE_set_load_pubkey_function __NS_SYMBOL(ENGINE_set_load_pubkey_function)
#endif

#ifndef EVP_CIPHER_CTX_new
#define EVP_CIPHER_CTX_new __NS_SYMBOL(EVP_CIPHER_CTX_new)
#endif

#ifndef EVP_EncodeUpdate
#define EVP_EncodeUpdate __NS_SYMBOL(EVP_EncodeUpdate)
#endif

#ifndef EVP_PKEY_asn1_get0
#define EVP_PKEY_asn1_get0 __NS_SYMBOL(EVP_PKEY_asn1_get0)
#endif

#ifndef EVP_bf_ofb
#define EVP_bf_ofb __NS_SYMBOL(EVP_bf_ofb)
#endif

#ifndef EVP_camellia_128_ofb
#define EVP_camellia_128_ofb __NS_SYMBOL(EVP_camellia_128_ofb)
#endif

#ifndef EVP_cast5_ofb
#define EVP_cast5_ofb __NS_SYMBOL(EVP_cast5_ofb)
#endif

#ifndef EVP_des_ede3_cfb
#define EVP_des_ede3_cfb __NS_SYMBOL(EVP_des_ede3_cfb)
#endif

#ifndef EVP_des_ede_ofb
#define EVP_des_ede_ofb __NS_SYMBOL(EVP_des_ede_ofb)
#endif

#ifndef EVP_des_ofb
#define EVP_des_ofb __NS_SYMBOL(EVP_des_ofb)
#endif

#ifndef EVP_idea_ofb
#define EVP_idea_ofb __NS_SYMBOL(EVP_idea_ofb)
#endif

#ifndef EVP_rc2_ofb
#define EVP_rc2_ofb __NS_SYMBOL(EVP_rc2_ofb)
#endif

#ifndef EVP_seed_ofb
#define EVP_seed_ofb __NS_SYMBOL(EVP_seed_ofb)
#endif

#ifndef EVP_sha256
#define EVP_sha256 __NS_SYMBOL(EVP_sha256)
#endif

#ifndef NETSCAPE_SPKI_get_pubkey
#define NETSCAPE_SPKI_get_pubkey __NS_SYMBOL(NETSCAPE_SPKI_get_pubkey)
#endif

#ifndef OCSP_REQUEST_get_ext_by_NID
#define OCSP_REQUEST_get_ext_by_NID __NS_SYMBOL(OCSP_REQUEST_get_ext_by_NID)
#endif

#ifndef OCSP_request_onereq_get0
#define OCSP_request_onereq_get0 __NS_SYMBOL(OCSP_request_onereq_get0)
#endif

#ifndef OPENSSL_memcmp
#define OPENSSL_memcmp __NS_SYMBOL(OPENSSL_memcmp)
#endif

#ifndef OPENSSL_rdtsc
#define OPENSSL_rdtsc __NS_SYMBOL(OPENSSL_rdtsc)
#endif

#ifndef PEM_SignFinal
#define PEM_SignFinal __NS_SYMBOL(PEM_SignFinal)
#endif

#ifndef PEM_write_bio_PKCS7_stream
#define PEM_write_bio_PKCS7_stream __NS_SYMBOL(PEM_write_bio_PKCS7_stream)
#endif

#ifndef RSA_public_encrypt
#define RSA_public_encrypt __NS_SYMBOL(RSA_public_encrypt)
#endif

#ifndef RSA_verify_PKCS1_PSS_mgf1
#define RSA_verify_PKCS1_PSS_mgf1 __NS_SYMBOL(RSA_verify_PKCS1_PSS_mgf1)
#endif

#ifndef TS_REQ_set_msg_imprint
#define TS_REQ_set_msg_imprint __NS_SYMBOL(TS_REQ_set_msg_imprint)
#endif

#ifndef WHIRLPOOL_Update
#define WHIRLPOOL_Update __NS_SYMBOL(WHIRLPOOL_Update)
#endif

#ifndef X509_CRL_get_ext_by_NID
#define X509_CRL_get_ext_by_NID __NS_SYMBOL(X509_CRL_get_ext_by_NID)
#endif

#ifndef X509_REQ_set_subject_name
#define X509_REQ_set_subject_name __NS_SYMBOL(X509_REQ_set_subject_name)
#endif

#ifndef X509_check_trust
#define X509_check_trust __NS_SYMBOL(X509_check_trust)
#endif

#ifndef X509_get_default_cert_dir
#define X509_get_default_cert_dir __NS_SYMBOL(X509_get_default_cert_dir)
#endif

#ifndef X509v3_get_ext_by_NID
#define X509v3_get_ext_by_NID __NS_SYMBOL(X509v3_get_ext_by_NID)
#endif

#ifndef _ossl_old_des_cbc_cksum
#define _ossl_old_des_cbc_cksum __NS_SYMBOL(_ossl_old_des_cbc_cksum)
#endif

#ifndef engine_table_register
#define engine_table_register __NS_SYMBOL(engine_table_register)
#endif

#ifndef get_rfc2409_prime_1024
#define get_rfc2409_prime_1024 __NS_SYMBOL(get_rfc2409_prime_1024)
#endif

#ifndef i2d_ASN1_INTEGER
#define i2d_ASN1_INTEGER __NS_SYMBOL(i2d_ASN1_INTEGER)
#endif

#ifndef i2d_ASN1_TIME
#define i2d_ASN1_TIME __NS_SYMBOL(i2d_ASN1_TIME)
#endif

#ifndef i2d_AUTHORITY_KEYID
#define i2d_AUTHORITY_KEYID __NS_SYMBOL(i2d_AUTHORITY_KEYID)
#endif

#ifndef i2d_CMS_ContentInfo
#define i2d_CMS_ContentInfo __NS_SYMBOL(i2d_CMS_ContentInfo)
#endif

#ifndef i2d_CMS_ReceiptRequest
#define i2d_CMS_ReceiptRequest __NS_SYMBOL(i2d_CMS_ReceiptRequest)
#endif

#ifndef i2d_DHparams
#define i2d_DHparams __NS_SYMBOL(i2d_DHparams)
#endif

#ifndef i2d_DSA_SIG
#define i2d_DSA_SIG __NS_SYMBOL(i2d_DSA_SIG)
#endif

#ifndef i2d_ECDSA_SIG
#define i2d_ECDSA_SIG __NS_SYMBOL(i2d_ECDSA_SIG)
#endif

#ifndef i2d_GOST_KEY_TRANSPORT
#define i2d_GOST_KEY_TRANSPORT __NS_SYMBOL(i2d_GOST_KEY_TRANSPORT)
#endif

#ifndef i2d_KRB5_ENCDATA
#define i2d_KRB5_ENCDATA __NS_SYMBOL(i2d_KRB5_ENCDATA)
#endif

#ifndef i2d_NETSCAPE_CERT_SEQUENCE
#define i2d_NETSCAPE_CERT_SEQUENCE __NS_SYMBOL(i2d_NETSCAPE_CERT_SEQUENCE)
#endif

#ifndef i2d_NETSCAPE_ENCRYPTED_PKEY
#define i2d_NETSCAPE_ENCRYPTED_PKEY __NS_SYMBOL(i2d_NETSCAPE_ENCRYPTED_PKEY)
#endif

#ifndef i2d_NETSCAPE_SPKAC
#define i2d_NETSCAPE_SPKAC __NS_SYMBOL(i2d_NETSCAPE_SPKAC)
#endif

#ifndef i2d_NETSCAPE_X509
#define i2d_NETSCAPE_X509 __NS_SYMBOL(i2d_NETSCAPE_X509)
#endif

#ifndef i2d_OCSP_SIGNATURE
#define i2d_OCSP_SIGNATURE __NS_SYMBOL(i2d_OCSP_SIGNATURE)
#endif

#ifndef i2d_OTHERNAME
#define i2d_OTHERNAME __NS_SYMBOL(i2d_OTHERNAME)
#endif

#ifndef i2d_PBE2PARAM
#define i2d_PBE2PARAM __NS_SYMBOL(i2d_PBE2PARAM)
#endif

#ifndef i2d_PBEPARAM
#define i2d_PBEPARAM __NS_SYMBOL(i2d_PBEPARAM)
#endif

#ifndef i2d_PKCS12
#define i2d_PKCS12 __NS_SYMBOL(i2d_PKCS12)
#endif

#ifndef i2d_PKCS7
#define i2d_PKCS7 __NS_SYMBOL(i2d_PKCS7)
#endif

#ifndef i2d_PKCS8_PRIV_KEY_INFO
#define i2d_PKCS8_PRIV_KEY_INFO __NS_SYMBOL(i2d_PKCS8_PRIV_KEY_INFO)
#endif

#ifndef i2d_PROXY_POLICY
#define i2d_PROXY_POLICY __NS_SYMBOL(i2d_PROXY_POLICY)
#endif

#ifndef i2d_RSA_PSS_PARAMS
#define i2d_RSA_PSS_PARAMS __NS_SYMBOL(i2d_RSA_PSS_PARAMS)
#endif

#ifndef i2d_TS_MSG_IMPRINT
#define i2d_TS_MSG_IMPRINT __NS_SYMBOL(i2d_TS_MSG_IMPRINT)
#endif

#ifndef i2d_X509_ALGOR
#define i2d_X509_ALGOR __NS_SYMBOL(i2d_X509_ALGOR)
#endif

#ifndef i2d_X509_ATTRIBUTE
#define i2d_X509_ATTRIBUTE __NS_SYMBOL(i2d_X509_ATTRIBUTE)
#endif

#ifndef i2d_X509_CERT_AUX
#define i2d_X509_CERT_AUX __NS_SYMBOL(i2d_X509_CERT_AUX)
#endif

#ifndef i2d_X509_CINF
#define i2d_X509_CINF __NS_SYMBOL(i2d_X509_CINF)
#endif

#ifndef i2d_X509_EXTENSION
#define i2d_X509_EXTENSION __NS_SYMBOL(i2d_X509_EXTENSION)
#endif

#ifndef i2d_X509_NAME_ENTRY
#define i2d_X509_NAME_ENTRY __NS_SYMBOL(i2d_X509_NAME_ENTRY)
#endif

#ifndef i2d_X509_PUBKEY
#define i2d_X509_PUBKEY __NS_SYMBOL(i2d_X509_PUBKEY)
#endif

#ifndef i2d_X509_REQ_INFO
#define i2d_X509_REQ_INFO __NS_SYMBOL(i2d_X509_REQ_INFO)
#endif

#ifndef i2d_X509_REVOKED
#define i2d_X509_REVOKED __NS_SYMBOL(i2d_X509_REVOKED)
#endif

#ifndef i2d_X509_SIG
#define i2d_X509_SIG __NS_SYMBOL(i2d_X509_SIG)
#endif

#ifndef i2d_X509_VAL
#define i2d_X509_VAL __NS_SYMBOL(i2d_X509_VAL)
#endif

#ifndef sk_dup
#define sk_dup __NS_SYMBOL(sk_dup)
#endif

#ifndef AES_cfb1_encrypt
#define AES_cfb1_encrypt __NS_SYMBOL(AES_cfb1_encrypt)
#endif

#ifndef BN_RECP_CTX_new
#define BN_RECP_CTX_new __NS_SYMBOL(BN_RECP_CTX_new)
#endif

#ifndef BN_get0_nist_prime_384
#define BN_get0_nist_prime_384 __NS_SYMBOL(BN_get0_nist_prime_384)
#endif

#ifndef CMS_signed_get_attr
#define CMS_signed_get_attr __NS_SYMBOL(CMS_signed_get_attr)
#endif

#ifndef Camellia_cfb1_encrypt
#define Camellia_cfb1_encrypt __NS_SYMBOL(Camellia_cfb1_encrypt)
#endif

#ifndef DH_OpenSSL
#define DH_OpenSSL __NS_SYMBOL(DH_OpenSSL)
#endif

#ifndef DH_set_method
#define DH_set_method __NS_SYMBOL(DH_set_method)
#endif

#ifndef DSA_new
#define DSA_new __NS_SYMBOL(DSA_new)
#endif

#ifndef ECDH_set_method
#define ECDH_set_method __NS_SYMBOL(ECDH_set_method)
#endif

#ifndef ECDSA_set_method
#define ECDSA_set_method __NS_SYMBOL(ECDSA_set_method)
#endif

#ifndef EVP_PKEY_size
#define EVP_PKEY_size __NS_SYMBOL(EVP_PKEY_size)
#endif

#ifndef EVP_aes_128_ecb
#define EVP_aes_128_ecb __NS_SYMBOL(EVP_aes_128_ecb)
#endif

#ifndef EVP_aes_256_cbc_hmac_sha1
#define EVP_aes_256_cbc_hmac_sha1 __NS_SYMBOL(EVP_aes_256_cbc_hmac_sha1)
#endif

#ifndef EVP_bf_ecb
#define EVP_bf_ecb __NS_SYMBOL(EVP_bf_ecb)
#endif

#ifndef EVP_camellia_128_ecb
#define EVP_camellia_128_ecb __NS_SYMBOL(EVP_camellia_128_ecb)
#endif

#ifndef EVP_cast5_ecb
#define EVP_cast5_ecb __NS_SYMBOL(EVP_cast5_ecb)
#endif

#ifndef EVP_des_ecb
#define EVP_des_ecb __NS_SYMBOL(EVP_des_ecb)
#endif

#ifndef EVP_des_ede_cfb
#define EVP_des_ede_cfb __NS_SYMBOL(EVP_des_ede_cfb)
#endif

#ifndef EVP_des_ede_ecb
#define EVP_des_ede_ecb __NS_SYMBOL(EVP_des_ede_ecb)
#endif

#ifndef EVP_idea_ecb
#define EVP_idea_ecb __NS_SYMBOL(EVP_idea_ecb)
#endif

#ifndef EVP_rc2_ecb
#define EVP_rc2_ecb __NS_SYMBOL(EVP_rc2_ecb)
#endif

#ifndef EVP_seed_ecb
#define EVP_seed_ecb __NS_SYMBOL(EVP_seed_ecb)
#endif

#ifndef EVP_sha384
#define EVP_sha384 __NS_SYMBOL(EVP_sha384)
#endif

#ifndef OBJ_cleanup
#define OBJ_cleanup __NS_SYMBOL(OBJ_cleanup)
#endif

#ifndef OPENSSL_ia32_cpuid
#define OPENSSL_ia32_cpuid __NS_SYMBOL(OPENSSL_ia32_cpuid)
#endif

#ifndef PEM_read_X509
#define PEM_read_X509 __NS_SYMBOL(PEM_read_X509)
#endif

#ifndef PEM_read_X509_AUX
#define PEM_read_X509_AUX __NS_SYMBOL(PEM_read_X509_AUX)
#endif

#ifndef PEM_read_X509_REQ
#define PEM_read_X509_REQ __NS_SYMBOL(PEM_read_X509_REQ)
#endif

#ifndef PKCS8_add_keyusage
#define PKCS8_add_keyusage __NS_SYMBOL(PKCS8_add_keyusage)
#endif

#ifndef RSA_private_encrypt
#define RSA_private_encrypt __NS_SYMBOL(RSA_private_encrypt)
#endif

#ifndef X509_REQ_verify
#define X509_REQ_verify __NS_SYMBOL(X509_REQ_verify)
#endif

#ifndef X509_get_default_cert_file
#define X509_get_default_cert_file __NS_SYMBOL(X509_get_default_cert_file)
#endif

#ifndef _ossl_old_des_cbc_encrypt
#define _ossl_old_des_cbc_encrypt __NS_SYMBOL(_ossl_old_des_cbc_encrypt)
#endif

#ifndef asn1_do_lock
#define asn1_do_lock __NS_SYMBOL(asn1_do_lock)
#endif

#ifndef ec_GFp_nist_group_set_curve
#define ec_GFp_nist_group_set_curve __NS_SYMBOL(ec_GFp_nist_group_set_curve)
#endif

#ifndef gost_control_func
#define gost_control_func __NS_SYMBOL(gost_control_func)
#endif

#ifndef ASN1_INTEGER_new
#define ASN1_INTEGER_new __NS_SYMBOL(ASN1_INTEGER_new)
#endif

#ifndef ASN1_TIME_new
#define ASN1_TIME_new __NS_SYMBOL(ASN1_TIME_new)
#endif

#ifndef ASN1_const_check_infinite_end
#define ASN1_const_check_infinite_end __NS_SYMBOL(ASN1_const_check_infinite_end)
#endif

#ifndef ASN1_generate_v3
#define ASN1_generate_v3 __NS_SYMBOL(ASN1_generate_v3)
#endif

#ifndef ASN1_item_ex_new
#define ASN1_item_ex_new __NS_SYMBOL(ASN1_item_ex_new)
#endif

#ifndef AUTHORITY_KEYID_new
#define AUTHORITY_KEYID_new __NS_SYMBOL(AUTHORITY_KEYID_new)
#endif

#ifndef BIO_asn1_get_prefix
#define BIO_asn1_get_prefix __NS_SYMBOL(BIO_asn1_get_prefix)
#endif

#ifndef BN_get0_nist_prime_521
#define BN_get0_nist_prime_521 __NS_SYMBOL(BN_get0_nist_prime_521)
#endif

#ifndef CMS_ContentInfo_new
#define CMS_ContentInfo_new __NS_SYMBOL(CMS_ContentInfo_new)
#endif

#ifndef CMS_ReceiptRequest_new
#define CMS_ReceiptRequest_new __NS_SYMBOL(CMS_ReceiptRequest_new)
#endif

#ifndef CMS_signed_delete_attr
#define CMS_signed_delete_attr __NS_SYMBOL(CMS_signed_delete_attr)
#endif

#ifndef CONF_set_default_method
#define CONF_set_default_method __NS_SYMBOL(CONF_set_default_method)
#endif

#ifndef CRYPTO_ccm128_setiv
#define CRYPTO_ccm128_setiv __NS_SYMBOL(CRYPTO_ccm128_setiv)
#endif

#ifndef DHparams_dup
#define DHparams_dup __NS_SYMBOL(DHparams_dup)
#endif

#ifndef DSA_new_method
#define DSA_new_method __NS_SYMBOL(DSA_new_method)
#endif

#ifndef ECDSA_SIG_new
#define ECDSA_SIG_new __NS_SYMBOL(ECDSA_SIG_new)
#endif

#ifndef ENGINE_set_load_ssl_client_cert_function
#define ENGINE_set_load_ssl_client_cert_function __NS_SYMBOL(ENGINE_set_load_ssl_client_cert_function)
#endif

#ifndef EVP_MD_CTX_create
#define EVP_MD_CTX_create __NS_SYMBOL(EVP_MD_CTX_create)
#endif

#ifndef EVP_camellia_192_cbc
#define EVP_camellia_192_cbc __NS_SYMBOL(EVP_camellia_192_cbc)
#endif

#ifndef EVP_des_cfb1
#define EVP_des_cfb1 __NS_SYMBOL(EVP_des_cfb1)
#endif

#ifndef EVP_des_ede3_cbc
#define EVP_des_ede3_cbc __NS_SYMBOL(EVP_des_ede3_cbc)
#endif

#ifndef EVP_get_pw_prompt
#define EVP_get_pw_prompt __NS_SYMBOL(EVP_get_pw_prompt)
#endif

#ifndef EVP_idea_cfb
#define EVP_idea_cfb __NS_SYMBOL(EVP_idea_cfb)
#endif

#ifndef EVP_rc2_64_cbc
#define EVP_rc2_64_cbc __NS_SYMBOL(EVP_rc2_64_cbc)
#endif

#ifndef EVP_sha512
#define EVP_sha512 __NS_SYMBOL(EVP_sha512)
#endif

#ifndef GOST_KEY_TRANSPORT_new
#define GOST_KEY_TRANSPORT_new __NS_SYMBOL(GOST_KEY_TRANSPORT_new)
#endif

#ifndef KRB5_ENCDATA_new
#define KRB5_ENCDATA_new __NS_SYMBOL(KRB5_ENCDATA_new)
#endif

#ifndef MDC2_Update
#define MDC2_Update __NS_SYMBOL(MDC2_Update)
#endif

#ifndef NETSCAPE_CERT_SEQUENCE_new
#define NETSCAPE_CERT_SEQUENCE_new __NS_SYMBOL(NETSCAPE_CERT_SEQUENCE_new)
#endif

#ifndef NETSCAPE_ENCRYPTED_PKEY_new
#define NETSCAPE_ENCRYPTED_PKEY_new __NS_SYMBOL(NETSCAPE_ENCRYPTED_PKEY_new)
#endif

#ifndef NETSCAPE_SPKAC_new
#define NETSCAPE_SPKAC_new __NS_SYMBOL(NETSCAPE_SPKAC_new)
#endif

#ifndef NETSCAPE_SPKI_b64_decode
#define NETSCAPE_SPKI_b64_decode __NS_SYMBOL(NETSCAPE_SPKI_b64_decode)
#endif

#ifndef NETSCAPE_X509_new
#define NETSCAPE_X509_new __NS_SYMBOL(NETSCAPE_X509_new)
#endif

#ifndef OCSP_REQUEST_get_ext_by_OBJ
#define OCSP_REQUEST_get_ext_by_OBJ __NS_SYMBOL(OCSP_REQUEST_get_ext_by_OBJ)
#endif

#ifndef OCSP_REQ_CTX_set1_req
#define OCSP_REQ_CTX_set1_req __NS_SYMBOL(OCSP_REQ_CTX_set1_req)
#endif

#ifndef OCSP_SIGNATURE_new
#define OCSP_SIGNATURE_new __NS_SYMBOL(OCSP_SIGNATURE_new)
#endif

#ifndef OCSP_cert_status_str
#define OCSP_cert_status_str __NS_SYMBOL(OCSP_cert_status_str)
#endif

#ifndef OCSP_onereq_get0_id
#define OCSP_onereq_get0_id __NS_SYMBOL(OCSP_onereq_get0_id)
#endif

#ifndef OTHERNAME_new
#define OTHERNAME_new __NS_SYMBOL(OTHERNAME_new)
#endif

#ifndef PBE2PARAM_new
#define PBE2PARAM_new __NS_SYMBOL(PBE2PARAM_new)
#endif

#ifndef PBEPARAM_new
#define PBEPARAM_new __NS_SYMBOL(PBEPARAM_new)
#endif

#ifndef PKCS12_new
#define PKCS12_new __NS_SYMBOL(PKCS12_new)
#endif

#ifndef PKCS7_new
#define PKCS7_new __NS_SYMBOL(PKCS7_new)
#endif

#ifndef PKCS8_PRIV_KEY_INFO_new
#define PKCS8_PRIV_KEY_INFO_new __NS_SYMBOL(PKCS8_PRIV_KEY_INFO_new)
#endif

#ifndef PROXY_POLICY_new
#define PROXY_POLICY_new __NS_SYMBOL(PROXY_POLICY_new)
#endif

#ifndef RAND_get_rand_method
#define RAND_get_rand_method __NS_SYMBOL(RAND_get_rand_method)
#endif

#ifndef RSA_PSS_PARAMS_new
#define RSA_PSS_PARAMS_new __NS_SYMBOL(RSA_PSS_PARAMS_new)
#endif

#ifndef RSA_private_decrypt
#define RSA_private_decrypt __NS_SYMBOL(RSA_private_decrypt)
#endif

#ifndef SMIME_write_PKCS7
#define SMIME_write_PKCS7 __NS_SYMBOL(SMIME_write_PKCS7)
#endif

#ifndef TS_MSG_IMPRINT_new
#define TS_MSG_IMPRINT_new __NS_SYMBOL(TS_MSG_IMPRINT_new)
#endif

#ifndef X509_ALGOR_new
#define X509_ALGOR_new __NS_SYMBOL(X509_ALGOR_new)
#endif

#ifndef X509_ATTRIBUTE_new
#define X509_ATTRIBUTE_new __NS_SYMBOL(X509_ATTRIBUTE_new)
#endif

#ifndef X509_CERT_AUX_new
#define X509_CERT_AUX_new __NS_SYMBOL(X509_CERT_AUX_new)
#endif

#ifndef X509_CINF_new
#define X509_CINF_new __NS_SYMBOL(X509_CINF_new)
#endif

#ifndef X509_CRL_get_ext_by_OBJ
#define X509_CRL_get_ext_by_OBJ __NS_SYMBOL(X509_CRL_get_ext_by_OBJ)
#endif

#ifndef X509_EXTENSION_new
#define X509_EXTENSION_new __NS_SYMBOL(X509_EXTENSION_new)
#endif

#ifndef X509_NAME_ENTRY_new
#define X509_NAME_ENTRY_new __NS_SYMBOL(X509_NAME_ENTRY_new)
#endif

#ifndef X509_PUBKEY_new
#define X509_PUBKEY_new __NS_SYMBOL(X509_PUBKEY_new)
#endif

#ifndef X509_REQ_INFO_new
#define X509_REQ_INFO_new __NS_SYMBOL(X509_REQ_INFO_new)
#endif

#ifndef X509_REQ_set_pubkey
#define X509_REQ_set_pubkey __NS_SYMBOL(X509_REQ_set_pubkey)
#endif

#ifndef X509_REVOKED_new
#define X509_REVOKED_new __NS_SYMBOL(X509_REVOKED_new)
#endif

#ifndef X509_SIG_new
#define X509_SIG_new __NS_SYMBOL(X509_SIG_new)
#endif

#ifndef X509_VAL_new
#define X509_VAL_new __NS_SYMBOL(X509_VAL_new)
#endif

#ifndef X509_get_default_cert_dir_env
#define X509_get_default_cert_dir_env __NS_SYMBOL(X509_get_default_cert_dir_env)
#endif

#ifndef X509_policy_tree_get0_policies
#define X509_policy_tree_get0_policies __NS_SYMBOL(X509_policy_tree_get0_policies)
#endif

#ifndef _CONF_get_section_values
#define _CONF_get_section_values __NS_SYMBOL(_CONF_get_section_values)
#endif

#ifndef _ossl_old_des_ncbc_encrypt
#define _ossl_old_des_ncbc_encrypt __NS_SYMBOL(_ossl_old_des_ncbc_encrypt)
#endif

#ifndef aesni_decrypt
#define aesni_decrypt __NS_SYMBOL(aesni_decrypt)
#endif

#ifndef d2i_DSAPrivateKey
#define d2i_DSAPrivateKey __NS_SYMBOL(d2i_DSAPrivateKey)
#endif

#ifndef ec_GFp_mont_group_finish
#define ec_GFp_mont_group_finish __NS_SYMBOL(ec_GFp_mont_group_finish)
#endif

#ifndef get_rfc3526_prime_1536
#define get_rfc3526_prime_1536 __NS_SYMBOL(get_rfc3526_prime_1536)
#endif

#ifndef tree_find_sk
#define tree_find_sk __NS_SYMBOL(tree_find_sk)
#endif

#ifndef BN_generate_prime_ex
#define BN_generate_prime_ex __NS_SYMBOL(BN_generate_prime_ex)
#endif

#ifndef BN_nist_mod_192
#define BN_nist_mod_192 __NS_SYMBOL(BN_nist_mod_192)
#endif

#ifndef CMAC_CTX_cleanup
#define CMAC_CTX_cleanup __NS_SYMBOL(CMAC_CTX_cleanup)
#endif

#ifndef CMS_get0_RecipientInfos
#define CMS_get0_RecipientInfos __NS_SYMBOL(CMS_get0_RecipientInfos)
#endif

#ifndef CMS_signed_add1_attr
#define CMS_signed_add1_attr __NS_SYMBOL(CMS_signed_add1_attr)
#endif

#ifndef ECDSA_do_sign_ex
#define ECDSA_do_sign_ex __NS_SYMBOL(ECDSA_do_sign_ex)
#endif

#ifndef ECDSA_verify
#define ECDSA_verify __NS_SYMBOL(ECDSA_verify)
#endif

#ifndef ERR_unload_GOST_strings
#define ERR_unload_GOST_strings __NS_SYMBOL(ERR_unload_GOST_strings)
#endif

#ifndef EVP_camellia_192_cfb128
#define EVP_camellia_192_cfb128 __NS_SYMBOL(EVP_camellia_192_cfb128)
#endif

#ifndef EVP_des_cfb8
#define EVP_des_cfb8 __NS_SYMBOL(EVP_des_cfb8)
#endif

#ifndef EVP_des_ede3_cfb64
#define EVP_des_ede3_cfb64 __NS_SYMBOL(EVP_des_ede3_cfb64)
#endif

#ifndef EVP_rc2_40_cbc
#define EVP_rc2_40_cbc __NS_SYMBOL(EVP_rc2_40_cbc)
#endif

#ifndef EVP_rc2_cfb
#define EVP_rc2_cfb __NS_SYMBOL(EVP_rc2_cfb)
#endif

#ifndef OCSP_id_get0_info
#define OCSP_id_get0_info __NS_SYMBOL(OCSP_id_get0_info)
#endif

#ifndef RSA_public_decrypt
#define RSA_public_decrypt __NS_SYMBOL(RSA_public_decrypt)
#endif

#ifndef X509_CRL_set_issuer_name
#define X509_CRL_set_issuer_name __NS_SYMBOL(X509_CRL_set_issuer_name)
#endif

#ifndef X509_NAME_get_text_by_OBJ
#define X509_NAME_get_text_by_OBJ __NS_SYMBOL(X509_NAME_get_text_by_OBJ)
#endif

#ifndef X509_get_default_cert_file_env
#define X509_get_default_cert_file_env __NS_SYMBOL(X509_get_default_cert_file_env)
#endif

#ifndef X509_set_serialNumber
#define X509_set_serialNumber __NS_SYMBOL(X509_set_serialNumber)
#endif

#ifndef _ossl_old_des_xcbc_encrypt
#define _ossl_old_des_xcbc_encrypt __NS_SYMBOL(_ossl_old_des_xcbc_encrypt)
#endif

#ifndef ec_GF2m_simple_group_finish
#define ec_GF2m_simple_group_finish __NS_SYMBOL(ec_GF2m_simple_group_finish)
#endif

#ifndef ec_GFp_simple_group_finish
#define ec_GFp_simple_group_finish __NS_SYMBOL(ec_GFp_simple_group_finish)
#endif

#ifndef engine_unlocked_finish
#define engine_unlocked_finish __NS_SYMBOL(engine_unlocked_finish)
#endif

#ifndef i2c_ASN1_INTEGER
#define i2c_ASN1_INTEGER __NS_SYMBOL(i2c_ASN1_INTEGER)
#endif

#ifndef pitem_free
#define pitem_free __NS_SYMBOL(pitem_free)
#endif

#ifndef policy_cache_set
#define policy_cache_set __NS_SYMBOL(policy_cache_set)
#endif

#ifndef policy_data_new
#define policy_data_new __NS_SYMBOL(policy_data_new)
#endif

#ifndef AES_cfb8_encrypt
#define AES_cfb8_encrypt __NS_SYMBOL(AES_cfb8_encrypt)
#endif

#ifndef ASN1_INTEGER_free
#define ASN1_INTEGER_free __NS_SYMBOL(ASN1_INTEGER_free)
#endif

#ifndef ASN1_TIME_free
#define ASN1_TIME_free __NS_SYMBOL(ASN1_TIME_free)
#endif

#ifndef AUTHORITY_KEYID_free
#define AUTHORITY_KEYID_free __NS_SYMBOL(AUTHORITY_KEYID_free)
#endif

#ifndef BIO_dgram_non_fatal_error
#define BIO_dgram_non_fatal_error __NS_SYMBOL(BIO_dgram_non_fatal_error)
#endif

#ifndef BIO_fd_should_retry
#define BIO_fd_should_retry __NS_SYMBOL(BIO_fd_should_retry)
#endif

#ifndef BIO_sock_should_retry
#define BIO_sock_should_retry __NS_SYMBOL(BIO_sock_should_retry)
#endif

#ifndef BN_div_word
#define BN_div_word __NS_SYMBOL(BN_div_word)
#endif

#ifndef BN_get_params
#define BN_get_params __NS_SYMBOL(BN_get_params)
#endif

#ifndef BUF_MEM_free
#define BUF_MEM_free __NS_SYMBOL(BUF_MEM_free)
#endif

#ifndef CMS_ContentInfo_free
#define CMS_ContentInfo_free __NS_SYMBOL(CMS_ContentInfo_free)
#endif

#ifndef CMS_ReceiptRequest_free
#define CMS_ReceiptRequest_free __NS_SYMBOL(CMS_ReceiptRequest_free)
#endif

#ifndef CMS_add0_recipient_password
#define CMS_add0_recipient_password __NS_SYMBOL(CMS_add0_recipient_password)
#endif

#ifndef CONF_load
#define CONF_load __NS_SYMBOL(CONF_load)
#endif

#ifndef Camellia_cfb8_encrypt
#define Camellia_cfb8_encrypt __NS_SYMBOL(Camellia_cfb8_encrypt)
#endif

#ifndef Camellia_encrypt
#define Camellia_encrypt __NS_SYMBOL(Camellia_encrypt)
#endif

#ifndef DES_check_key_parity
#define DES_check_key_parity __NS_SYMBOL(DES_check_key_parity)
#endif

#ifndef DES_ecb_encrypt
#define DES_ecb_encrypt __NS_SYMBOL(DES_ecb_encrypt)
#endif

#ifndef DSA_SIG_free
#define DSA_SIG_free __NS_SYMBOL(DSA_SIG_free)
#endif

#ifndef ECDSA_SIG_free
#define ECDSA_SIG_free __NS_SYMBOL(ECDSA_SIG_free)
#endif

#ifndef EC_GROUP_get_trinomial_basis
#define EC_GROUP_get_trinomial_basis __NS_SYMBOL(EC_GROUP_get_trinomial_basis)
#endif

#ifndef ENGINE_get_last
#define ENGINE_get_last __NS_SYMBOL(ENGINE_get_last)
#endif

#ifndef ENGINE_get_load_privkey_function
#define ENGINE_get_load_privkey_function __NS_SYMBOL(ENGINE_get_load_privkey_function)
#endif

#ifndef EVP_CipherInit
#define EVP_CipherInit __NS_SYMBOL(EVP_CipherInit)
#endif

#ifndef EVP_PKEY_asn1_find
#define EVP_PKEY_asn1_find __NS_SYMBOL(EVP_PKEY_asn1_find)
#endif

#ifndef EVP_PKEY_save_parameters
#define EVP_PKEY_save_parameters __NS_SYMBOL(EVP_PKEY_save_parameters)
#endif

#ifndef EVP_add_digest
#define EVP_add_digest __NS_SYMBOL(EVP_add_digest)
#endif

#ifndef EVP_aes_128_ofb
#define EVP_aes_128_ofb __NS_SYMBOL(EVP_aes_128_ofb)
#endif

#ifndef EVP_camellia_192_ofb
#define EVP_camellia_192_ofb __NS_SYMBOL(EVP_camellia_192_ofb)
#endif

#ifndef EVP_cast5_cfb
#define EVP_cast5_cfb __NS_SYMBOL(EVP_cast5_cfb)
#endif

#ifndef EVP_des_ede3_ofb
#define EVP_des_ede3_ofb __NS_SYMBOL(EVP_des_ede3_ofb)
#endif

#ifndef EVP_read_pw_string
#define EVP_read_pw_string __NS_SYMBOL(EVP_read_pw_string)
#endif

#ifndef GOST_KEY_TRANSPORT_free
#define GOST_KEY_TRANSPORT_free __NS_SYMBOL(GOST_KEY_TRANSPORT_free)
#endif

#ifndef KRB5_ENCDATA_free
#define KRB5_ENCDATA_free __NS_SYMBOL(KRB5_ENCDATA_free)
#endif

#ifndef NETSCAPE_CERT_SEQUENCE_free
#define NETSCAPE_CERT_SEQUENCE_free __NS_SYMBOL(NETSCAPE_CERT_SEQUENCE_free)
#endif

#ifndef NETSCAPE_ENCRYPTED_PKEY_free
#define NETSCAPE_ENCRYPTED_PKEY_free __NS_SYMBOL(NETSCAPE_ENCRYPTED_PKEY_free)
#endif

#ifndef NETSCAPE_SPKAC_free
#define NETSCAPE_SPKAC_free __NS_SYMBOL(NETSCAPE_SPKAC_free)
#endif

#ifndef NETSCAPE_SPKI_verify
#define NETSCAPE_SPKI_verify __NS_SYMBOL(NETSCAPE_SPKI_verify)
#endif

#ifndef NETSCAPE_X509_free
#define NETSCAPE_X509_free __NS_SYMBOL(NETSCAPE_X509_free)
#endif

#ifndef OCSP_REQUEST_get_ext_by_critical
#define OCSP_REQUEST_get_ext_by_critical __NS_SYMBOL(OCSP_REQUEST_get_ext_by_critical)
#endif

#ifndef OCSP_SIGNATURE_free
#define OCSP_SIGNATURE_free __NS_SYMBOL(OCSP_SIGNATURE_free)
#endif

#ifndef OCSP_request_set1_name
#define OCSP_request_set1_name __NS_SYMBOL(OCSP_request_set1_name)
#endif

#ifndef OPENSSL_gmtime_adj
#define OPENSSL_gmtime_adj __NS_SYMBOL(OPENSSL_gmtime_adj)
#endif

#ifndef OTHERNAME_free
#define OTHERNAME_free __NS_SYMBOL(OTHERNAME_free)
#endif

#ifndef PBE2PARAM_free
#define PBE2PARAM_free __NS_SYMBOL(PBE2PARAM_free)
#endif

#ifndef PBEPARAM_free
#define PBEPARAM_free __NS_SYMBOL(PBEPARAM_free)
#endif

#ifndef PEM_write_bio_X509
#define PEM_write_bio_X509 __NS_SYMBOL(PEM_write_bio_X509)
#endif

#ifndef PEM_write_bio_X509_AUX
#define PEM_write_bio_X509_AUX __NS_SYMBOL(PEM_write_bio_X509_AUX)
#endif

#ifndef PEM_write_bio_X509_REQ
#define PEM_write_bio_X509_REQ __NS_SYMBOL(PEM_write_bio_X509_REQ)
#endif

#ifndef PKCS12_free
#define PKCS12_free __NS_SYMBOL(PKCS12_free)
#endif

#ifndef PKCS7_free
#define PKCS7_free __NS_SYMBOL(PKCS7_free)
#endif

#ifndef PKCS8_PRIV_KEY_INFO_free
#define PKCS8_PRIV_KEY_INFO_free __NS_SYMBOL(PKCS8_PRIV_KEY_INFO_free)
#endif

#ifndef PROXY_POLICY_free
#define PROXY_POLICY_free __NS_SYMBOL(PROXY_POLICY_free)
#endif

#ifndef RSA_PSS_PARAMS_free
#define RSA_PSS_PARAMS_free __NS_SYMBOL(RSA_PSS_PARAMS_free)
#endif

#ifndef RSA_flags
#define RSA_flags __NS_SYMBOL(RSA_flags)
#endif

#ifndef TS_MSG_IMPRINT_free
#define TS_MSG_IMPRINT_free __NS_SYMBOL(TS_MSG_IMPRINT_free)
#endif

#ifndef X509_ALGOR_free
#define X509_ALGOR_free __NS_SYMBOL(X509_ALGOR_free)
#endif

#ifndef X509_ATTRIBUTE_free
#define X509_ATTRIBUTE_free __NS_SYMBOL(X509_ATTRIBUTE_free)
#endif

#ifndef X509_CERT_AUX_free
#define X509_CERT_AUX_free __NS_SYMBOL(X509_CERT_AUX_free)
#endif

#ifndef X509_CINF_free
#define X509_CINF_free __NS_SYMBOL(X509_CINF_free)
#endif

#ifndef X509_CRL_get_ext_by_critical
#define X509_CRL_get_ext_by_critical __NS_SYMBOL(X509_CRL_get_ext_by_critical)
#endif

#ifndef X509_EXTENSION_free
#define X509_EXTENSION_free __NS_SYMBOL(X509_EXTENSION_free)
#endif

#ifndef X509_NAME_ENTRY_free
#define X509_NAME_ENTRY_free __NS_SYMBOL(X509_NAME_ENTRY_free)
#endif

#ifndef X509_PUBKEY_free
#define X509_PUBKEY_free __NS_SYMBOL(X509_PUBKEY_free)
#endif

#ifndef X509_REQ_INFO_free
#define X509_REQ_INFO_free __NS_SYMBOL(X509_REQ_INFO_free)
#endif

#ifndef X509_REVOKED_free
#define X509_REVOKED_free __NS_SYMBOL(X509_REVOKED_free)
#endif

#ifndef X509_SIG_free
#define X509_SIG_free __NS_SYMBOL(X509_SIG_free)
#endif

#ifndef X509_VAL_free
#define X509_VAL_free __NS_SYMBOL(X509_VAL_free)
#endif

#ifndef X509_policy_tree_get0_user_policies
#define X509_policy_tree_get0_user_policies __NS_SYMBOL(X509_policy_tree_get0_user_policies)
#endif

#ifndef _ossl_old_des_cfb_encrypt
#define _ossl_old_des_cfb_encrypt __NS_SYMBOL(_ossl_old_des_cfb_encrypt)
#endif

#ifndef get_rfc3526_prime_2048
#define get_rfc3526_prime_2048 __NS_SYMBOL(get_rfc3526_prime_2048)
#endif

#ifndef i2d_DSAPrivateKey
#define i2d_DSAPrivateKey __NS_SYMBOL(i2d_DSAPrivateKey)
#endif

#ifndef lh_stats_bio
#define lh_stats_bio __NS_SYMBOL(lh_stats_bio)
#endif

#ifndef v2i_ASN1_BIT_STRING
#define v2i_ASN1_BIT_STRING __NS_SYMBOL(v2i_ASN1_BIT_STRING)
#endif

#ifndef ASN1_PCTX_free
#define ASN1_PCTX_free __NS_SYMBOL(ASN1_PCTX_free)
#endif

#ifndef ASN1_TYPE_get_octetstring
#define ASN1_TYPE_get_octetstring __NS_SYMBOL(ASN1_TYPE_get_octetstring)
#endif

#ifndef ASN1_TYPE_set1
#define ASN1_TYPE_set1 __NS_SYMBOL(ASN1_TYPE_set1)
#endif

#ifndef ASN1_seq_pack
#define ASN1_seq_pack __NS_SYMBOL(ASN1_seq_pack)
#endif

#ifndef BIO_CONNECT_free
#define BIO_CONNECT_free __NS_SYMBOL(BIO_CONNECT_free)
#endif

#ifndef CMS_signed_add1_attr_by_OBJ
#define CMS_signed_add1_attr_by_OBJ __NS_SYMBOL(CMS_signed_add1_attr_by_OBJ)
#endif

#ifndef CRYPTO_set_ex_data_implementation
#define CRYPTO_set_ex_data_implementation __NS_SYMBOL(CRYPTO_set_ex_data_implementation)
#endif

#ifndef ENGINE_get_load_pubkey_function
#define ENGINE_get_load_pubkey_function __NS_SYMBOL(ENGINE_get_load_pubkey_function)
#endif

#ifndef ERR_set_implementation
#define ERR_set_implementation __NS_SYMBOL(ERR_set_implementation)
#endif

#ifndef EVP_aes_128_cfb
#define EVP_aes_128_cfb __NS_SYMBOL(EVP_aes_128_cfb)
#endif

#ifndef EVP_camellia_192_ecb
#define EVP_camellia_192_ecb __NS_SYMBOL(EVP_camellia_192_ecb)
#endif

#ifndef EVP_des_ede3_ecb
#define EVP_des_ede3_ecb __NS_SYMBOL(EVP_des_ede3_ecb)
#endif

#ifndef OCSP_cert_id_new
#define OCSP_cert_id_new __NS_SYMBOL(OCSP_cert_id_new)
#endif

#ifndef PKCS12_add_friendlyname_asc
#define PKCS12_add_friendlyname_asc __NS_SYMBOL(PKCS12_add_friendlyname_asc)
#endif

#ifndef RSA_padding_check_none
#define RSA_padding_check_none __NS_SYMBOL(RSA_padding_check_none)
#endif

#ifndef TS_CONF_load_certs
#define TS_CONF_load_certs __NS_SYMBOL(TS_CONF_load_certs)
#endif

#ifndef TS_RESP_get_status_info
#define TS_RESP_get_status_info __NS_SYMBOL(TS_RESP_get_status_info)
#endif

#ifndef X509_CRL_set_lastUpdate
#define X509_CRL_set_lastUpdate __NS_SYMBOL(X509_CRL_set_lastUpdate)
#endif

#ifndef _ossl_old_des_ecb_encrypt
#define _ossl_old_des_ecb_encrypt __NS_SYMBOL(_ossl_old_des_ecb_encrypt)
#endif

#ifndef d2i_ASN1_BOOLEAN
#define d2i_ASN1_BOOLEAN __NS_SYMBOL(d2i_ASN1_BOOLEAN)
#endif

#ifndef ecdh_check
#define ecdh_check __NS_SYMBOL(ecdh_check)
#endif

#ifndef ecdsa_check
#define ecdsa_check __NS_SYMBOL(ecdsa_check)
#endif

#ifndef pqueue_new
#define pqueue_new __NS_SYMBOL(pqueue_new)
#endif

#ifndef ASN1_PCTX_get_flags
#define ASN1_PCTX_get_flags __NS_SYMBOL(ASN1_PCTX_get_flags)
#endif

#ifndef ASN1_TIME_set
#define ASN1_TIME_set __NS_SYMBOL(ASN1_TIME_set)
#endif

#ifndef ASN1_get_object
#define ASN1_get_object __NS_SYMBOL(ASN1_get_object)
#endif

#ifndef ASN1_item_ex_d2i
#define ASN1_item_ex_d2i __NS_SYMBOL(ASN1_item_ex_d2i)
#endif

#ifndef BIO_asn1_set_suffix
#define BIO_asn1_set_suffix __NS_SYMBOL(BIO_asn1_set_suffix)
#endif

#ifndef BN_RECP_CTX_free
#define BN_RECP_CTX_free __NS_SYMBOL(BN_RECP_CTX_free)
#endif

#ifndef BN_mod_add
#define BN_mod_add __NS_SYMBOL(BN_mod_add)
#endif

#ifndef CMS_ContentInfo_print_ctx
#define CMS_ContentInfo_print_ctx __NS_SYMBOL(CMS_ContentInfo_print_ctx)
#endif

#ifndef CMS_get1_ReceiptRequest
#define CMS_get1_ReceiptRequest __NS_SYMBOL(CMS_get1_ReceiptRequest)
#endif

#ifndef Camellia_decrypt
#define Camellia_decrypt __NS_SYMBOL(Camellia_decrypt)
#endif

#ifndef EC_POINT_set_compressed_coordinates_GF2m
#define EC_POINT_set_compressed_coordinates_GF2m __NS_SYMBOL(EC_POINT_set_compressed_coordinates_GF2m)
#endif

#ifndef ENGINE_get_ssl_client_cert_function
#define ENGINE_get_ssl_client_cert_function __NS_SYMBOL(ENGINE_get_ssl_client_cert_function)
#endif

#ifndef ENGINE_register_all_DH
#define ENGINE_register_all_DH __NS_SYMBOL(ENGINE_register_all_DH)
#endif

#ifndef ENGINE_register_all_DSA
#define ENGINE_register_all_DSA __NS_SYMBOL(ENGINE_register_all_DSA)
#endif

#ifndef ENGINE_register_all_ECDH
#define ENGINE_register_all_ECDH __NS_SYMBOL(ENGINE_register_all_ECDH)
#endif

#ifndef ENGINE_register_all_ECDSA
#define ENGINE_register_all_ECDSA __NS_SYMBOL(ENGINE_register_all_ECDSA)
#endif

#ifndef ENGINE_register_all_RAND
#define ENGINE_register_all_RAND __NS_SYMBOL(ENGINE_register_all_RAND)
#endif

#ifndef ENGINE_register_all_RSA
#define ENGINE_register_all_RSA __NS_SYMBOL(ENGINE_register_all_RSA)
#endif

#ifndef ENGINE_register_all_STORE
#define ENGINE_register_all_STORE __NS_SYMBOL(ENGINE_register_all_STORE)
#endif

#ifndef EVP_PKEY_paramgen
#define EVP_PKEY_paramgen __NS_SYMBOL(EVP_PKEY_paramgen)
#endif

#ifndef EVP_PKEY_sign
#define EVP_PKEY_sign __NS_SYMBOL(EVP_PKEY_sign)
#endif

#ifndef EVP_aes_192_cfb
#define EVP_aes_192_cfb __NS_SYMBOL(EVP_aes_192_cfb)
#endif

#ifndef EVP_camellia_256_cbc
#define EVP_camellia_256_cbc __NS_SYMBOL(EVP_camellia_256_cbc)
#endif

#ifndef EVP_des_ede3_cfb1
#define EVP_des_ede3_cfb1 __NS_SYMBOL(EVP_des_ede3_cfb1)
#endif

#ifndef EVP_read_pw_string_min
#define EVP_read_pw_string_min __NS_SYMBOL(EVP_read_pw_string_min)
#endif

#ifndef OCSP_REQUEST_get_ext
#define OCSP_REQUEST_get_ext __NS_SYMBOL(OCSP_REQUEST_get_ext)
#endif

#ifndef OCSP_crl_reason_str
#define OCSP_crl_reason_str __NS_SYMBOL(OCSP_crl_reason_str)
#endif

#ifndef PKCS5_pbe_set0_algor
#define PKCS5_pbe_set0_algor __NS_SYMBOL(PKCS5_pbe_set0_algor)
#endif

#ifndef PKCS7_get_smimecap
#define PKCS7_get_smimecap __NS_SYMBOL(PKCS7_get_smimecap)
#endif

#ifndef PKCS8_pkey_set0
#define PKCS8_pkey_set0 __NS_SYMBOL(PKCS8_pkey_set0)
#endif

#ifndef RSA_blinding_off
#define RSA_blinding_off __NS_SYMBOL(RSA_blinding_off)
#endif

#ifndef TS_MSG_IMPRINT_dup
#define TS_MSG_IMPRINT_dup __NS_SYMBOL(TS_MSG_IMPRINT_dup)
#endif

#ifndef TS_RESP_set_tst_info
#define TS_RESP_set_tst_info __NS_SYMBOL(TS_RESP_set_tst_info)
#endif

#ifndef TS_STATUS_INFO_print_bio
#define TS_STATUS_INFO_print_bio __NS_SYMBOL(TS_STATUS_INFO_print_bio)
#endif

#ifndef X509_ATTRIBUTE_dup
#define X509_ATTRIBUTE_dup __NS_SYMBOL(X509_ATTRIBUTE_dup)
#endif

#ifndef X509_CRL_get_ext
#define X509_CRL_get_ext __NS_SYMBOL(X509_CRL_get_ext)
#endif

#ifndef X509_CRL_print
#define X509_CRL_print __NS_SYMBOL(X509_CRL_print)
#endif

#ifndef X509_INFO_free
#define X509_INFO_free __NS_SYMBOL(X509_INFO_free)
#endif

#ifndef X509_LOOKUP_free
#define X509_LOOKUP_free __NS_SYMBOL(X509_LOOKUP_free)
#endif

#ifndef X509_NAME_ENTRY_dup
#define X509_NAME_ENTRY_dup __NS_SYMBOL(X509_NAME_ENTRY_dup)
#endif

#ifndef X509_PUBKEY_set
#define X509_PUBKEY_set __NS_SYMBOL(X509_PUBKEY_set)
#endif

#ifndef X509_STORE_load_locations
#define X509_STORE_load_locations __NS_SYMBOL(X509_STORE_load_locations)
#endif

#ifndef X509_alias_set1
#define X509_alias_set1 __NS_SYMBOL(X509_alias_set1)
#endif

#ifndef X509_policy_level_node_count
#define X509_policy_level_node_count __NS_SYMBOL(X509_policy_level_node_count)
#endif

#ifndef _ossl_old_des_encrypt
#define _ossl_old_des_encrypt __NS_SYMBOL(_ossl_old_des_encrypt)
#endif

#ifndef cms_DigestedData_init_bio
#define cms_DigestedData_init_bio __NS_SYMBOL(cms_DigestedData_init_bio)
#endif

#ifndef d2i_ASN1_ENUMERATED
#define d2i_ASN1_ENUMERATED __NS_SYMBOL(d2i_ASN1_ENUMERATED)
#endif

#ifndef d2i_DSAparams
#define d2i_DSAparams __NS_SYMBOL(d2i_DSAparams)
#endif

#ifndef d2i_EDIPARTYNAME
#define d2i_EDIPARTYNAME __NS_SYMBOL(d2i_EDIPARTYNAME)
#endif

#ifndef d2i_GOST_KEY_INFO
#define d2i_GOST_KEY_INFO __NS_SYMBOL(d2i_GOST_KEY_INFO)
#endif

#ifndef d2i_KRB5_PRINCNAME
#define d2i_KRB5_PRINCNAME __NS_SYMBOL(d2i_KRB5_PRINCNAME)
#endif

#ifndef d2i_NETSCAPE_PKEY
#define d2i_NETSCAPE_PKEY __NS_SYMBOL(d2i_NETSCAPE_PKEY)
#endif

#ifndef d2i_NETSCAPE_SPKI
#define d2i_NETSCAPE_SPKI __NS_SYMBOL(d2i_NETSCAPE_SPKI)
#endif

#ifndef d2i_OCSP_CERTID
#define d2i_OCSP_CERTID __NS_SYMBOL(d2i_OCSP_CERTID)
#endif

#ifndef d2i_PBKDF2PARAM
#define d2i_PBKDF2PARAM __NS_SYMBOL(d2i_PBKDF2PARAM)
#endif

#ifndef d2i_PKCS12_MAC_DATA
#define d2i_PKCS12_MAC_DATA __NS_SYMBOL(d2i_PKCS12_MAC_DATA)
#endif

#ifndef d2i_PROXY_CERT_INFO_EXTENSION
#define d2i_PROXY_CERT_INFO_EXTENSION __NS_SYMBOL(d2i_PROXY_CERT_INFO_EXTENSION)
#endif

#ifndef d2i_RSAPrivateKey
#define d2i_RSAPrivateKey __NS_SYMBOL(d2i_RSAPrivateKey)
#endif

#ifndef d2i_X509
#define d2i_X509 __NS_SYMBOL(d2i_X509)
#endif

#ifndef d2i_X509_ALGORS
#define d2i_X509_ALGORS __NS_SYMBOL(d2i_X509_ALGORS)
#endif

#ifndef d2i_X509_CRL_INFO
#define d2i_X509_CRL_INFO __NS_SYMBOL(d2i_X509_CRL_INFO)
#endif

#ifndef d2i_X509_EXTENSIONS
#define d2i_X509_EXTENSIONS __NS_SYMBOL(d2i_X509_EXTENSIONS)
#endif

#ifndef d2i_X509_REQ
#define d2i_X509_REQ __NS_SYMBOL(d2i_X509_REQ)
#endif

#ifndef engine_set_all_null
#define engine_set_all_null __NS_SYMBOL(engine_set_all_null)
#endif

#ifndef get_rfc3526_prime_3072
#define get_rfc3526_prime_3072 __NS_SYMBOL(get_rfc3526_prime_3072)
#endif

#ifndef gost_get0_priv_key
#define gost_get0_priv_key __NS_SYMBOL(gost_get0_priv_key)
#endif

#ifndef i2d_PKCS7_NDEF
#define i2d_PKCS7_NDEF __NS_SYMBOL(i2d_PKCS7_NDEF)
#endif

#ifndef level_find_node
#define level_find_node __NS_SYMBOL(level_find_node)
#endif

#ifndef ASN1_PCTX_set_flags
#define ASN1_PCTX_set_flags __NS_SYMBOL(ASN1_PCTX_set_flags)
#endif

#ifndef ASN1_i2d_bio
#define ASN1_i2d_bio __NS_SYMBOL(ASN1_i2d_bio)
#endif

#ifndef CMS_signed_add1_attr_by_NID
#define CMS_signed_add1_attr_by_NID __NS_SYMBOL(CMS_signed_add1_attr_by_NID)
#endif

#ifndef COMP_CTX_free
#define COMP_CTX_free __NS_SYMBOL(COMP_CTX_free)
#endif

#ifndef DES_is_weak_key
#define DES_is_weak_key __NS_SYMBOL(DES_is_weak_key)
#endif

#ifndef DH_new
#define DH_new __NS_SYMBOL(DH_new)
#endif

#ifndef ECPKParameters_print
#define ECPKParameters_print __NS_SYMBOL(ECPKParameters_print)
#endif

#ifndef EC_KEY_new_by_curve_name
#define EC_KEY_new_by_curve_name __NS_SYMBOL(EC_KEY_new_by_curve_name)
#endif

#ifndef ENGINE_load_private_key
#define ENGINE_load_private_key __NS_SYMBOL(ENGINE_load_private_key)
#endif

#ifndef ERR_GOST_error
#define ERR_GOST_error __NS_SYMBOL(ERR_GOST_error)
#endif

#ifndef EVP_CIPHER_set_asn1_iv
#define EVP_CIPHER_set_asn1_iv __NS_SYMBOL(EVP_CIPHER_set_asn1_iv)
#endif

#ifndef EVP_DigestInit
#define EVP_DigestInit __NS_SYMBOL(EVP_DigestInit)
#endif

#ifndef EVP_PKEY_copy_parameters
#define EVP_PKEY_copy_parameters __NS_SYMBOL(EVP_PKEY_copy_parameters)
#endif

#ifndef EVP_PKEY_meth_new
#define EVP_PKEY_meth_new __NS_SYMBOL(EVP_PKEY_meth_new)
#endif

#ifndef EVP_aes_128_cfb128
#define EVP_aes_128_cfb128 __NS_SYMBOL(EVP_aes_128_cfb128)
#endif

#ifndef EVP_aes_256_cfb
#define EVP_aes_256_cfb __NS_SYMBOL(EVP_aes_256_cfb)
#endif

#ifndef EVP_camellia_256_cfb128
#define EVP_camellia_256_cfb128 __NS_SYMBOL(EVP_camellia_256_cfb128)
#endif

#ifndef EVP_des_ede3_cfb8
#define EVP_des_ede3_cfb8 __NS_SYMBOL(EVP_des_ede3_cfb8)
#endif

#ifndef OPENSSL_no_config
#define OPENSSL_no_config __NS_SYMBOL(OPENSSL_no_config)
#endif

#ifndef RSA_padding_check_PKCS1_type_1
#define RSA_padding_check_PKCS1_type_1 __NS_SYMBOL(RSA_padding_check_PKCS1_type_1)
#endif

#ifndef TS_REQ_get_msg_imprint
#define TS_REQ_get_msg_imprint __NS_SYMBOL(TS_REQ_get_msg_imprint)
#endif

#ifndef X509_REQ_print
#define X509_REQ_print __NS_SYMBOL(X509_REQ_print)
#endif

#ifndef X509_print_ex_fp
#define X509_print_ex_fp __NS_SYMBOL(X509_print_ex_fp)
#endif

#ifndef X509_sign
#define X509_sign __NS_SYMBOL(X509_sign)
#endif

#ifndef _CONF_add_string
#define _CONF_add_string __NS_SYMBOL(_CONF_add_string)
#endif

#ifndef _ossl_old_des_encrypt2
#define _ossl_old_des_encrypt2 __NS_SYMBOL(_ossl_old_des_encrypt2)
#endif

#ifndef a2d_ASN1_OBJECT
#define a2d_ASN1_OBJECT __NS_SYMBOL(a2d_ASN1_OBJECT)
#endif

#ifndef asn1_enc_init
#define asn1_enc_init __NS_SYMBOL(asn1_enc_init)
#endif

#ifndef d2i_CMS_bio
#define d2i_CMS_bio __NS_SYMBOL(d2i_CMS_bio)
#endif

#ifndef ec_GF2m_simple_group_clear_finish
#define ec_GF2m_simple_group_clear_finish __NS_SYMBOL(ec_GF2m_simple_group_clear_finish)
#endif

#ifndef ec_GFp_mont_group_clear_finish
#define ec_GFp_mont_group_clear_finish __NS_SYMBOL(ec_GFp_mont_group_clear_finish)
#endif

#ifndef ec_GFp_simple_group_clear_finish
#define ec_GFp_simple_group_clear_finish __NS_SYMBOL(ec_GFp_simple_group_clear_finish)
#endif

#ifndef gost_set_default_param
#define gost_set_default_param __NS_SYMBOL(gost_set_default_param)
#endif

#ifndef ASN1_PCTX_get_nm_flags
#define ASN1_PCTX_get_nm_flags __NS_SYMBOL(ASN1_PCTX_get_nm_flags)
#endif

#ifndef BIO_fd_non_fatal_error
#define BIO_fd_non_fatal_error __NS_SYMBOL(BIO_fd_non_fatal_error)
#endif

#ifndef BIO_sock_non_fatal_error
#define BIO_sock_non_fatal_error __NS_SYMBOL(BIO_sock_non_fatal_error)
#endif

#ifndef BN_mpi2bn
#define BN_mpi2bn __NS_SYMBOL(BN_mpi2bn)
#endif

#ifndef BN_usub
#define BN_usub __NS_SYMBOL(BN_usub)
#endif

#ifndef BUF_MEM_grow
#define BUF_MEM_grow __NS_SYMBOL(BUF_MEM_grow)
#endif

#ifndef BUF_strndup
#define BUF_strndup __NS_SYMBOL(BUF_strndup)
#endif

#ifndef CMS_get0_type
#define CMS_get0_type __NS_SYMBOL(CMS_get0_type)
#endif

#ifndef CRYPTO_num_locks
#define CRYPTO_num_locks __NS_SYMBOL(CRYPTO_num_locks)
#endif

#ifndef DES_read_2passwords
#define DES_read_2passwords __NS_SYMBOL(DES_read_2passwords)
#endif

#ifndef DH_new_method
#define DH_new_method __NS_SYMBOL(DH_new_method)
#endif

#ifndef ENGINE_register_all_ciphers
#define ENGINE_register_all_ciphers __NS_SYMBOL(ENGINE_register_all_ciphers)
#endif

#ifndef ENGINE_register_all_digests
#define ENGINE_register_all_digests __NS_SYMBOL(ENGINE_register_all_digests)
#endif

#ifndef ENGINE_register_all_pkey_asn1_meths
#define ENGINE_register_all_pkey_asn1_meths __NS_SYMBOL(ENGINE_register_all_pkey_asn1_meths)
#endif

#ifndef ENGINE_register_all_pkey_meths
#define ENGINE_register_all_pkey_meths __NS_SYMBOL(ENGINE_register_all_pkey_meths)
#endif

#ifndef EVP_camellia_256_ofb
#define EVP_camellia_256_ofb __NS_SYMBOL(EVP_camellia_256_ofb)
#endif

#ifndef EVP_des_ede
#define EVP_des_ede __NS_SYMBOL(EVP_des_ede)
#endif

#ifndef OBJ_find_sigid_by_algs
#define OBJ_find_sigid_by_algs __NS_SYMBOL(OBJ_find_sigid_by_algs)
#endif

#ifndef OCSP_REQUEST_delete_ext
#define OCSP_REQUEST_delete_ext __NS_SYMBOL(OCSP_REQUEST_delete_ext)
#endif

#ifndef OCSP_request_is_signed
#define OCSP_request_is_signed __NS_SYMBOL(OCSP_request_is_signed)
#endif

#ifndef PEM_X509_INFO_read_bio
#define PEM_X509_INFO_read_bio __NS_SYMBOL(PEM_X509_INFO_read_bio)
#endif

#ifndef PKCS12_add_friendlyname_uni
#define PKCS12_add_friendlyname_uni __NS_SYMBOL(PKCS12_add_friendlyname_uni)
#endif

#ifndef PKCS7_dup
#define PKCS7_dup __NS_SYMBOL(PKCS7_dup)
#endif

#ifndef RAND_set_rand_engine
#define RAND_set_rand_engine __NS_SYMBOL(RAND_set_rand_engine)
#endif

#ifndef SHA512_Init
#define SHA512_Init __NS_SYMBOL(SHA512_Init)
#endif

#ifndef SRP_VBASE_free
#define SRP_VBASE_free __NS_SYMBOL(SRP_VBASE_free)
#endif

#ifndef TS_MSG_IMPRINT_set_algo
#define TS_MSG_IMPRINT_set_algo __NS_SYMBOL(TS_MSG_IMPRINT_set_algo)
#endif

#ifndef TS_OBJ_print_bio
#define TS_OBJ_print_bio __NS_SYMBOL(TS_OBJ_print_bio)
#endif

#ifndef TS_VERIFY_CTX_init
#define TS_VERIFY_CTX_init __NS_SYMBOL(TS_VERIFY_CTX_init)
#endif

#ifndef UI_new_method
#define UI_new_method __NS_SYMBOL(UI_new_method)
#endif

#ifndef X509V3_EXT_get_nid
#define X509V3_EXT_get_nid __NS_SYMBOL(X509V3_EXT_get_nid)
#endif

#ifndef X509_ATTRIBUTE_create
#define X509_ATTRIBUTE_create __NS_SYMBOL(X509_ATTRIBUTE_create)
#endif

#ifndef X509_CRL_delete_ext
#define X509_CRL_delete_ext __NS_SYMBOL(X509_CRL_delete_ext)
#endif

#ifndef X509_NAME_cmp
#define X509_NAME_cmp __NS_SYMBOL(X509_NAME_cmp)
#endif

#ifndef X509_REQ_print_ex
#define X509_REQ_print_ex __NS_SYMBOL(X509_REQ_print_ex)
#endif

#ifndef X509_set_issuer_name
#define X509_set_issuer_name __NS_SYMBOL(X509_set_issuer_name)
#endif

#ifndef X509at_get_attr_by_OBJ
#define X509at_get_attr_by_OBJ __NS_SYMBOL(X509at_get_attr_by_OBJ)
#endif

#ifndef _ossl_old_des_encrypt3
#define _ossl_old_des_encrypt3 __NS_SYMBOL(_ossl_old_des_encrypt3)
#endif

#ifndef cms_DigestedData_do_final
#define cms_DigestedData_do_final __NS_SYMBOL(cms_DigestedData_do_final)
#endif

#ifndef d2i_TS_MSG_IMPRINT_bio
#define d2i_TS_MSG_IMPRINT_bio __NS_SYMBOL(d2i_TS_MSG_IMPRINT_bio)
#endif

#ifndef get_rfc3526_prime_4096
#define get_rfc3526_prime_4096 __NS_SYMBOL(get_rfc3526_prime_4096)
#endif

#ifndef i2d_ASN1_ENUMERATED
#define i2d_ASN1_ENUMERATED __NS_SYMBOL(i2d_ASN1_ENUMERATED)
#endif

#ifndef i2d_DSAparams
#define i2d_DSAparams __NS_SYMBOL(i2d_DSAparams)
#endif

#ifndef i2d_EDIPARTYNAME
#define i2d_EDIPARTYNAME __NS_SYMBOL(i2d_EDIPARTYNAME)
#endif

#ifndef i2d_GOST_KEY_INFO
#define i2d_GOST_KEY_INFO __NS_SYMBOL(i2d_GOST_KEY_INFO)
#endif

#ifndef i2d_KRB5_PRINCNAME
#define i2d_KRB5_PRINCNAME __NS_SYMBOL(i2d_KRB5_PRINCNAME)
#endif

#ifndef i2d_NETSCAPE_PKEY
#define i2d_NETSCAPE_PKEY __NS_SYMBOL(i2d_NETSCAPE_PKEY)
#endif

#ifndef i2d_NETSCAPE_SPKI
#define i2d_NETSCAPE_SPKI __NS_SYMBOL(i2d_NETSCAPE_SPKI)
#endif

#ifndef i2d_OCSP_CERTID
#define i2d_OCSP_CERTID __NS_SYMBOL(i2d_OCSP_CERTID)
#endif

#ifndef i2d_PBKDF2PARAM
#define i2d_PBKDF2PARAM __NS_SYMBOL(i2d_PBKDF2PARAM)
#endif

#ifndef i2d_PKCS12_MAC_DATA
#define i2d_PKCS12_MAC_DATA __NS_SYMBOL(i2d_PKCS12_MAC_DATA)
#endif

#ifndef i2d_PROXY_CERT_INFO_EXTENSION
#define i2d_PROXY_CERT_INFO_EXTENSION __NS_SYMBOL(i2d_PROXY_CERT_INFO_EXTENSION)
#endif

#ifndef i2d_RSAPrivateKey
#define i2d_RSAPrivateKey __NS_SYMBOL(i2d_RSAPrivateKey)
#endif

#ifndef i2d_X509
#define i2d_X509 __NS_SYMBOL(i2d_X509)
#endif

#ifndef i2d_X509_ALGORS
#define i2d_X509_ALGORS __NS_SYMBOL(i2d_X509_ALGORS)
#endif

#ifndef i2d_X509_CRL_INFO
#define i2d_X509_CRL_INFO __NS_SYMBOL(i2d_X509_CRL_INFO)
#endif

#ifndef i2d_X509_EXTENSIONS
#define i2d_X509_EXTENSIONS __NS_SYMBOL(i2d_X509_EXTENSIONS)
#endif

#ifndef i2d_X509_REQ
#define i2d_X509_REQ __NS_SYMBOL(i2d_X509_REQ)
#endif

#ifndef ASN1_BIT_STRING_set_asc
#define ASN1_BIT_STRING_set_asc __NS_SYMBOL(ASN1_BIT_STRING_set_asc)
#endif

#ifndef ASN1_PCTX_set_nm_flags
#define ASN1_PCTX_set_nm_flags __NS_SYMBOL(ASN1_PCTX_set_nm_flags)
#endif

#ifndef ASN1_item_dup
#define ASN1_item_dup __NS_SYMBOL(ASN1_item_dup)
#endif

#ifndef BIO_asn1_get_suffix
#define BIO_asn1_get_suffix __NS_SYMBOL(BIO_asn1_get_suffix)
#endif

#ifndef BIO_s_connect
#define BIO_s_connect __NS_SYMBOL(BIO_s_connect)
#endif

#ifndef BIO_vprintf
#define BIO_vprintf __NS_SYMBOL(BIO_vprintf)
#endif

#ifndef BN_is_prime
#define BN_is_prime __NS_SYMBOL(BN_is_prime)
#endif

#ifndef BN_value_one
#define BN_value_one __NS_SYMBOL(BN_value_one)
#endif

#ifndef CMS_RecipientInfo_type
#define CMS_RecipientInfo_type __NS_SYMBOL(CMS_RecipientInfo_type)
#endif

#ifndef CMS_signed_add1_attr_by_txt
#define CMS_signed_add1_attr_by_txt __NS_SYMBOL(CMS_signed_add1_attr_by_txt)
#endif

#ifndef CRYPTO_get_new_dynlockid
#define CRYPTO_get_new_dynlockid __NS_SYMBOL(CRYPTO_get_new_dynlockid)
#endif

#ifndef EC_POINT_bn2point
#define EC_POINT_bn2point __NS_SYMBOL(EC_POINT_bn2point)
#endif

#ifndef EVP_camellia_256_ecb
#define EVP_camellia_256_ecb __NS_SYMBOL(EVP_camellia_256_ecb)
#endif

#ifndef EVP_des_ede3
#define EVP_des_ede3 __NS_SYMBOL(EVP_des_ede3)
#endif

#ifndef PEM_write_X509
#define PEM_write_X509 __NS_SYMBOL(PEM_write_X509)
#endif

#ifndef PEM_write_X509_AUX
#define PEM_write_X509_AUX __NS_SYMBOL(PEM_write_X509_AUX)
#endif

#ifndef PEM_write_X509_REQ
#define PEM_write_X509_REQ __NS_SYMBOL(PEM_write_X509_REQ)
#endif

#ifndef RSA_padding_check_X931
#define RSA_padding_check_X931 __NS_SYMBOL(RSA_padding_check_X931)
#endif

#ifndef SMIME_read_PKCS7
#define SMIME_read_PKCS7 __NS_SYMBOL(SMIME_read_PKCS7)
#endif

#ifndef X509_LOOKUP_file
#define X509_LOOKUP_file __NS_SYMBOL(X509_LOOKUP_file)
#endif

#ifndef X509_VERIFY_PARAM_free
#define X509_VERIFY_PARAM_free __NS_SYMBOL(X509_VERIFY_PARAM_free)
#endif

#ifndef X509v3_get_ext_by_OBJ
#define X509v3_get_ext_by_OBJ __NS_SYMBOL(X509v3_get_ext_by_OBJ)
#endif

#ifndef _ossl_old_des_decrypt3
#define _ossl_old_des_decrypt3 __NS_SYMBOL(_ossl_old_des_decrypt3)
#endif

#ifndef cms_Data_create
#define cms_Data_create __NS_SYMBOL(cms_Data_create)
#endif

#ifndef d2i_PKEY_USAGE_PERIOD
#define d2i_PKEY_USAGE_PERIOD __NS_SYMBOL(d2i_PKEY_USAGE_PERIOD)
#endif

#ifndef done_gost_hash_ctx
#define done_gost_hash_ctx __NS_SYMBOL(done_gost_hash_ctx)
#endif

#ifndef i2d_CMS_bio
#define i2d_CMS_bio __NS_SYMBOL(i2d_CMS_bio)
#endif

#ifndef pqueue_free
#define pqueue_free __NS_SYMBOL(pqueue_free)
#endif

#ifndef ASN1_ENUMERATED_new
#define ASN1_ENUMERATED_new __NS_SYMBOL(ASN1_ENUMERATED_new)
#endif

#ifndef ASN1_PCTX_get_cert_flags
#define ASN1_PCTX_get_cert_flags __NS_SYMBOL(ASN1_PCTX_get_cert_flags)
#endif

#ifndef ASN1_item_digest
#define ASN1_item_digest __NS_SYMBOL(ASN1_item_digest)
#endif

#ifndef BIO_new_connect
#define BIO_new_connect __NS_SYMBOL(BIO_new_connect)
#endif

#ifndef BN_RECP_CTX_set
#define BN_RECP_CTX_set __NS_SYMBOL(BN_RECP_CTX_set)
#endif

#ifndef BN_num_bits_word
#define BN_num_bits_word __NS_SYMBOL(BN_num_bits_word)
#endif

#ifndef CMAC_CTX_get0_cipher_ctx
#define CMAC_CTX_get0_cipher_ctx __NS_SYMBOL(CMAC_CTX_get0_cipher_ctx)
#endif

#ifndef CMS_EnvelopedData_create
#define CMS_EnvelopedData_create __NS_SYMBOL(CMS_EnvelopedData_create)
#endif

#ifndef CRYPTO_set_mem_ex_functions
#define CRYPTO_set_mem_ex_functions __NS_SYMBOL(CRYPTO_set_mem_ex_functions)
#endif

#ifndef DES_set_key
#define DES_set_key __NS_SYMBOL(DES_set_key)
#endif

#ifndef DSA_print
#define DSA_print __NS_SYMBOL(DSA_print)
#endif

#ifndef ECDSA_sign
#define ECDSA_sign __NS_SYMBOL(ECDSA_sign)
#endif

#ifndef EDIPARTYNAME_new
#define EDIPARTYNAME_new __NS_SYMBOL(EDIPARTYNAME_new)
#endif

#ifndef ENGINE_get_next
#define ENGINE_get_next __NS_SYMBOL(ENGINE_get_next)
#endif

#ifndef EVP_CipherInit_ex
#define EVP_CipherInit_ex __NS_SYMBOL(EVP_CipherInit_ex)
#endif

#ifndef EVP_aes_128_cfb1
#define EVP_aes_128_cfb1 __NS_SYMBOL(EVP_aes_128_cfb1)
#endif

#ifndef EVP_camellia_128_cfb1
#define EVP_camellia_128_cfb1 __NS_SYMBOL(EVP_camellia_128_cfb1)
#endif

#ifndef GOST_KEY_INFO_new
#define GOST_KEY_INFO_new __NS_SYMBOL(GOST_KEY_INFO_new)
#endif

#ifndef KRB5_PRINCNAME_new
#define KRB5_PRINCNAME_new __NS_SYMBOL(KRB5_PRINCNAME_new)
#endif

#ifndef NETSCAPE_PKEY_new
#define NETSCAPE_PKEY_new __NS_SYMBOL(NETSCAPE_PKEY_new)
#endif

#ifndef NETSCAPE_SPKI_new
#define NETSCAPE_SPKI_new __NS_SYMBOL(NETSCAPE_SPKI_new)
#endif

#ifndef OCSP_CERTID_new
#define OCSP_CERTID_new __NS_SYMBOL(OCSP_CERTID_new)
#endif

#ifndef OCSP_REQUEST_get1_ext_d2i
#define OCSP_REQUEST_get1_ext_d2i __NS_SYMBOL(OCSP_REQUEST_get1_ext_d2i)
#endif

#ifndef OCSP_REQUEST_print
#define OCSP_REQUEST_print __NS_SYMBOL(OCSP_REQUEST_print)
#endif

#ifndef OCSP_REQ_CTX_add1_header
#define OCSP_REQ_CTX_add1_header __NS_SYMBOL(OCSP_REQ_CTX_add1_header)
#endif

#ifndef OCSP_response_create
#define OCSP_response_create __NS_SYMBOL(OCSP_response_create)
#endif

#ifndef OPENSSL_uni2asc
#define OPENSSL_uni2asc __NS_SYMBOL(OPENSSL_uni2asc)
#endif

#ifndef PBKDF2PARAM_new
#define PBKDF2PARAM_new __NS_SYMBOL(PBKDF2PARAM_new)
#endif

#ifndef PKCS12_MAC_DATA_new
#define PKCS12_MAC_DATA_new __NS_SYMBOL(PKCS12_MAC_DATA_new)
#endif

#ifndef PROXY_CERT_INFO_EXTENSION_new
#define PROXY_CERT_INFO_EXTENSION_new __NS_SYMBOL(PROXY_CERT_INFO_EXTENSION_new)
#endif

#ifndef RSA_blinding_on
#define RSA_blinding_on __NS_SYMBOL(RSA_blinding_on)
#endif

#ifndef RSA_print
#define RSA_print __NS_SYMBOL(RSA_print)
#endif

#ifndef SHA256_Init
#define SHA256_Init __NS_SYMBOL(SHA256_Init)
#endif

#ifndef SMIME_crlf_copy
#define SMIME_crlf_copy __NS_SYMBOL(SMIME_crlf_copy)
#endif

#ifndef SSLeay
#define SSLeay __NS_SYMBOL(SSLeay)
#endif

#ifndef TS_RESP_get_token
#define TS_RESP_get_token __NS_SYMBOL(TS_RESP_get_token)
#endif

#ifndef X509_ALGOR_dup
#define X509_ALGOR_dup __NS_SYMBOL(X509_ALGOR_dup)
#endif

#ifndef X509_CRL_INFO_new
#define X509_CRL_INFO_new __NS_SYMBOL(X509_CRL_INFO_new)
#endif

#ifndef X509_CRL_get_ext_d2i
#define X509_CRL_get_ext_d2i __NS_SYMBOL(X509_CRL_get_ext_d2i)
#endif

#ifndef X509_CRL_set_nextUpdate
#define X509_CRL_set_nextUpdate __NS_SYMBOL(X509_CRL_set_nextUpdate)
#endif

#ifndef X509_EXTENSION_dup
#define X509_EXTENSION_dup __NS_SYMBOL(X509_EXTENSION_dup)
#endif

#ifndef X509_LOOKUP_init
#define X509_LOOKUP_init __NS_SYMBOL(X509_LOOKUP_init)
#endif

#ifndef X509_REQ_new
#define X509_REQ_new __NS_SYMBOL(X509_REQ_new)
#endif

#ifndef X509_TRUST_get_by_id
#define X509_TRUST_get_by_id __NS_SYMBOL(X509_TRUST_get_by_id)
#endif

#ifndef X509_load_cert_file
#define X509_load_cert_file __NS_SYMBOL(X509_load_cert_file)
#endif

#ifndef X509_new
#define X509_new __NS_SYMBOL(X509_new)
#endif

#ifndef X509_policy_level_get0_node
#define X509_policy_level_get0_node __NS_SYMBOL(X509_policy_level_get0_node)
#endif

#ifndef X509_set_subject_name
#define X509_set_subject_name __NS_SYMBOL(X509_set_subject_name)
#endif

#ifndef _ossl_old_des_ede3_cbc_encrypt
#define _ossl_old_des_ede3_cbc_encrypt __NS_SYMBOL(_ossl_old_des_ede3_cbc_encrypt)
#endif

#ifndef d2i_DSAPublicKey
#define d2i_DSAPublicKey __NS_SYMBOL(d2i_DSAPublicKey)
#endif

#ifndef d2i_PKCS7_SIGNED
#define d2i_PKCS7_SIGNED __NS_SYMBOL(d2i_PKCS7_SIGNED)
#endif

#ifndef d2i_RSAPublicKey
#define d2i_RSAPublicKey __NS_SYMBOL(d2i_RSAPublicKey)
#endif

#ifndef dsa_builtin_paramgen
#define dsa_builtin_paramgen __NS_SYMBOL(dsa_builtin_paramgen)
#endif

#ifndef get_rfc3526_prime_6144
#define get_rfc3526_prime_6144 __NS_SYMBOL(get_rfc3526_prime_6144)
#endif

#ifndef start_hash
#define start_hash __NS_SYMBOL(start_hash)
#endif

#ifndef ASN1_PCTX_set_cert_flags
#define ASN1_PCTX_set_cert_flags __NS_SYMBOL(ASN1_PCTX_set_cert_flags)
#endif

#ifndef ASN1_TYPE_set_int_octetstring
#define ASN1_TYPE_set_int_octetstring __NS_SYMBOL(ASN1_TYPE_set_int_octetstring)
#endif

#ifndef ASN1_UNIVERSALSTRING_to_string
#define ASN1_UNIVERSALSTRING_to_string __NS_SYMBOL(ASN1_UNIVERSALSTRING_to_string)
#endif

#ifndef ASN1_d2i_bio
#define ASN1_d2i_bio __NS_SYMBOL(ASN1_d2i_bio)
#endif

#ifndef ASN1_item_i2d
#define ASN1_item_i2d __NS_SYMBOL(ASN1_item_i2d)
#endif

#ifndef BN_rshift1
#define BN_rshift1 __NS_SYMBOL(BN_rshift1)
#endif

#ifndef CMAC_CTX_free
#define CMAC_CTX_free __NS_SYMBOL(CMAC_CTX_free)
#endif

#ifndef CMS_signed_get0_data_by_OBJ
#define CMS_signed_get0_data_by_OBJ __NS_SYMBOL(CMS_signed_get0_data_by_OBJ)
#endif

#ifndef COMP_compress_block
#define COMP_compress_block __NS_SYMBOL(COMP_compress_block)
#endif

#ifndef CRYPTO_ccm128_aad
#define CRYPTO_ccm128_aad __NS_SYMBOL(CRYPTO_ccm128_aad)
#endif

#ifndef CRYPTO_ex_data_new_class
#define CRYPTO_ex_data_new_class __NS_SYMBOL(CRYPTO_ex_data_new_class)
#endif

#ifndef ERR_load_ERR_strings
#define ERR_load_ERR_strings __NS_SYMBOL(ERR_load_ERR_strings)
#endif

#ifndef EVP_DigestInit_ex
#define EVP_DigestInit_ex __NS_SYMBOL(EVP_DigestInit_ex)
#endif

#ifndef EVP_camellia_192_cfb1
#define EVP_camellia_192_cfb1 __NS_SYMBOL(EVP_camellia_192_cfb1)
#endif

#ifndef OCSP_request_add1_cert
#define OCSP_request_add1_cert __NS_SYMBOL(OCSP_request_add1_cert)
#endif

#ifndef PEM_read_bio_CMS
#define PEM_read_bio_CMS __NS_SYMBOL(PEM_read_bio_CMS)
#endif

#ifndef PKCS12_add_CSPName_asc
#define PKCS12_add_CSPName_asc __NS_SYMBOL(PKCS12_add_CSPName_asc)
#endif

#ifndef TS_RESP_get_tst_info
#define TS_RESP_get_tst_info __NS_SYMBOL(TS_RESP_get_tst_info)
#endif

#ifndef X509_sign_ctx
#define X509_sign_ctx __NS_SYMBOL(X509_sign_ctx)
#endif

#ifndef _ossl_old_des_ede3_cfb64_encrypt
#define _ossl_old_des_ede3_cfb64_encrypt __NS_SYMBOL(_ossl_old_des_ede3_cfb64_encrypt)
#endif

#ifndef ec_GFp_simple_group_copy
#define ec_GFp_simple_group_copy __NS_SYMBOL(ec_GFp_simple_group_copy)
#endif

#ifndef i2d_PKEY_USAGE_PERIOD
#define i2d_PKEY_USAGE_PERIOD __NS_SYMBOL(i2d_PKEY_USAGE_PERIOD)
#endif

#ifndef i2d_TS_MSG_IMPRINT_bio
#define i2d_TS_MSG_IMPRINT_bio __NS_SYMBOL(i2d_TS_MSG_IMPRINT_bio)
#endif

#ifndef pqueue_insert
#define pqueue_insert __NS_SYMBOL(pqueue_insert)
#endif

#ifndef ASN1_ENUMERATED_free
#define ASN1_ENUMERATED_free __NS_SYMBOL(ASN1_ENUMERATED_free)
#endif

#ifndef ASN1_PCTX_get_oid_flags
#define ASN1_PCTX_get_oid_flags __NS_SYMBOL(ASN1_PCTX_get_oid_flags)
#endif

#ifndef BN_is_prime_fasttest
#define BN_is_prime_fasttest __NS_SYMBOL(BN_is_prime_fasttest)
#endif

#ifndef CMS_unsigned_get_attr_count
#define CMS_unsigned_get_attr_count __NS_SYMBOL(CMS_unsigned_get_attr_count)
#endif

#ifndef EC_GROUP_new_curve_GF2m
#define EC_GROUP_new_curve_GF2m __NS_SYMBOL(EC_GROUP_new_curve_GF2m)
#endif

#ifndef EDIPARTYNAME_free
#define EDIPARTYNAME_free __NS_SYMBOL(EDIPARTYNAME_free)
#endif

#ifndef EVP_camellia_256_cfb1
#define EVP_camellia_256_cfb1 __NS_SYMBOL(EVP_camellia_256_cfb1)
#endif

#ifndef GOST_KEY_INFO_free
#define GOST_KEY_INFO_free __NS_SYMBOL(GOST_KEY_INFO_free)
#endif

#ifndef KRB5_PRINCNAME_free
#define KRB5_PRINCNAME_free __NS_SYMBOL(KRB5_PRINCNAME_free)
#endif

#ifndef NETSCAPE_PKEY_free
#define NETSCAPE_PKEY_free __NS_SYMBOL(NETSCAPE_PKEY_free)
#endif

#ifndef NETSCAPE_SPKI_free
#define NETSCAPE_SPKI_free __NS_SYMBOL(NETSCAPE_SPKI_free)
#endif

#ifndef OCSP_CERTID_free
#define OCSP_CERTID_free __NS_SYMBOL(OCSP_CERTID_free)
#endif

#ifndef OCSP_REQUEST_add1_ext_i2d
#define OCSP_REQUEST_add1_ext_i2d __NS_SYMBOL(OCSP_REQUEST_add1_ext_i2d)
#endif

#ifndef PBKDF2PARAM_free
#define PBKDF2PARAM_free __NS_SYMBOL(PBKDF2PARAM_free)
#endif

#ifndef PKCS12_MAC_DATA_free
#define PKCS12_MAC_DATA_free __NS_SYMBOL(PKCS12_MAC_DATA_free)
#endif

#ifndef PKCS12_MAKE_KEYBAG
#define PKCS12_MAKE_KEYBAG __NS_SYMBOL(PKCS12_MAKE_KEYBAG)
#endif

#ifndef PKCS7_simple_smimecap
#define PKCS7_simple_smimecap __NS_SYMBOL(PKCS7_simple_smimecap)
#endif

#ifndef PROXY_CERT_INFO_EXTENSION_free
#define PROXY_CERT_INFO_EXTENSION_free __NS_SYMBOL(PROXY_CERT_INFO_EXTENSION_free)
#endif

#ifndef RSA_padding_check_SSLv23
#define RSA_padding_check_SSLv23 __NS_SYMBOL(RSA_padding_check_SSLv23)
#endif

#ifndef TS_TST_INFO_set_version
#define TS_TST_INFO_set_version __NS_SYMBOL(TS_TST_INFO_set_version)
#endif

#ifndef X509_ALGOR_set0
#define X509_ALGOR_set0 __NS_SYMBOL(X509_ALGOR_set0)
#endif

#ifndef X509_CRL_INFO_free
#define X509_CRL_INFO_free __NS_SYMBOL(X509_CRL_INFO_free)
#endif

#ifndef X509_CRL_add1_ext_i2d
#define X509_CRL_add1_ext_i2d __NS_SYMBOL(X509_CRL_add1_ext_i2d)
#endif

#ifndef X509_REQ_free
#define X509_REQ_free __NS_SYMBOL(X509_REQ_free)
#endif

#ifndef X509_free
#define X509_free __NS_SYMBOL(X509_free)
#endif

#ifndef X509_policy_check
#define X509_policy_check __NS_SYMBOL(X509_policy_check)
#endif

#ifndef X509_set_notBefore
#define X509_set_notBefore __NS_SYMBOL(X509_set_notBefore)
#endif

#ifndef _ossl_old_des_ede3_ofb64_encrypt
#define _ossl_old_des_ede3_ofb64_encrypt __NS_SYMBOL(_ossl_old_des_ede3_ofb64_encrypt)
#endif

#ifndef asn1_enc_free
#define asn1_enc_free __NS_SYMBOL(asn1_enc_free)
#endif

#ifndef b2i_PublicKey
#define b2i_PublicKey __NS_SYMBOL(b2i_PublicKey)
#endif

#ifndef cms_set1_SignerIdentifier
#define cms_set1_SignerIdentifier __NS_SYMBOL(cms_set1_SignerIdentifier)
#endif

#ifndef ec_GFp_mont_group_copy
#define ec_GFp_mont_group_copy __NS_SYMBOL(ec_GFp_mont_group_copy)
#endif

#ifndef get_gost_engine_param
#define get_gost_engine_param __NS_SYMBOL(get_gost_engine_param)
#endif

#ifndef get_rfc3526_prime_8192
#define get_rfc3526_prime_8192 __NS_SYMBOL(get_rfc3526_prime_8192)
#endif

#ifndef i2d_DSAPublicKey
#define i2d_DSAPublicKey __NS_SYMBOL(i2d_DSAPublicKey)
#endif

#ifndef i2d_PKCS7_SIGNED
#define i2d_PKCS7_SIGNED __NS_SYMBOL(i2d_PKCS7_SIGNED)
#endif

#ifndef i2d_RSAPublicKey
#define i2d_RSAPublicKey __NS_SYMBOL(i2d_RSAPublicKey)
#endif

#ifndef register_ameth_gost
#define register_ameth_gost __NS_SYMBOL(register_ameth_gost)
#endif

#ifndef ASN1_PCTX_set_oid_flags
#define ASN1_PCTX_set_oid_flags __NS_SYMBOL(ASN1_PCTX_set_oid_flags)
#endif

#ifndef ASN1_TIME_adj
#define ASN1_TIME_adj __NS_SYMBOL(ASN1_TIME_adj)
#endif

#ifndef CMS_set_detached
#define CMS_set_detached __NS_SYMBOL(CMS_set_detached)
#endif

#ifndef CMS_unsigned_get_attr_by_NID
#define CMS_unsigned_get_attr_by_NID __NS_SYMBOL(CMS_unsigned_get_attr_by_NID)
#endif

#ifndef EC_GROUP_get_pentanomial_basis
#define EC_GROUP_get_pentanomial_basis __NS_SYMBOL(EC_GROUP_get_pentanomial_basis)
#endif

#ifndef ENGINE_get_STORE
#define ENGINE_get_STORE __NS_SYMBOL(ENGINE_get_STORE)
#endif

#ifndef ENGINE_set_default_DH
#define ENGINE_set_default_DH __NS_SYMBOL(ENGINE_set_default_DH)
#endif

#ifndef ENGINE_set_default_DSA
#define ENGINE_set_default_DSA __NS_SYMBOL(ENGINE_set_default_DSA)
#endif

#ifndef ENGINE_set_default_ECDH
#define ENGINE_set_default_ECDH __NS_SYMBOL(ENGINE_set_default_ECDH)
#endif

#ifndef ENGINE_set_default_ECDSA
#define ENGINE_set_default_ECDSA __NS_SYMBOL(ENGINE_set_default_ECDSA)
#endif

#ifndef ENGINE_set_default_RAND
#define ENGINE_set_default_RAND __NS_SYMBOL(ENGINE_set_default_RAND)
#endif

#ifndef ENGINE_set_default_RSA
#define ENGINE_set_default_RSA __NS_SYMBOL(ENGINE_set_default_RSA)
#endif

#ifndef EVP_aes_128_cfb8
#define EVP_aes_128_cfb8 __NS_SYMBOL(EVP_aes_128_cfb8)
#endif

#ifndef EVP_camellia_128_cfb8
#define EVP_camellia_128_cfb8 __NS_SYMBOL(EVP_camellia_128_cfb8)
#endif

#ifndef OPENSSL_DIR_end
#define OPENSSL_DIR_end __NS_SYMBOL(OPENSSL_DIR_end)
#endif

#ifndef PEM_proc_type
#define PEM_proc_type __NS_SYMBOL(PEM_proc_type)
#endif

#ifndef PKCS12_key_gen_uni
#define PKCS12_key_gen_uni __NS_SYMBOL(PKCS12_key_gen_uni)
#endif

#ifndef PKEY_USAGE_PERIOD_new
#define PKEY_USAGE_PERIOD_new __NS_SYMBOL(PKEY_USAGE_PERIOD_new)
#endif

#ifndef TS_TST_INFO_get_version
#define TS_TST_INFO_get_version __NS_SYMBOL(TS_TST_INFO_get_version)
#endif

#ifndef WHIRLPOOL_BitUpdate
#define WHIRLPOOL_BitUpdate __NS_SYMBOL(WHIRLPOOL_BitUpdate)
#endif

#ifndef X509_LOOKUP_shutdown
#define X509_LOOKUP_shutdown __NS_SYMBOL(X509_LOOKUP_shutdown)
#endif

#ifndef X509_policy_node_get0_policy
#define X509_policy_node_get0_policy __NS_SYMBOL(X509_policy_node_get0_policy)
#endif

#ifndef _ossl_old_des_enc_read
#define _ossl_old_des_enc_read __NS_SYMBOL(_ossl_old_des_enc_read)
#endif

#ifndef d2i_TS_MSG_IMPRINT_fp
#define d2i_TS_MSG_IMPRINT_fp __NS_SYMBOL(d2i_TS_MSG_IMPRINT_fp)
#endif

#ifndef ec_GF2m_simple_group_copy
#define ec_GF2m_simple_group_copy __NS_SYMBOL(ec_GF2m_simple_group_copy)
#endif

#ifndef ASN1_PCTX_get_str_flags
#define ASN1_PCTX_get_str_flags __NS_SYMBOL(ASN1_PCTX_get_str_flags)
#endif

#ifndef ASN1_STRING_set_by_NID
#define ASN1_STRING_set_by_NID __NS_SYMBOL(ASN1_STRING_set_by_NID)
#endif

#ifndef BIO_set
#define BIO_set __NS_SYMBOL(BIO_set)
#endif

#ifndef BN_bn2dec
#define BN_bn2dec __NS_SYMBOL(BN_bn2dec)
#endif

#ifndef BN_mod_add_quick
#define BN_mod_add_quick __NS_SYMBOL(BN_mod_add_quick)
#endif

#ifndef CMS_unsigned_get_attr_by_OBJ
#define CMS_unsigned_get_attr_by_OBJ __NS_SYMBOL(CMS_unsigned_get_attr_by_OBJ)
#endif

#ifndef DSAparams_dup
#define DSAparams_dup __NS_SYMBOL(DSAparams_dup)
#endif

#ifndef EC_POINT_point2oct
#define EC_POINT_point2oct __NS_SYMBOL(EC_POINT_point2oct)
#endif

#ifndef ENGINE_set_STORE
#define ENGINE_set_STORE __NS_SYMBOL(ENGINE_set_STORE)
#endif

#ifndef ENGINE_set_default_string
#define ENGINE_set_default_string __NS_SYMBOL(ENGINE_set_default_string)
#endif

#ifndef EVP_CIPHER_asn1_to_param
#define EVP_CIPHER_asn1_to_param __NS_SYMBOL(EVP_CIPHER_asn1_to_param)
#endif

#ifndef EVP_PKEY_meth_get0_info
#define EVP_PKEY_meth_get0_info __NS_SYMBOL(EVP_PKEY_meth_get0_info)
#endif

#ifndef EVP_camellia_192_cfb8
#define EVP_camellia_192_cfb8 __NS_SYMBOL(EVP_camellia_192_cfb8)
#endif

#ifndef OCSP_REQUEST_add_ext
#define OCSP_REQUEST_add_ext __NS_SYMBOL(OCSP_REQUEST_add_ext)
#endif

#ifndef PEM_read_CMS
#define PEM_read_CMS __NS_SYMBOL(PEM_read_CMS)
#endif

#ifndef PEM_read_bio_X509_CERT_PAIR
#define PEM_read_bio_X509_CERT_PAIR __NS_SYMBOL(PEM_read_bio_X509_CERT_PAIR)
#endif

#ifndef PEM_write_bio_X509_REQ_NEW
#define PEM_write_bio_X509_REQ_NEW __NS_SYMBOL(PEM_write_bio_X509_REQ_NEW)
#endif

#ifndef PKCS12_get_attr_gen
#define PKCS12_get_attr_gen __NS_SYMBOL(PKCS12_get_attr_gen)
#endif

#ifndef PKCS5_pbe2_set_iv
#define PKCS5_pbe2_set_iv __NS_SYMBOL(PKCS5_pbe2_set_iv)
#endif

#ifndef PKCS7_SIGNED_new
#define PKCS7_SIGNED_new __NS_SYMBOL(PKCS7_SIGNED_new)
#endif

#ifndef RSAPublicKey_dup
#define RSAPublicKey_dup __NS_SYMBOL(RSAPublicKey_dup)
#endif

#ifndef TS_TST_INFO_set_policy_id
#define TS_TST_INFO_set_policy_id __NS_SYMBOL(TS_TST_INFO_set_policy_id)
#endif

#ifndef X509_CRL_add_ext
#define X509_CRL_add_ext __NS_SYMBOL(X509_CRL_add_ext)
#endif

#ifndef X509_REQ_dup
#define X509_REQ_dup __NS_SYMBOL(X509_REQ_dup)
#endif

#ifndef X509_REQ_get_pubkey
#define X509_REQ_get_pubkey __NS_SYMBOL(X509_REQ_get_pubkey)
#endif

#ifndef X509_REQ_sign
#define X509_REQ_sign __NS_SYMBOL(X509_REQ_sign)
#endif

#ifndef X509_TRUST_get0
#define X509_TRUST_get0 __NS_SYMBOL(X509_TRUST_get0)
#endif

#ifndef X509_dup
#define X509_dup __NS_SYMBOL(X509_dup)
#endif

#ifndef _ossl_old_des_enc_write
#define _ossl_old_des_enc_write __NS_SYMBOL(_ossl_old_des_enc_write)
#endif

#ifndef b2i_PrivateKey_bio
#define b2i_PrivateKey_bio __NS_SYMBOL(b2i_PrivateKey_bio)
#endif

#ifndef d2i_ASN1_BIT_STRING
#define d2i_ASN1_BIT_STRING __NS_SYMBOL(d2i_ASN1_BIT_STRING)
#endif

#ifndef d2i_GENERAL_NAME
#define d2i_GENERAL_NAME __NS_SYMBOL(d2i_GENERAL_NAME)
#endif

#ifndef d2i_GOST_KEY_AGREEMENT_INFO
#define d2i_GOST_KEY_AGREEMENT_INFO __NS_SYMBOL(d2i_GOST_KEY_AGREEMENT_INFO)
#endif

#ifndef d2i_KRB5_TKTBODY
#define d2i_KRB5_TKTBODY __NS_SYMBOL(d2i_KRB5_TKTBODY)
#endif

#ifndef d2i_OCSP_ONEREQ
#define d2i_OCSP_ONEREQ __NS_SYMBOL(d2i_OCSP_ONEREQ)
#endif

#ifndef d2i_PKCS12_BAGS
#define d2i_PKCS12_BAGS __NS_SYMBOL(d2i_PKCS12_BAGS)
#endif

#ifndef d2i_X509_CRL
#define d2i_X509_CRL __NS_SYMBOL(d2i_X509_CRL)
#endif

#ifndef i2d_Netscape_RSA
#define i2d_Netscape_RSA __NS_SYMBOL(i2d_Netscape_RSA)
#endif

#ifndef ASN1_PCTX_set_str_flags
#define ASN1_PCTX_set_str_flags __NS_SYMBOL(ASN1_PCTX_set_str_flags)
#endif

#ifndef BIO_s_file
#define BIO_s_file __NS_SYMBOL(BIO_s_file)
#endif

#ifndef BN_mod_mul_reciprocal
#define BN_mod_mul_reciprocal __NS_SYMBOL(BN_mod_mul_reciprocal)
#endif

#ifndef CMS_ReceiptRequest_create0
#define CMS_ReceiptRequest_create0 __NS_SYMBOL(CMS_ReceiptRequest_create0)
#endif

#ifndef CMS_unsigned_get_attr
#define CMS_unsigned_get_attr __NS_SYMBOL(CMS_unsigned_get_attr)
#endif

#ifndef CONF_load_bio
#define CONF_load_bio __NS_SYMBOL(CONF_load_bio)
#endif

#ifndef EC_GROUP_free
#define EC_GROUP_free __NS_SYMBOL(EC_GROUP_free)
#endif

#ifndef ENGINE_init
#define ENGINE_init __NS_SYMBOL(ENGINE_init)
#endif

#ifndef EVP_camellia_256_cfb8
#define EVP_camellia_256_cfb8 __NS_SYMBOL(EVP_camellia_256_cfb8)
#endif

#ifndef EVP_get_cipherbyname
#define EVP_get_cipherbyname __NS_SYMBOL(EVP_get_cipherbyname)
#endif

#ifndef NETSCAPE_SPKI_b64_encode
#define NETSCAPE_SPKI_b64_encode __NS_SYMBOL(NETSCAPE_SPKI_b64_encode)
#endif

#ifndef OBJ_NAME_new_index
#define OBJ_NAME_new_index __NS_SYMBOL(OBJ_NAME_new_index)
#endif

#ifndef OBJ_new_nid
#define OBJ_new_nid __NS_SYMBOL(OBJ_new_nid)
#endif

#ifndef PKEY_USAGE_PERIOD_free
#define PKEY_USAGE_PERIOD_free __NS_SYMBOL(PKEY_USAGE_PERIOD_free)
#endif

#ifndef TS_MSG_IMPRINT_get_algo
#define TS_MSG_IMPRINT_get_algo __NS_SYMBOL(TS_MSG_IMPRINT_get_algo)
#endif

#ifndef X509_CRL_sort
#define X509_CRL_sort __NS_SYMBOL(X509_CRL_sort)
#endif

#ifndef X509_VERIFY_PARAM_inherit
#define X509_VERIFY_PARAM_inherit __NS_SYMBOL(X509_VERIFY_PARAM_inherit)
#endif

#ifndef X509_policy_node_get0_qualifiers
#define X509_policy_node_get0_qualifiers __NS_SYMBOL(X509_policy_node_get0_qualifiers)
#endif

#ifndef _CONF_get_string
#define _CONF_get_string __NS_SYMBOL(_CONF_get_string)
#endif

#ifndef _ossl_old_des_fcrypt
#define _ossl_old_des_fcrypt __NS_SYMBOL(_ossl_old_des_fcrypt)
#endif

#ifndef a2i_ASN1_ENUMERATED
#define a2i_ASN1_ENUMERATED __NS_SYMBOL(a2i_ASN1_ENUMERATED)
#endif

#ifndef a2i_ASN1_STRING
#define a2i_ASN1_STRING __NS_SYMBOL(a2i_ASN1_STRING)
#endif

#ifndef gcm_ghash_4bit
#define gcm_ghash_4bit __NS_SYMBOL(gcm_ghash_4bit)
#endif

#ifndef i2d_RSA_NET
#define i2d_RSA_NET __NS_SYMBOL(i2d_RSA_NET)
#endif

#ifndef ASN1_ENUMERATED_get
#define ASN1_ENUMERATED_get __NS_SYMBOL(ASN1_ENUMERATED_get)
#endif

#ifndef ASN1_item_print
#define ASN1_item_print __NS_SYMBOL(ASN1_item_print)
#endif

#ifndef BIO_ctrl_get_write_guarantee
#define BIO_ctrl_get_write_guarantee __NS_SYMBOL(BIO_ctrl_get_write_guarantee)
#endif

#ifndef BIO_new_fp
#define BIO_new_fp __NS_SYMBOL(BIO_new_fp)
#endif

#ifndef CMS_unsigned_delete_attr
#define CMS_unsigned_delete_attr __NS_SYMBOL(CMS_unsigned_delete_attr)
#endif

#ifndef DSA_sign
#define DSA_sign __NS_SYMBOL(DSA_sign)
#endif

#ifndef DSAparams_print_fp
#define DSAparams_print_fp __NS_SYMBOL(DSAparams_print_fp)
#endif

#ifndef ENGINE_set_default_ciphers
#define ENGINE_set_default_ciphers __NS_SYMBOL(ENGINE_set_default_ciphers)
#endif

#ifndef ENGINE_set_default_digests
#define ENGINE_set_default_digests __NS_SYMBOL(ENGINE_set_default_digests)
#endif

#ifndef ENGINE_set_default_pkey_asn1_meths
#define ENGINE_set_default_pkey_asn1_meths __NS_SYMBOL(ENGINE_set_default_pkey_asn1_meths)
#endif

#ifndef ENGINE_set_default_pkey_meths
#define ENGINE_set_default_pkey_meths __NS_SYMBOL(ENGINE_set_default_pkey_meths)
#endif

#ifndef ERR_print_errors_fp
#define ERR_print_errors_fp __NS_SYMBOL(ERR_print_errors_fp)
#endif

#ifndef EVP_PKEY_meth_copy
#define EVP_PKEY_meth_copy __NS_SYMBOL(EVP_PKEY_meth_copy)
#endif

#ifndef EVP_aes_128_ctr
#define EVP_aes_128_ctr __NS_SYMBOL(EVP_aes_128_ctr)
#endif

#ifndef EVP_get_digestbyname
#define EVP_get_digestbyname __NS_SYMBOL(EVP_get_digestbyname)
#endif

#ifndef OCSP_ONEREQ_get_ext_count
#define OCSP_ONEREQ_get_ext_count __NS_SYMBOL(OCSP_ONEREQ_get_ext_count)
#endif

#ifndef PKCS7_SIGNED_free
#define PKCS7_SIGNED_free __NS_SYMBOL(PKCS7_SIGNED_free)
#endif

#ifndef RAND_cleanup
#define RAND_cleanup __NS_SYMBOL(RAND_cleanup)
#endif

#ifndef RSAPrivateKey_dup
#define RSAPrivateKey_dup __NS_SYMBOL(RSAPrivateKey_dup)
#endif

#ifndef RSA_verify_ASN1_OCTET_STRING
#define RSA_verify_ASN1_OCTET_STRING __NS_SYMBOL(RSA_verify_ASN1_OCTET_STRING)
#endif

#ifndef TS_MSG_IMPRINT_set_msg
#define TS_MSG_IMPRINT_set_msg __NS_SYMBOL(TS_MSG_IMPRINT_set_msg)
#endif

#ifndef TS_VERIFY_CTX_free
#define TS_VERIFY_CTX_free __NS_SYMBOL(TS_VERIFY_CTX_free)
#endif

#ifndef TS_ext_print_bio
#define TS_ext_print_bio __NS_SYMBOL(TS_ext_print_bio)
#endif

#ifndef X509V3_EXT_get
#define X509V3_EXT_get __NS_SYMBOL(X509V3_EXT_get)
#endif

#ifndef X509_LOOKUP_ctrl
#define X509_LOOKUP_ctrl __NS_SYMBOL(X509_LOOKUP_ctrl)
#endif

#ifndef X509_REQ_check_private_key
#define X509_REQ_check_private_key __NS_SYMBOL(X509_REQ_check_private_key)
#endif

#ifndef X509_get_ex_new_index
#define X509_get_ex_new_index __NS_SYMBOL(X509_get_ex_new_index)
#endif

#ifndef X509_get_ext_count
#define X509_get_ext_count __NS_SYMBOL(X509_get_ext_count)
#endif

#ifndef X509_issuer_and_serial_hash
#define X509_issuer_and_serial_hash __NS_SYMBOL(X509_issuer_and_serial_hash)
#endif

#ifndef X509at_get_attr
#define X509at_get_attr __NS_SYMBOL(X509at_get_attr)
#endif

#ifndef _ossl_old_des_crypt
#define _ossl_old_des_crypt __NS_SYMBOL(_ossl_old_des_crypt)
#endif

#ifndef engine_free_util
#define engine_free_util __NS_SYMBOL(engine_free_util)
#endif

#ifndef i2d_ASN1_BIT_STRING
#define i2d_ASN1_BIT_STRING __NS_SYMBOL(i2d_ASN1_BIT_STRING)
#endif

#ifndef i2d_GENERAL_NAME
#define i2d_GENERAL_NAME __NS_SYMBOL(i2d_GENERAL_NAME)
#endif

#ifndef i2d_GOST_KEY_AGREEMENT_INFO
#define i2d_GOST_KEY_AGREEMENT_INFO __NS_SYMBOL(i2d_GOST_KEY_AGREEMENT_INFO)
#endif

#ifndef i2d_KRB5_TKTBODY
#define i2d_KRB5_TKTBODY __NS_SYMBOL(i2d_KRB5_TKTBODY)
#endif

#ifndef i2d_OCSP_ONEREQ
#define i2d_OCSP_ONEREQ __NS_SYMBOL(i2d_OCSP_ONEREQ)
#endif

#ifndef i2d_PKCS12_BAGS
#define i2d_PKCS12_BAGS __NS_SYMBOL(i2d_PKCS12_BAGS)
#endif

#ifndef i2d_TS_MSG_IMPRINT_fp
#define i2d_TS_MSG_IMPRINT_fp __NS_SYMBOL(i2d_TS_MSG_IMPRINT_fp)
#endif

#ifndef i2d_X509_CRL
#define i2d_X509_CRL __NS_SYMBOL(i2d_X509_CRL)
#endif

#ifndef level_add_node
#define level_add_node __NS_SYMBOL(level_add_node)
#endif

#ifndef BUF_strlcpy
#define BUF_strlcpy __NS_SYMBOL(BUF_strlcpy)
#endif

#ifndef CMS_unsigned_add1_attr
#define CMS_unsigned_add1_attr __NS_SYMBOL(CMS_unsigned_add1_attr)
#endif

#ifndef CRYPTO_nistcts128_encrypt_block
#define CRYPTO_nistcts128_encrypt_block __NS_SYMBOL(CRYPTO_nistcts128_encrypt_block)
#endif

#ifndef CRYPTO_set_locked_mem_functions
#define CRYPTO_set_locked_mem_functions __NS_SYMBOL(CRYPTO_set_locked_mem_functions)
#endif

#ifndef DSO_set_default_method
#define DSO_set_default_method __NS_SYMBOL(DSO_set_default_method)
#endif

#ifndef ENGINE_get_default_DH
#define ENGINE_get_default_DH __NS_SYMBOL(ENGINE_get_default_DH)
#endif

#ifndef ENGINE_get_default_DSA
#define ENGINE_get_default_DSA __NS_SYMBOL(ENGINE_get_default_DSA)
#endif

#ifndef ENGINE_get_default_ECDH
#define ENGINE_get_default_ECDH __NS_SYMBOL(ENGINE_get_default_ECDH)
#endif

#ifndef ENGINE_get_default_ECDSA
#define ENGINE_get_default_ECDSA __NS_SYMBOL(ENGINE_get_default_ECDSA)
#endif

#ifndef ENGINE_get_default_RAND
#define ENGINE_get_default_RAND __NS_SYMBOL(ENGINE_get_default_RAND)
#endif

#ifndef ENGINE_get_default_RSA
#define ENGINE_get_default_RSA __NS_SYMBOL(ENGINE_get_default_RSA)
#endif

#ifndef EVP_PKEY_missing_parameters
#define EVP_PKEY_missing_parameters __NS_SYMBOL(EVP_PKEY_missing_parameters)
#endif

#ifndef EVP_cleanup
#define EVP_cleanup __NS_SYMBOL(EVP_cleanup)
#endif

#ifndef OBJ_add_object
#define OBJ_add_object __NS_SYMBOL(OBJ_add_object)
#endif

#ifndef OCSP_ONEREQ_get_ext_by_NID
#define OCSP_ONEREQ_get_ext_by_NID __NS_SYMBOL(OCSP_ONEREQ_get_ext_by_NID)
#endif

#ifndef PEM_read_X509_CERT_PAIR
#define PEM_read_X509_CERT_PAIR __NS_SYMBOL(PEM_read_X509_CERT_PAIR)
#endif

#ifndef PEM_write_bio_CMS
#define PEM_write_bio_CMS __NS_SYMBOL(PEM_write_bio_CMS)
#endif

#ifndef PKCS7_content_new
#define PKCS7_content_new __NS_SYMBOL(PKCS7_content_new)
#endif

#ifndef RSA_setup_blinding
#define RSA_setup_blinding __NS_SYMBOL(RSA_setup_blinding)
#endif

#ifndef SRP_VBASE_init
#define SRP_VBASE_init __NS_SYMBOL(SRP_VBASE_init)
#endif

#ifndef TS_MSG_IMPRINT_get_msg
#define TS_MSG_IMPRINT_get_msg __NS_SYMBOL(TS_MSG_IMPRINT_get_msg)
#endif

#ifndef UI_UTIL_read_pw
#define UI_UTIL_read_pw __NS_SYMBOL(UI_UTIL_read_pw)
#endif

#ifndef X509_policy_node_get0_parent
#define X509_policy_node_get0_parent __NS_SYMBOL(X509_policy_node_get0_parent)
#endif

#ifndef X509_print_ex
#define X509_print_ex __NS_SYMBOL(X509_print_ex)
#endif

#ifndef X509v3_get_ext_by_critical
#define X509v3_get_ext_by_critical __NS_SYMBOL(X509v3_get_ext_by_critical)
#endif

#ifndef _ossl_old_crypt
#define _ossl_old_crypt __NS_SYMBOL(_ossl_old_crypt)
#endif

#ifndef bn_mul_words
#define bn_mul_words __NS_SYMBOL(bn_mul_words)
#endif

#ifndef hash_block
#define hash_block __NS_SYMBOL(hash_block)
#endif

#ifndef keyWrapCryptoPro
#define keyWrapCryptoPro __NS_SYMBOL(keyWrapCryptoPro)
#endif

#ifndef ASN1_BIT_STRING_new
#define ASN1_BIT_STRING_new __NS_SYMBOL(ASN1_BIT_STRING_new)
#endif

#ifndef ASN1_BIT_STRING_num_asc
#define ASN1_BIT_STRING_num_asc __NS_SYMBOL(ASN1_BIT_STRING_num_asc)
#endif

#ifndef BIO_ctrl_get_read_request
#define BIO_ctrl_get_read_request __NS_SYMBOL(BIO_ctrl_get_read_request)
#endif

#ifndef CMAC_CTX_copy
#define CMAC_CTX_copy __NS_SYMBOL(CMAC_CTX_copy)
#endif

#ifndef CRYPTO_cleanup_all_ex_data
#define CRYPTO_cleanup_all_ex_data __NS_SYMBOL(CRYPTO_cleanup_all_ex_data)
#endif

#ifndef DES_set_key_checked
#define DES_set_key_checked __NS_SYMBOL(DES_set_key_checked)
#endif

#ifndef DES_string_to_2keys
#define DES_string_to_2keys __NS_SYMBOL(DES_string_to_2keys)
#endif

#ifndef DSO_get_default_method
#define DSO_get_default_method __NS_SYMBOL(DSO_get_default_method)
#endif

#ifndef EC_KEY_free
#define EC_KEY_free __NS_SYMBOL(EC_KEY_free)
#endif

#ifndef EVP_OpenFinal
#define EVP_OpenFinal __NS_SYMBOL(EVP_OpenFinal)
#endif

#ifndef GENERAL_NAME_new
#define GENERAL_NAME_new __NS_SYMBOL(GENERAL_NAME_new)
#endif

#ifndef GOST_KEY_AGREEMENT_INFO_new
#define GOST_KEY_AGREEMENT_INFO_new __NS_SYMBOL(GOST_KEY_AGREEMENT_INFO_new)
#endif

#ifndef KRB5_TKTBODY_new
#define KRB5_TKTBODY_new __NS_SYMBOL(KRB5_TKTBODY_new)
#endif

#ifndef OBJ_add_sigid
#define OBJ_add_sigid __NS_SYMBOL(OBJ_add_sigid)
#endif

#ifndef OCSP_ONEREQ_get_ext_by_OBJ
#define OCSP_ONEREQ_get_ext_by_OBJ __NS_SYMBOL(OCSP_ONEREQ_get_ext_by_OBJ)
#endif

#ifndef OCSP_ONEREQ_new
#define OCSP_ONEREQ_new __NS_SYMBOL(OCSP_ONEREQ_new)
#endif

#ifndef PKCS12_BAGS_new
#define PKCS12_BAGS_new __NS_SYMBOL(PKCS12_BAGS_new)
#endif

#ifndef PKCS12_MAKE_SHKEYBAG
#define PKCS12_MAKE_SHKEYBAG __NS_SYMBOL(PKCS12_MAKE_SHKEYBAG)
#endif

#ifndef PKCS8_pkey_get0
#define PKCS8_pkey_get0 __NS_SYMBOL(PKCS8_pkey_get0)
#endif

#ifndef SHA512_Final
#define SHA512_Final __NS_SYMBOL(SHA512_Final)
#endif

#ifndef TS_REQ_set_policy_id
#define TS_REQ_set_policy_id __NS_SYMBOL(TS_REQ_set_policy_id)
#endif

#ifndef X509_CRL_new
#define X509_CRL_new __NS_SYMBOL(X509_CRL_new)
#endif

#ifndef X509_NAME_get_index_by_OBJ
#define X509_NAME_get_index_by_OBJ __NS_SYMBOL(X509_NAME_get_index_by_OBJ)
#endif

#ifndef X509_REQ_sign_ctx
#define X509_REQ_sign_ctx __NS_SYMBOL(X509_REQ_sign_ctx)
#endif

#ifndef X509_TRUST_get_count
#define X509_TRUST_get_count __NS_SYMBOL(X509_TRUST_get_count)
#endif

#ifndef X509_get_ext_by_NID
#define X509_get_ext_by_NID __NS_SYMBOL(X509_get_ext_by_NID)
#endif

#ifndef X509_set_notAfter
#define X509_set_notAfter __NS_SYMBOL(X509_set_notAfter)
#endif

#ifndef _ossl_old_des_ofb_encrypt
#define _ossl_old_des_ofb_encrypt __NS_SYMBOL(_ossl_old_des_ofb_encrypt)
#endif

#ifndef asn1_enc_save
#define asn1_enc_save __NS_SYMBOL(asn1_enc_save)
#endif

#ifndef d2i_PKCS7_SIGNER_INFO
#define d2i_PKCS7_SIGNER_INFO __NS_SYMBOL(d2i_PKCS7_SIGNER_INFO)
#endif

#ifndef d2i_TS_REQ
#define d2i_TS_REQ __NS_SYMBOL(d2i_TS_REQ)
#endif

#ifndef i2d_PKCS12_bio
#define i2d_PKCS12_bio __NS_SYMBOL(i2d_PKCS12_bio)
#endif

#ifndef sk_new
#define sk_new __NS_SYMBOL(sk_new)
#endif

#ifndef AES_unwrap_key
#define AES_unwrap_key __NS_SYMBOL(AES_unwrap_key)
#endif

#ifndef ASN1_TYPE_cmp
#define ASN1_TYPE_cmp __NS_SYMBOL(ASN1_TYPE_cmp)
#endif

#ifndef ASN1_unpack_string
#define ASN1_unpack_string __NS_SYMBOL(ASN1_unpack_string)
#endif

#ifndef BN_add_word
#define BN_add_word __NS_SYMBOL(BN_add_word)
#endif

#ifndef BN_mod_sub
#define BN_mod_sub __NS_SYMBOL(BN_mod_sub)
#endif

#ifndef CMS_unsigned_add1_attr_by_OBJ
#define CMS_unsigned_add1_attr_by_OBJ __NS_SYMBOL(CMS_unsigned_add1_attr_by_OBJ)
#endif

#ifndef COMP_expand_block
#define COMP_expand_block __NS_SYMBOL(COMP_expand_block)
#endif

#ifndef DH_check_pub_key
#define DH_check_pub_key __NS_SYMBOL(DH_check_pub_key)
#endif

#ifndef DSO_get_method
#define DSO_get_method __NS_SYMBOL(DSO_get_method)
#endif

#ifndef ECDSA_sign_ex
#define ECDSA_sign_ex __NS_SYMBOL(ECDSA_sign_ex)
#endif

#ifndef ENGINE_get_DH
#define ENGINE_get_DH __NS_SYMBOL(ENGINE_get_DH)
#endif

#ifndef ENGINE_get_DSA
#define ENGINE_get_DSA __NS_SYMBOL(ENGINE_get_DSA)
#endif

#ifndef ENGINE_get_ECDH
#define ENGINE_get_ECDH __NS_SYMBOL(ENGINE_get_ECDH)
#endif

#ifndef ENGINE_get_ECDSA
#define ENGINE_get_ECDSA __NS_SYMBOL(ENGINE_get_ECDSA)
#endif

#ifndef ENGINE_get_RAND
#define ENGINE_get_RAND __NS_SYMBOL(ENGINE_get_RAND)
#endif

#ifndef ENGINE_get_RSA
#define ENGINE_get_RSA __NS_SYMBOL(ENGINE_get_RSA)
#endif

#ifndef ENGINE_get_prev
#define ENGINE_get_prev __NS_SYMBOL(ENGINE_get_prev)
#endif

#ifndef EVP_EncodeBlock
#define EVP_EncodeBlock __NS_SYMBOL(EVP_EncodeBlock)
#endif

#ifndef EVP_PKEY_cmp_parameters
#define EVP_PKEY_cmp_parameters __NS_SYMBOL(EVP_PKEY_cmp_parameters)
#endif

#ifndef EVP_PKEY_keygen_init
#define EVP_PKEY_keygen_init __NS_SYMBOL(EVP_PKEY_keygen_init)
#endif

#ifndef EVP_SealFinal
#define EVP_SealFinal __NS_SYMBOL(EVP_SealFinal)
#endif

#ifndef EVP_aes_192_cbc
#define EVP_aes_192_cbc __NS_SYMBOL(EVP_aes_192_cbc)
#endif

#ifndef OCSP_ONEREQ_get_ext_by_critical
#define OCSP_ONEREQ_get_ext_by_critical __NS_SYMBOL(OCSP_ONEREQ_get_ext_by_critical)
#endif

#ifndef OCSP_basic_add1_status
#define OCSP_basic_add1_status __NS_SYMBOL(OCSP_basic_add1_status)
#endif

#ifndef OCSP_sendreq_new
#define OCSP_sendreq_new __NS_SYMBOL(OCSP_sendreq_new)
#endif

#ifndef PEM_write_X509_REQ_NEW
#define PEM_write_X509_REQ_NEW __NS_SYMBOL(PEM_write_X509_REQ_NEW)
#endif

#ifndef TS_VERIFY_CTX_cleanup
#define TS_VERIFY_CTX_cleanup __NS_SYMBOL(TS_VERIFY_CTX_cleanup)
#endif

#ifndef UI_get_default_method
#define UI_get_default_method __NS_SYMBOL(UI_get_default_method)
#endif

#ifndef X509_LOOKUP_by_subject
#define X509_LOOKUP_by_subject __NS_SYMBOL(X509_LOOKUP_by_subject)
#endif

#ifndef X509_keyid_set1
#define X509_keyid_set1 __NS_SYMBOL(X509_keyid_set1)
#endif

#ifndef X509_set_ex_data
#define X509_set_ex_data __NS_SYMBOL(X509_set_ex_data)
#endif

#ifndef _ossl_old_des_pcbc_encrypt
#define _ossl_old_des_pcbc_encrypt __NS_SYMBOL(_ossl_old_des_pcbc_encrypt)
#endif

#ifndef a2i_ASN1_INTEGER
#define a2i_ASN1_INTEGER __NS_SYMBOL(a2i_ASN1_INTEGER)
#endif

#ifndef ec_GFp_simple_group_set_curve
#define ec_GFp_simple_group_set_curve __NS_SYMBOL(ec_GFp_simple_group_set_curve)
#endif

#ifndef idea_set_decrypt_key
#define idea_set_decrypt_key __NS_SYMBOL(idea_set_decrypt_key)
#endif

#ifndef ASN1_BIT_STRING_free
#define ASN1_BIT_STRING_free __NS_SYMBOL(ASN1_BIT_STRING_free)
#endif

#ifndef BIO_ctrl_reset_read_request
#define BIO_ctrl_reset_read_request __NS_SYMBOL(BIO_ctrl_reset_read_request)
#endif

#ifndef BN_BLINDING_free
#define BN_BLINDING_free __NS_SYMBOL(BN_BLINDING_free)
#endif

#ifndef DSO_set_method
#define DSO_set_method __NS_SYMBOL(DSO_set_method)
#endif

#ifndef ENGINE_set_DH
#define ENGINE_set_DH __NS_SYMBOL(ENGINE_set_DH)
#endif

#ifndef ENGINE_set_DSA
#define ENGINE_set_DSA __NS_SYMBOL(ENGINE_set_DSA)
#endif

#ifndef ENGINE_set_ECDH
#define ENGINE_set_ECDH __NS_SYMBOL(ENGINE_set_ECDH)
#endif

#ifndef ENGINE_set_ECDSA
#define ENGINE_set_ECDSA __NS_SYMBOL(ENGINE_set_ECDSA)
#endif

#ifndef ENGINE_set_RAND
#define ENGINE_set_RAND __NS_SYMBOL(ENGINE_set_RAND)
#endif

#ifndef ENGINE_set_RSA
#define ENGINE_set_RSA __NS_SYMBOL(ENGINE_set_RSA)
#endif

#ifndef EVP_PKEY2PKCS8
#define EVP_PKEY2PKCS8 __NS_SYMBOL(EVP_PKEY2PKCS8)
#endif

#ifndef GENERAL_NAME_free
#define GENERAL_NAME_free __NS_SYMBOL(GENERAL_NAME_free)
#endif

#ifndef GOST_KEY_AGREEMENT_INFO_free
#define GOST_KEY_AGREEMENT_INFO_free __NS_SYMBOL(GOST_KEY_AGREEMENT_INFO_free)
#endif

#ifndef KRB5_TKTBODY_free
#define KRB5_TKTBODY_free __NS_SYMBOL(KRB5_TKTBODY_free)
#endif

#ifndef MD5_Transform
#define MD5_Transform __NS_SYMBOL(MD5_Transform)
#endif

#ifndef OCSP_ONEREQ_free
#define OCSP_ONEREQ_free __NS_SYMBOL(OCSP_ONEREQ_free)
#endif

#ifndef OCSP_ONEREQ_get_ext
#define OCSP_ONEREQ_get_ext __NS_SYMBOL(OCSP_ONEREQ_get_ext)
#endif

#ifndef PEM_write_bio_X509_CERT_PAIR
#define PEM_write_bio_X509_CERT_PAIR __NS_SYMBOL(PEM_write_bio_X509_CERT_PAIR)
#endif

#ifndef PKCS12_BAGS_free
#define PKCS12_BAGS_free __NS_SYMBOL(PKCS12_BAGS_free)
#endif

#ifndef PKCS7_sign_add_signer
#define PKCS7_sign_add_signer __NS_SYMBOL(PKCS7_sign_add_signer)
#endif

#ifndef SHA1_Transform
#define SHA1_Transform __NS_SYMBOL(SHA1_Transform)
#endif

#ifndef TS_CONF_load_key
#define TS_CONF_load_key __NS_SYMBOL(TS_CONF_load_key)
#endif

#ifndef X509_CRL_free
#define X509_CRL_free __NS_SYMBOL(X509_CRL_free)
#endif

#ifndef X509_TRUST_set
#define X509_TRUST_set __NS_SYMBOL(X509_TRUST_set)
#endif

#ifndef X509_get_ex_data
#define X509_get_ex_data __NS_SYMBOL(X509_get_ex_data)
#endif

#ifndef X509_get_ext_by_OBJ
#define X509_get_ext_by_OBJ __NS_SYMBOL(X509_get_ext_by_OBJ)
#endif

#ifndef X509at_delete_attr
#define X509at_delete_attr __NS_SYMBOL(X509at_delete_attr)
#endif

#ifndef _ossl_old_des_quad_cksum
#define _ossl_old_des_quad_cksum __NS_SYMBOL(_ossl_old_des_quad_cksum)
#endif

#ifndef c2i_ASN1_BIT_STRING
#define c2i_ASN1_BIT_STRING __NS_SYMBOL(c2i_ASN1_BIT_STRING)
#endif

#ifndef i2d_PKCS12_fp
#define i2d_PKCS12_fp __NS_SYMBOL(i2d_PKCS12_fp)
#endif

#ifndef i2d_PKCS7_SIGNER_INFO
#define i2d_PKCS7_SIGNER_INFO __NS_SYMBOL(i2d_PKCS7_SIGNER_INFO)
#endif

#ifndef i2d_TS_REQ
#define i2d_TS_REQ __NS_SYMBOL(i2d_TS_REQ)
#endif

#ifndef md4_block_data_order
#define md4_block_data_order __NS_SYMBOL(md4_block_data_order)
#endif

#ifndef pqueue_peek
#define pqueue_peek __NS_SYMBOL(pqueue_peek)
#endif

#ifndef ripemd160_block_data_order
#define ripemd160_block_data_order __NS_SYMBOL(ripemd160_block_data_order)
#endif

#ifndef ASN1_item_i2d_fp
#define ASN1_item_i2d_fp __NS_SYMBOL(ASN1_item_i2d_fp)
#endif

#ifndef CMS_unsigned_add1_attr_by_NID
#define CMS_unsigned_add1_attr_by_NID __NS_SYMBOL(CMS_unsigned_add1_attr_by_NID)
#endif

#ifndef CRYPTO_set_locked_mem_ex_functions
#define CRYPTO_set_locked_mem_ex_functions __NS_SYMBOL(CRYPTO_set_locked_mem_ex_functions)
#endif

#ifndef DSO_free
#define DSO_free __NS_SYMBOL(DSO_free)
#endif

#ifndef EVP_PKEY2PKCS8_broken
#define EVP_PKEY2PKCS8_broken __NS_SYMBOL(EVP_PKEY2PKCS8_broken)
#endif

#ifndef EVP_PKEY_asn1_find_str
#define EVP_PKEY_asn1_find_str __NS_SYMBOL(EVP_PKEY_asn1_find_str)
#endif

#ifndef MD5_Final
#define MD5_Final __NS_SYMBOL(MD5_Final)
#endif

#ifndef OCSP_ONEREQ_delete_ext
#define OCSP_ONEREQ_delete_ext __NS_SYMBOL(OCSP_ONEREQ_delete_ext)
#endif

#ifndef OCSP_request_sign
#define OCSP_request_sign __NS_SYMBOL(OCSP_request_sign)
#endif

#ifndef PEM_dek_info
#define PEM_dek_info __NS_SYMBOL(PEM_dek_info)
#endif

#ifndef SHA1_Final
#define SHA1_Final __NS_SYMBOL(SHA1_Final)
#endif

#ifndef TS_TST_INFO_get_policy_id
#define TS_TST_INFO_get_policy_id __NS_SYMBOL(TS_TST_INFO_get_policy_id)
#endif

#ifndef UI_free
#define UI_free __NS_SYMBOL(UI_free)
#endif

#ifndef X509_CRL_sign
#define X509_CRL_sign __NS_SYMBOL(X509_CRL_sign)
#endif

#ifndef X509_PUBKEY_get
#define X509_PUBKEY_get __NS_SYMBOL(X509_PUBKEY_get)
#endif

#ifndef _ossl_old_des_random_seed
#define _ossl_old_des_random_seed __NS_SYMBOL(_ossl_old_des_random_seed)
#endif

#ifndef d2i_AutoPrivateKey
#define d2i_AutoPrivateKey __NS_SYMBOL(d2i_AutoPrivateKey)
#endif

#ifndef d2i_X509_AUX
#define d2i_X509_AUX __NS_SYMBOL(d2i_X509_AUX)
#endif

#ifndef pqueue_pop
#define pqueue_pop __NS_SYMBOL(pqueue_pop)
#endif

#ifndef BIO_nread0
#define BIO_nread0 __NS_SYMBOL(BIO_nread0)
#endif

#ifndef BUF_memdup
#define BUF_memdup __NS_SYMBOL(BUF_memdup)
#endif

#ifndef CONF_load_fp
#define CONF_load_fp __NS_SYMBOL(CONF_load_fp)
#endif

#ifndef EC_POINT_oct2point
#define EC_POINT_oct2point __NS_SYMBOL(EC_POINT_oct2point)
#endif

#ifndef ENGINE_get_cipher_engine
#define ENGINE_get_cipher_engine __NS_SYMBOL(ENGINE_get_cipher_engine)
#endif

#ifndef ENGINE_get_digest_engine
#define ENGINE_get_digest_engine __NS_SYMBOL(ENGINE_get_digest_engine)
#endif

#ifndef ENGINE_get_pkey_asn1_meth_engine
#define ENGINE_get_pkey_asn1_meth_engine __NS_SYMBOL(ENGINE_get_pkey_asn1_meth_engine)
#endif

#ifndef ENGINE_get_pkey_meth_engine
#define ENGINE_get_pkey_meth_engine __NS_SYMBOL(ENGINE_get_pkey_meth_engine)
#endif

#ifndef EVP_BytesToKey
#define EVP_BytesToKey __NS_SYMBOL(EVP_BytesToKey)
#endif

#ifndef EVP_CIPHER_do_all
#define EVP_CIPHER_do_all __NS_SYMBOL(EVP_CIPHER_do_all)
#endif

#ifndef EVP_DigestVerifyInit
#define EVP_DigestVerifyInit __NS_SYMBOL(EVP_DigestVerifyInit)
#endif

#ifndef EVP_PKEY_cmp
#define EVP_PKEY_cmp __NS_SYMBOL(EVP_PKEY_cmp)
#endif

#ifndef EVP_aes_192_ecb
#define EVP_aes_192_ecb __NS_SYMBOL(EVP_aes_192_ecb)
#endif

#ifndef OCSP_ONEREQ_get1_ext_d2i
#define OCSP_ONEREQ_get1_ext_d2i __NS_SYMBOL(OCSP_ONEREQ_get1_ext_d2i)
#endif

#ifndef PEM_write_CMS
#define PEM_write_CMS __NS_SYMBOL(PEM_write_CMS)
#endif

#ifndef PKCS7_SIGNER_INFO_new
#define PKCS7_SIGNER_INFO_new __NS_SYMBOL(PKCS7_SIGNER_INFO_new)
#endif

#ifndef SHA224
#define SHA224 __NS_SYMBOL(SHA224)
#endif

#ifndef TS_REQ_new
#define TS_REQ_new __NS_SYMBOL(TS_REQ_new)
#endif

#ifndef TS_TST_INFO_set_msg_imprint
#define TS_TST_INFO_set_msg_imprint __NS_SYMBOL(TS_TST_INFO_set_msg_imprint)
#endif

#ifndef X509V3_add_value_uchar
#define X509V3_add_value_uchar __NS_SYMBOL(X509V3_add_value_uchar)
#endif

#ifndef X509_ALGOR_get0
#define X509_ALGOR_get0 __NS_SYMBOL(X509_ALGOR_get0)
#endif

#ifndef X509_CRL_dup
#define X509_CRL_dup __NS_SYMBOL(X509_CRL_dup)
#endif

#ifndef X509_LOOKUP_by_issuer_serial
#define X509_LOOKUP_by_issuer_serial __NS_SYMBOL(X509_LOOKUP_by_issuer_serial)
#endif

#ifndef X509_REVOKED_set_revocationDate
#define X509_REVOKED_set_revocationDate __NS_SYMBOL(X509_REVOKED_set_revocationDate)
#endif

#ifndef X509_get_ext_by_critical
#define X509_get_ext_by_critical __NS_SYMBOL(X509_get_ext_by_critical)
#endif

#ifndef _ossl_old_des_random_key
#define _ossl_old_des_random_key __NS_SYMBOL(_ossl_old_des_random_key)
#endif

#ifndef d2i_ASN1_OCTET_STRING
#define d2i_ASN1_OCTET_STRING __NS_SYMBOL(d2i_ASN1_OCTET_STRING)
#endif

#ifndef d2i_GENERAL_NAMES
#define d2i_GENERAL_NAMES __NS_SYMBOL(d2i_GENERAL_NAMES)
#endif

#ifndef d2i_GOST_KEY_PARAMS
#define d2i_GOST_KEY_PARAMS __NS_SYMBOL(d2i_GOST_KEY_PARAMS)
#endif

#ifndef d2i_KRB5_TICKET
#define d2i_KRB5_TICKET __NS_SYMBOL(d2i_KRB5_TICKET)
#endif

#ifndef d2i_OCSP_REQINFO
#define d2i_OCSP_REQINFO __NS_SYMBOL(d2i_OCSP_REQINFO)
#endif

#ifndef d2i_PKCS12_SAFEBAG
#define d2i_PKCS12_SAFEBAG __NS_SYMBOL(d2i_PKCS12_SAFEBAG)
#endif

#ifndef d2i_PKCS12_bio
#define d2i_PKCS12_bio __NS_SYMBOL(d2i_PKCS12_bio)
#endif

#ifndef ASN1_UTCTIME_set_string
#define ASN1_UTCTIME_set_string __NS_SYMBOL(ASN1_UTCTIME_set_string)
#endif

#ifndef ASN1_item_ex_i2d
#define ASN1_item_ex_i2d __NS_SYMBOL(ASN1_item_ex_i2d)
#endif

#ifndef CMS_unsigned_add1_attr_by_txt
#define CMS_unsigned_add1_attr_by_txt __NS_SYMBOL(CMS_unsigned_add1_attr_by_txt)
#endif

#ifndef CRYPTO_ctr128_encrypt_ctr32
#define CRYPTO_ctr128_encrypt_ctr32 __NS_SYMBOL(CRYPTO_ctr128_encrypt_ctr32)
#endif

#ifndef EVP_DigestSignFinal
#define EVP_DigestSignFinal __NS_SYMBOL(EVP_DigestSignFinal)
#endif

#ifndef OCSP_ONEREQ_add1_ext_i2d
#define OCSP_ONEREQ_add1_ext_i2d __NS_SYMBOL(OCSP_ONEREQ_add1_ext_i2d)
#endif

#ifndef RAND_write_file
#define RAND_write_file __NS_SYMBOL(RAND_write_file)
#endif

#ifndef X509V3_conf_free
#define X509V3_conf_free __NS_SYMBOL(X509V3_conf_free)
#endif

#ifndef _ossl_old_des_read_password
#define _ossl_old_des_read_password __NS_SYMBOL(_ossl_old_des_read_password)
#endif

#ifndef ec_GFp_nist_field_mul
#define ec_GFp_nist_field_mul __NS_SYMBOL(ec_GFp_nist_field_mul)
#endif

#ifndef i2d_ASN1_bytes
#define i2d_ASN1_bytes __NS_SYMBOL(i2d_ASN1_bytes)
#endif

#ifndef pqueue_find
#define pqueue_find __NS_SYMBOL(pqueue_find)
#endif

#ifndef ASN1_TIME_check
#define ASN1_TIME_check __NS_SYMBOL(ASN1_TIME_check)
#endif

#ifndef ASN1_item_verify
#define ASN1_item_verify __NS_SYMBOL(ASN1_item_verify)
#endif

#ifndef ASN1_pack_string
#define ASN1_pack_string __NS_SYMBOL(ASN1_pack_string)
#endif

#ifndef BN_CTX_new
#define BN_CTX_new __NS_SYMBOL(BN_CTX_new)
#endif

#ifndef BN_mod_exp
#define BN_mod_exp __NS_SYMBOL(BN_mod_exp)
#endif

#ifndef BN_to_ASN1_ENUMERATED
#define BN_to_ASN1_ENUMERATED __NS_SYMBOL(BN_to_ASN1_ENUMERATED)
#endif

#ifndef BUF_MEM_grow_clean
#define BUF_MEM_grow_clean __NS_SYMBOL(BUF_MEM_grow_clean)
#endif

#ifndef DSA_verify
#define DSA_verify __NS_SYMBOL(DSA_verify)
#endif

#ifndef EC_POINT_point2hex
#define EC_POINT_point2hex __NS_SYMBOL(EC_POINT_point2hex)
#endif

#ifndef ENGINE_get_cipher
#define ENGINE_get_cipher __NS_SYMBOL(ENGINE_get_cipher)
#endif

#ifndef ENGINE_get_digest
#define ENGINE_get_digest __NS_SYMBOL(ENGINE_get_digest)
#endif

#ifndef ENGINE_get_pkey_asn1_meth
#define ENGINE_get_pkey_asn1_meth __NS_SYMBOL(ENGINE_get_pkey_asn1_meth)
#endif

#ifndef ENGINE_get_pkey_meth
#define ENGINE_get_pkey_meth __NS_SYMBOL(ENGINE_get_pkey_meth)
#endif

#ifndef ERR_print_errors
#define ERR_print_errors __NS_SYMBOL(ERR_print_errors)
#endif

#ifndef EVP_CIPHER_get_asn1_iv
#define EVP_CIPHER_get_asn1_iv __NS_SYMBOL(EVP_CIPHER_get_asn1_iv)
#endif

#ifndef EVP_PKEY_verify_init
#define EVP_PKEY_verify_init __NS_SYMBOL(EVP_PKEY_verify_init)
#endif

#ifndef OCSP_ONEREQ_add_ext
#define OCSP_ONEREQ_add_ext __NS_SYMBOL(OCSP_ONEREQ_add_ext)
#endif

#ifndef OPENSSL_cleanse
#define OPENSSL_cleanse __NS_SYMBOL(OPENSSL_cleanse)
#endif

#ifndef PEM_read_bio_X509_CRL
#define PEM_read_bio_X509_CRL __NS_SYMBOL(PEM_read_bio_X509_CRL)
#endif

#ifndef PKCS12_get_friendlyname
#define PKCS12_get_friendlyname __NS_SYMBOL(PKCS12_get_friendlyname)
#endif

#ifndef PKCS7_SIGNER_INFO_free
#define PKCS7_SIGNER_INFO_free __NS_SYMBOL(PKCS7_SIGNER_INFO_free)
#endif

#ifndef TS_REQ_free
#define TS_REQ_free __NS_SYMBOL(TS_REQ_free)
#endif

#ifndef X509_CRL_add0_revoked
#define X509_CRL_add0_revoked __NS_SYMBOL(X509_CRL_add0_revoked)
#endif

#ifndef X509_LOOKUP_by_fingerprint
#define X509_LOOKUP_by_fingerprint __NS_SYMBOL(X509_LOOKUP_by_fingerprint)
#endif

#ifndef X509_get_ext
#define X509_get_ext __NS_SYMBOL(X509_get_ext)
#endif

#ifndef X509at_add1_attr
#define X509at_add1_attr __NS_SYMBOL(X509at_add1_attr)
#endif

#ifndef _ossl_old_des_read_2passwords
#define _ossl_old_des_read_2passwords __NS_SYMBOL(_ossl_old_des_read_2passwords)
#endif

#ifndef d2i_PKCS12_fp
#define d2i_PKCS12_fp __NS_SYMBOL(d2i_PKCS12_fp)
#endif

#ifndef i2d_ASN1_OCTET_STRING
#define i2d_ASN1_OCTET_STRING __NS_SYMBOL(i2d_ASN1_OCTET_STRING)
#endif

#ifndef i2d_GENERAL_NAMES
#define i2d_GENERAL_NAMES __NS_SYMBOL(i2d_GENERAL_NAMES)
#endif

#ifndef i2d_GOST_KEY_PARAMS
#define i2d_GOST_KEY_PARAMS __NS_SYMBOL(i2d_GOST_KEY_PARAMS)
#endif

#ifndef i2d_KRB5_TICKET
#define i2d_KRB5_TICKET __NS_SYMBOL(i2d_KRB5_TICKET)
#endif

#ifndef i2d_OCSP_REQINFO
#define i2d_OCSP_REQINFO __NS_SYMBOL(i2d_OCSP_REQINFO)
#endif

#ifndef i2d_PKCS12_SAFEBAG
#define i2d_PKCS12_SAFEBAG __NS_SYMBOL(i2d_PKCS12_SAFEBAG)
#endif

#ifndef BIO_free
#define BIO_free __NS_SYMBOL(BIO_free)
#endif

#ifndef BN_div_recp
#define BN_div_recp __NS_SYMBOL(BN_div_recp)
#endif

#ifndef BN_num_bits
#define BN_num_bits __NS_SYMBOL(BN_num_bits)
#endif

#ifndef CMS_unsigned_get0_data_by_OBJ
#define CMS_unsigned_get0_data_by_OBJ __NS_SYMBOL(CMS_unsigned_get0_data_by_OBJ)
#endif

#ifndef CRYPTO_get_ex_new_index
#define CRYPTO_get_ex_new_index __NS_SYMBOL(CRYPTO_get_ex_new_index)
#endif

#ifndef CRYPTO_is_mem_check_on
#define CRYPTO_is_mem_check_on __NS_SYMBOL(CRYPTO_is_mem_check_on)
#endif

#ifndef CRYPTO_set_mem_debug_functions
#define CRYPTO_set_mem_debug_functions __NS_SYMBOL(CRYPTO_set_mem_debug_functions)
#endif

#ifndef DES_set_key_unchecked
#define DES_set_key_unchecked __NS_SYMBOL(DES_set_key_unchecked)
#endif

#ifndef EVP_aes_192_ofb
#define EVP_aes_192_ofb __NS_SYMBOL(EVP_aes_192_ofb)
#endif

#ifndef PEM_write_X509_CERT_PAIR
#define PEM_write_X509_CERT_PAIR __NS_SYMBOL(PEM_write_X509_CERT_PAIR)
#endif

#ifndef RAND_seed
#define RAND_seed __NS_SYMBOL(RAND_seed)
#endif

#ifndef TS_REQ_get_policy_id
#define TS_REQ_get_policy_id __NS_SYMBOL(TS_REQ_get_policy_id)
#endif

#ifndef X509V3_EXT_add_list
#define X509V3_EXT_add_list __NS_SYMBOL(X509V3_EXT_add_list)
#endif

#ifndef X509V3_EXT_print
#define X509V3_EXT_print __NS_SYMBOL(X509V3_EXT_print)
#endif

#ifndef X509_CRL_sign_ctx
#define X509_CRL_sign_ctx __NS_SYMBOL(X509_CRL_sign_ctx)
#endif

#ifndef X509_set_pubkey
#define X509_set_pubkey __NS_SYMBOL(X509_set_pubkey)
#endif

#ifndef _ossl_old_des_set_odd_parity
#define _ossl_old_des_set_odd_parity __NS_SYMBOL(_ossl_old_des_set_odd_parity)
#endif

#ifndef d2i_BASIC_CONSTRAINTS
#define d2i_BASIC_CONSTRAINTS __NS_SYMBOL(d2i_BASIC_CONSTRAINTS)
#endif

#ifndef d2i_SXNETID
#define d2i_SXNETID __NS_SYMBOL(d2i_SXNETID)
#endif

#ifndef ec_GFp_mont_group_set_curve
#define ec_GFp_mont_group_set_curve __NS_SYMBOL(ec_GFp_mont_group_set_curve)
#endif

#ifndef gost2001_do_sign
#define gost2001_do_sign __NS_SYMBOL(gost2001_do_sign)
#endif

#ifndef ASN1_OCTET_STRING_new
#define ASN1_OCTET_STRING_new __NS_SYMBOL(ASN1_OCTET_STRING_new)
#endif

#ifndef BN_BLINDING_update
#define BN_BLINDING_update __NS_SYMBOL(BN_BLINDING_update)
#endif

#ifndef BN_lshift
#define BN_lshift __NS_SYMBOL(BN_lshift)
#endif

#ifndef ENGINE_load_public_key
#define ENGINE_load_public_key __NS_SYMBOL(ENGINE_load_public_key)
#endif

#ifndef GENERAL_NAMES_new
#define GENERAL_NAMES_new __NS_SYMBOL(GENERAL_NAMES_new)
#endif

#ifndef GOST_KEY_PARAMS_new
#define GOST_KEY_PARAMS_new __NS_SYMBOL(GOST_KEY_PARAMS_new)
#endif

#ifndef KRB5_TICKET_new
#define KRB5_TICKET_new __NS_SYMBOL(KRB5_TICKET_new)
#endif

#ifndef OCSP_BASICRESP_get_ext_count
#define OCSP_BASICRESP_get_ext_count __NS_SYMBOL(OCSP_BASICRESP_get_ext_count)
#endif

#ifndef OCSP_REQINFO_new
#define OCSP_REQINFO_new __NS_SYMBOL(OCSP_REQINFO_new)
#endif

#ifndef PKCS12_SAFEBAG_new
#define PKCS12_SAFEBAG_new __NS_SYMBOL(PKCS12_SAFEBAG_new)
#endif

#ifndef PKCS12_x5092certbag
#define PKCS12_x5092certbag __NS_SYMBOL(PKCS12_x5092certbag)
#endif

#ifndef SRP_Calc_server_key
#define SRP_Calc_server_key __NS_SYMBOL(SRP_Calc_server_key)
#endif

#ifndef TS_REQ_dup
#define TS_REQ_dup __NS_SYMBOL(TS_REQ_dup)
#endif

#ifndef TS_REQ_set_nonce
#define TS_REQ_set_nonce __NS_SYMBOL(TS_REQ_set_nonce)
#endif

#ifndef X509_ALGOR_set_md
#define X509_ALGOR_set_md __NS_SYMBOL(X509_ALGOR_set_md)
#endif

#ifndef X509_LOOKUP_by_alias
#define X509_LOOKUP_by_alias __NS_SYMBOL(X509_LOOKUP_by_alias)
#endif

#ifndef X509_NAME_ENTRY_get_data
#define X509_NAME_ENTRY_get_data __NS_SYMBOL(X509_NAME_ENTRY_get_data)
#endif

#ifndef X509_delete_ext
#define X509_delete_ext __NS_SYMBOL(X509_delete_ext)
#endif

#ifndef X509v3_get_ext
#define X509v3_get_ext __NS_SYMBOL(X509v3_get_ext)
#endif

#ifndef X9_62_PENTANOMIAL_new
#define X9_62_PENTANOMIAL_new __NS_SYMBOL(X9_62_PENTANOMIAL_new)
#endif

#ifndef _ossl_old_des_is_weak_key
#define _ossl_old_des_is_weak_key __NS_SYMBOL(_ossl_old_des_is_weak_key)
#endif

#ifndef d2i_PKCS7_ISSUER_AND_SERIAL
#define d2i_PKCS7_ISSUER_AND_SERIAL __NS_SYMBOL(d2i_PKCS7_ISSUER_AND_SERIAL)
#endif

#ifndef ASN1_TIME_to_generalizedtime
#define ASN1_TIME_to_generalizedtime __NS_SYMBOL(ASN1_TIME_to_generalizedtime)
#endif

#ifndef BIO_new_CMS
#define BIO_new_CMS __NS_SYMBOL(BIO_new_CMS)
#endif

#ifndef BN_mod_sub_quick
#define BN_mod_sub_quick __NS_SYMBOL(BN_mod_sub_quick)
#endif

#ifndef CMS_add1_recipient_cert
#define CMS_add1_recipient_cert __NS_SYMBOL(CMS_add1_recipient_cert)
#endif

#ifndef DSAparams_print
#define DSAparams_print __NS_SYMBOL(DSAparams_print)
#endif

#ifndef EC_EX_DATA_free_all_data
#define EC_EX_DATA_free_all_data __NS_SYMBOL(EC_EX_DATA_free_all_data)
#endif

#ifndef EC_KEY_copy
#define EC_KEY_copy __NS_SYMBOL(EC_KEY_copy)
#endif

#ifndef ENGINE_finish
#define ENGINE_finish __NS_SYMBOL(ENGINE_finish)
#endif

#ifndef ENGINE_free
#define ENGINE_free __NS_SYMBOL(ENGINE_free)
#endif

#ifndef EVP_PKEY_keygen
#define EVP_PKEY_keygen __NS_SYMBOL(EVP_PKEY_keygen)
#endif

#ifndef OBJ_cmp
#define OBJ_cmp __NS_SYMBOL(OBJ_cmp)
#endif

#ifndef PEM_read_X509_CRL
#define PEM_read_X509_CRL __NS_SYMBOL(PEM_read_X509_CRL)
#endif

#ifndef RSA_padding_add_PKCS1_type_2
#define RSA_padding_add_PKCS1_type_2 __NS_SYMBOL(RSA_padding_add_PKCS1_type_2)
#endif

#ifndef TS_CONF_get_tsa_section
#define TS_CONF_get_tsa_section __NS_SYMBOL(TS_CONF_get_tsa_section)
#endif

#ifndef X509_REVOKED_set_serialNumber
#define X509_REVOKED_set_serialNumber __NS_SYMBOL(X509_REVOKED_set_serialNumber)
#endif

#ifndef X509_TRUST_add
#define X509_TRUST_add __NS_SYMBOL(X509_TRUST_add)
#endif

#ifndef _ossl_old_des_set_key
#define _ossl_old_des_set_key __NS_SYMBOL(_ossl_old_des_set_key)
#endif

#ifndef i2d_BASIC_CONSTRAINTS
#define i2d_BASIC_CONSTRAINTS __NS_SYMBOL(i2d_BASIC_CONSTRAINTS)
#endif

#ifndef i2d_SXNETID
#define i2d_SXNETID __NS_SYMBOL(i2d_SXNETID)
#endif

#ifndef lh_node_stats
#define lh_node_stats __NS_SYMBOL(lh_node_stats)
#endif

#ifndef pqueue_print
#define pqueue_print __NS_SYMBOL(pqueue_print)
#endif

#ifndef ASN1_OCTET_STRING_free
#define ASN1_OCTET_STRING_free __NS_SYMBOL(ASN1_OCTET_STRING_free)
#endif

#ifndef BIO_nread
#define BIO_nread __NS_SYMBOL(BIO_nread)
#endif

#ifndef BN_clear_free
#define BN_clear_free __NS_SYMBOL(BN_clear_free)
#endif

#ifndef ECDSA_sign_setup
#define ECDSA_sign_setup __NS_SYMBOL(ECDSA_sign_setup)
#endif

#ifndef ENGINE_add
#define ENGINE_add __NS_SYMBOL(ENGINE_add)
#endif

#ifndef EVP_CIPHER_do_all_sorted
#define EVP_CIPHER_do_all_sorted __NS_SYMBOL(EVP_CIPHER_do_all_sorted)
#endif

#ifndef EVP_aes_192_cfb128
#define EVP_aes_192_cfb128 __NS_SYMBOL(EVP_aes_192_cfb128)
#endif

#ifndef GENERAL_NAMES_free
#define GENERAL_NAMES_free __NS_SYMBOL(GENERAL_NAMES_free)
#endif

#ifndef GOST_KEY_PARAMS_free
#define GOST_KEY_PARAMS_free __NS_SYMBOL(GOST_KEY_PARAMS_free)
#endif

#ifndef KRB5_TICKET_free
#define KRB5_TICKET_free __NS_SYMBOL(KRB5_TICKET_free)
#endif

#ifndef NETSCAPE_SPKI_sign
#define NETSCAPE_SPKI_sign __NS_SYMBOL(NETSCAPE_SPKI_sign)
#endif

#ifndef OCSP_BASICRESP_get_ext_by_NID
#define OCSP_BASICRESP_get_ext_by_NID __NS_SYMBOL(OCSP_BASICRESP_get_ext_by_NID)
#endif

#ifndef OCSP_REQINFO_free
#define OCSP_REQINFO_free __NS_SYMBOL(OCSP_REQINFO_free)
#endif

#ifndef PKCS12_SAFEBAG_free
#define PKCS12_SAFEBAG_free __NS_SYMBOL(PKCS12_SAFEBAG_free)
#endif

#ifndef PKCS12_item_decrypt_d2i
#define PKCS12_item_decrypt_d2i __NS_SYMBOL(PKCS12_item_decrypt_d2i)
#endif

#ifndef PKCS12_x509crl2certbag
#define PKCS12_x509crl2certbag __NS_SYMBOL(PKCS12_x509crl2certbag)
#endif

#ifndef RSA_X931_hash_id
#define RSA_X931_hash_id __NS_SYMBOL(RSA_X931_hash_id)
#endif

#ifndef X509V3_add_value_bool
#define X509V3_add_value_bool __NS_SYMBOL(X509V3_add_value_bool)
#endif

#ifndef X509_NAME_get_entry
#define X509_NAME_get_entry __NS_SYMBOL(X509_NAME_get_entry)
#endif

#ifndef X509_STORE_new
#define X509_STORE_new __NS_SYMBOL(X509_STORE_new)
#endif

#ifndef X509_add_ext
#define X509_add_ext __NS_SYMBOL(X509_add_ext)
#endif

#ifndef X9_62_PENTANOMIAL_free
#define X9_62_PENTANOMIAL_free __NS_SYMBOL(X9_62_PENTANOMIAL_free)
#endif

#ifndef _CONF_new_data
#define _CONF_new_data __NS_SYMBOL(_CONF_new_data)
#endif

#ifndef _ossl_old_des_key_sched
#define _ossl_old_des_key_sched __NS_SYMBOL(_ossl_old_des_key_sched)
#endif

#ifndef cms_SignerIdentifier_get0_signer_id
#define cms_SignerIdentifier_get0_signer_id __NS_SYMBOL(cms_SignerIdentifier_get0_signer_id)
#endif

#ifndef d2i_EXTENDED_KEY_USAGE
#define d2i_EXTENDED_KEY_USAGE __NS_SYMBOL(d2i_EXTENDED_KEY_USAGE)
#endif

#ifndef d2i_TS_REQ_bio
#define d2i_TS_REQ_bio __NS_SYMBOL(d2i_TS_REQ_bio)
#endif

#ifndef engine_cleanup_add_first
#define engine_cleanup_add_first __NS_SYMBOL(engine_cleanup_add_first)
#endif

#ifndef i2d_PKCS7_ISSUER_AND_SERIAL
#define i2d_PKCS7_ISSUER_AND_SERIAL __NS_SYMBOL(i2d_PKCS7_ISSUER_AND_SERIAL)
#endif

#ifndef i2d_X509_AUX
#define i2d_X509_AUX __NS_SYMBOL(i2d_X509_AUX)
#endif

#ifndef keyUnwrapCryptoPro
#define keyUnwrapCryptoPro __NS_SYMBOL(keyUnwrapCryptoPro)
#endif

#ifndef sk_free
#define sk_free __NS_SYMBOL(sk_free)
#endif

#ifndef ASN1_GENERALIZEDTIME_set_string
#define ASN1_GENERALIZEDTIME_set_string __NS_SYMBOL(ASN1_GENERALIZEDTIME_set_string)
#endif

#ifndef ASN1_STRING_TABLE_get
#define ASN1_STRING_TABLE_get __NS_SYMBOL(ASN1_STRING_TABLE_get)
#endif

#ifndef BASIC_CONSTRAINTS_new
#define BASIC_CONSTRAINTS_new __NS_SYMBOL(BASIC_CONSTRAINTS_new)
#endif

#ifndef BN_GF2m_mod_arr
#define BN_GF2m_mod_arr __NS_SYMBOL(BN_GF2m_mod_arr)
#endif

#ifndef BN_mod_exp_mont_word
#define BN_mod_exp_mont_word __NS_SYMBOL(BN_mod_exp_mont_word)
#endif

#ifndef BN_mod_inverse
#define BN_mod_inverse __NS_SYMBOL(BN_mod_inverse)
#endif

#ifndef ENGINE_get_ciphers
#define ENGINE_get_ciphers __NS_SYMBOL(ENGINE_get_ciphers)
#endif

#ifndef ENGINE_get_digests
#define ENGINE_get_digests __NS_SYMBOL(ENGINE_get_digests)
#endif

#ifndef ENGINE_get_pkey_asn1_meths
#define ENGINE_get_pkey_asn1_meths __NS_SYMBOL(ENGINE_get_pkey_asn1_meths)
#endif

#ifndef ENGINE_get_pkey_meths
#define ENGINE_get_pkey_meths __NS_SYMBOL(ENGINE_get_pkey_meths)
#endif

#ifndef EVP_PKEY_new
#define EVP_PKEY_new __NS_SYMBOL(EVP_PKEY_new)
#endif

#ifndef PKCS7_add_attrib_content_type
#define PKCS7_add_attrib_content_type __NS_SYMBOL(PKCS7_add_attrib_content_type)
#endif

#ifndef PKCS7_set_type
#define PKCS7_set_type __NS_SYMBOL(PKCS7_set_type)
#endif

#ifndef POLICY_CONSTRAINTS_new
#define POLICY_CONSTRAINTS_new __NS_SYMBOL(POLICY_CONSTRAINTS_new)
#endif

#ifndef SXNETID_new
#define SXNETID_new __NS_SYMBOL(SXNETID_new)
#endif

#ifndef TS_TST_INFO_get_msg_imprint
#define TS_TST_INFO_get_msg_imprint __NS_SYMBOL(TS_TST_INFO_get_msg_imprint)
#endif

#ifndef _ossl_old_des_string_to_key
#define _ossl_old_des_string_to_key __NS_SYMBOL(_ossl_old_des_string_to_key)
#endif

#ifndef asn1_enc_restore
#define asn1_enc_restore __NS_SYMBOL(asn1_enc_restore)
#endif

#ifndef i2d_CMS_bio_stream
#define i2d_CMS_bio_stream __NS_SYMBOL(i2d_CMS_bio_stream)
#endif

#ifndef s2i_ASN1_OCTET_STRING
#define s2i_ASN1_OCTET_STRING __NS_SYMBOL(s2i_ASN1_OCTET_STRING)
#endif

#ifndef ASN1_item_i2d_bio
#define ASN1_item_i2d_bio __NS_SYMBOL(ASN1_item_i2d_bio)
#endif

#ifndef BUF_strlcat
#define BUF_strlcat __NS_SYMBOL(BUF_strlcat)
#endif

#ifndef CMAC_Init
#define CMAC_Init __NS_SYMBOL(CMAC_Init)
#endif

#ifndef DES_ede3_cfb_encrypt
#define DES_ede3_cfb_encrypt __NS_SYMBOL(DES_ede3_cfb_encrypt)
#endif

#ifndef DSA_set_method
#define DSA_set_method __NS_SYMBOL(DSA_set_method)
#endif

#ifndef ENGINE_set_ciphers
#define ENGINE_set_ciphers __NS_SYMBOL(ENGINE_set_ciphers)
#endif

#ifndef ENGINE_set_digests
#define ENGINE_set_digests __NS_SYMBOL(ENGINE_set_digests)
#endif

#ifndef ENGINE_set_pkey_asn1_meths
#define ENGINE_set_pkey_asn1_meths __NS_SYMBOL(ENGINE_set_pkey_asn1_meths)
#endif

#ifndef ENGINE_set_pkey_meths
#define ENGINE_set_pkey_meths __NS_SYMBOL(ENGINE_set_pkey_meths)
#endif

#ifndef GENERAL_NAME_dup
#define GENERAL_NAME_dup __NS_SYMBOL(GENERAL_NAME_dup)
#endif

#ifndef OCSP_BASICRESP_get_ext_by_OBJ
#define OCSP_BASICRESP_get_ext_by_OBJ __NS_SYMBOL(OCSP_BASICRESP_get_ext_by_OBJ)
#endif

#ifndef OPENSSL_wipe_cpu
#define OPENSSL_wipe_cpu __NS_SYMBOL(OPENSSL_wipe_cpu)
#endif

#ifndef PEM_write_bio_X509_CRL
#define PEM_write_bio_X509_CRL __NS_SYMBOL(PEM_write_bio_X509_CRL)
#endif

#ifndef PKCS12_certbag2x509
#define PKCS12_certbag2x509 __NS_SYMBOL(PKCS12_certbag2x509)
#endif

#ifndef PKCS7_ISSUER_AND_SERIAL_new
#define PKCS7_ISSUER_AND_SERIAL_new __NS_SYMBOL(PKCS7_ISSUER_AND_SERIAL_new)
#endif

#ifndef TS_TST_INFO_set_serial
#define TS_TST_INFO_set_serial __NS_SYMBOL(TS_TST_INFO_set_serial)
#endif

#ifndef X509_get_ext_d2i
#define X509_get_ext_d2i __NS_SYMBOL(X509_get_ext_d2i)
#endif

#ifndef X509v3_delete_ext
#define X509v3_delete_ext __NS_SYMBOL(X509v3_delete_ext)
#endif

#ifndef X9_62_CHARACTERISTIC_TWO_new
#define X9_62_CHARACTERISTIC_TWO_new __NS_SYMBOL(X9_62_CHARACTERISTIC_TWO_new)
#endif

#ifndef _ossl_old_des_string_to_2keys
#define _ossl_old_des_string_to_2keys __NS_SYMBOL(_ossl_old_des_string_to_2keys)
#endif

#ifndef d2i_ASN1_NULL
#define d2i_ASN1_NULL __NS_SYMBOL(d2i_ASN1_NULL)
#endif

#ifndef d2i_GOST_CIPHER_PARAMS
#define d2i_GOST_CIPHER_PARAMS __NS_SYMBOL(d2i_GOST_CIPHER_PARAMS)
#endif

#ifndef d2i_KRB5_APREQBODY
#define d2i_KRB5_APREQBODY __NS_SYMBOL(d2i_KRB5_APREQBODY)
#endif

#ifndef d2i_OCSP_REQUEST
#define d2i_OCSP_REQUEST __NS_SYMBOL(d2i_OCSP_REQUEST)
#endif

#ifndef i2d_EXTENDED_KEY_USAGE
#define i2d_EXTENDED_KEY_USAGE __NS_SYMBOL(i2d_EXTENDED_KEY_USAGE)
#endif

#ifndef lh_strhash
#define lh_strhash __NS_SYMBOL(lh_strhash)
#endif

#ifndef ASN1_TYPE_get_int_octetstring
#define ASN1_TYPE_get_int_octetstring __NS_SYMBOL(ASN1_TYPE_get_int_octetstring)
#endif

#ifndef ASN1_UTCTIME_set
#define ASN1_UTCTIME_set __NS_SYMBOL(ASN1_UTCTIME_set)
#endif

#ifndef BASIC_CONSTRAINTS_free
#define BASIC_CONSTRAINTS_free __NS_SYMBOL(BASIC_CONSTRAINTS_free)
#endif

#ifndef BN_mod_mul
#define BN_mod_mul __NS_SYMBOL(BN_mod_mul)
#endif

#ifndef CMS_add1_ReceiptRequest
#define CMS_add1_ReceiptRequest __NS_SYMBOL(CMS_add1_ReceiptRequest)
#endif

#ifndef EVP_MD_do_all
#define EVP_MD_do_all __NS_SYMBOL(EVP_MD_do_all)
#endif

#ifndef EVP_aes_192_cfb1
#define EVP_aes_192_cfb1 __NS_SYMBOL(EVP_aes_192_cfb1)
#endif

#ifndef OCSP_id_issuer_cmp
#define OCSP_id_issuer_cmp __NS_SYMBOL(OCSP_id_issuer_cmp)
#endif

#ifndef PEM_write_bio_CMS_stream
#define PEM_write_bio_CMS_stream __NS_SYMBOL(PEM_write_bio_CMS_stream)
#endif

#ifndef POLICY_CONSTRAINTS_free
#define POLICY_CONSTRAINTS_free __NS_SYMBOL(POLICY_CONSTRAINTS_free)
#endif

#ifndef SXNETID_free
#define SXNETID_free __NS_SYMBOL(SXNETID_free)
#endif

#ifndef TS_REQ_to_TS_VERIFY_CTX
#define TS_REQ_to_TS_VERIFY_CTX __NS_SYMBOL(TS_REQ_to_TS_VERIFY_CTX)
#endif

#ifndef UI_add_input_string
#define UI_add_input_string __NS_SYMBOL(UI_add_input_string)
#endif

#ifndef X509V3_add_value_bool_nf
#define X509V3_add_value_bool_nf __NS_SYMBOL(X509V3_add_value_bool_nf)
#endif

#ifndef X509_VERIFY_PARAM_set1_policies
#define X509_VERIFY_PARAM_set1_policies __NS_SYMBOL(X509_VERIFY_PARAM_set1_policies)
#endif

#ifndef _ossl_old_des_cfb64_encrypt
#define _ossl_old_des_cfb64_encrypt __NS_SYMBOL(_ossl_old_des_cfb64_encrypt)
#endif

#ifndef engine_pkey_asn1_meths_free
#define engine_pkey_asn1_meths_free __NS_SYMBOL(engine_pkey_asn1_meths_free)
#endif

#ifndef engine_pkey_meths_free
#define engine_pkey_meths_free __NS_SYMBOL(engine_pkey_meths_free)
#endif

#ifndef i2d_TS_REQ_bio
#define i2d_TS_REQ_bio __NS_SYMBOL(i2d_TS_REQ_bio)
#endif

#ifndef ASN1_UTCTIME_adj
#define ASN1_UTCTIME_adj __NS_SYMBOL(ASN1_UTCTIME_adj)
#endif

#ifndef BIO_sock_init
#define BIO_sock_init __NS_SYMBOL(BIO_sock_init)
#endif

#ifndef CRYPTO_get_mem_functions
#define CRYPTO_get_mem_functions __NS_SYMBOL(CRYPTO_get_mem_functions)
#endif

#ifndef EC_POINT_free
#define EC_POINT_free __NS_SYMBOL(EC_POINT_free)
#endif

#ifndef EVP_CIPHER_CTX_iv_length
#define EVP_CIPHER_CTX_iv_length __NS_SYMBOL(EVP_CIPHER_CTX_iv_length)
#endif

#ifndef EVP_PKEY_verify
#define EVP_PKEY_verify __NS_SYMBOL(EVP_PKEY_verify)
#endif

#ifndef EXTENDED_KEY_USAGE_new
#define EXTENDED_KEY_USAGE_new __NS_SYMBOL(EXTENDED_KEY_USAGE_new)
#endif

#ifndef GENERAL_NAME_cmp
#define GENERAL_NAME_cmp __NS_SYMBOL(GENERAL_NAME_cmp)
#endif

#ifndef GENERAL_SUBTREE_new
#define GENERAL_SUBTREE_new __NS_SYMBOL(GENERAL_SUBTREE_new)
#endif

#ifndef OCSP_BASICRESP_get_ext_by_critical
#define OCSP_BASICRESP_get_ext_by_critical __NS_SYMBOL(OCSP_BASICRESP_get_ext_by_critical)
#endif

#ifndef PKCS12_pack_p7data
#define PKCS12_pack_p7data __NS_SYMBOL(PKCS12_pack_p7data)
#endif

#ifndef PKCS7_ISSUER_AND_SERIAL_free
#define PKCS7_ISSUER_AND_SERIAL_free __NS_SYMBOL(PKCS7_ISSUER_AND_SERIAL_free)
#endif

#ifndef RSA_set_default_method
#define RSA_set_default_method __NS_SYMBOL(RSA_set_default_method)
#endif

#ifndef TS_TST_INFO_print_bio
#define TS_TST_INFO_print_bio __NS_SYMBOL(TS_TST_INFO_print_bio)
#endif

#ifndef TS_X509_ALGOR_print_bio
#define TS_X509_ALGOR_print_bio __NS_SYMBOL(TS_X509_ALGOR_print_bio)
#endif

#ifndef X509_NAME_entry_count
#define X509_NAME_entry_count __NS_SYMBOL(X509_NAME_entry_count)
#endif

#ifndef X509_add1_ext_i2d
#define X509_add1_ext_i2d __NS_SYMBOL(X509_add1_ext_i2d)
#endif

#ifndef X509_alias_get0
#define X509_alias_get0 __NS_SYMBOL(X509_alias_get0)
#endif

#ifndef X9_62_CHARACTERISTIC_TWO_free
#define X9_62_CHARACTERISTIC_TWO_free __NS_SYMBOL(X9_62_CHARACTERISTIC_TWO_free)
#endif

#ifndef _ossl_old_des_ofb64_encrypt
#define _ossl_old_des_ofb64_encrypt __NS_SYMBOL(_ossl_old_des_ofb64_encrypt)
#endif

#ifndef d2i_X509_fp
#define d2i_X509_fp __NS_SYMBOL(d2i_X509_fp)
#endif

#ifndef i2d_ASN1_NULL
#define i2d_ASN1_NULL __NS_SYMBOL(i2d_ASN1_NULL)
#endif

#ifndef i2d_GOST_CIPHER_PARAMS
#define i2d_GOST_CIPHER_PARAMS __NS_SYMBOL(i2d_GOST_CIPHER_PARAMS)
#endif

#ifndef i2d_KRB5_APREQBODY
#define i2d_KRB5_APREQBODY __NS_SYMBOL(i2d_KRB5_APREQBODY)
#endif

#ifndef i2d_OCSP_REQUEST
#define i2d_OCSP_REQUEST __NS_SYMBOL(i2d_OCSP_REQUEST)
#endif

#ifndef pkey_GOST94cp_encrypt
#define pkey_GOST94cp_encrypt __NS_SYMBOL(pkey_GOST94cp_encrypt)
#endif

#ifndef policy_node_free
#define policy_node_free __NS_SYMBOL(policy_node_free)
#endif

#ifndef sk_new_null
#define sk_new_null __NS_SYMBOL(sk_new_null)
#endif

#ifndef ASN1_put_object
#define ASN1_put_object __NS_SYMBOL(ASN1_put_object)
#endif

#ifndef BIO_gethostbyname
#define BIO_gethostbyname __NS_SYMBOL(BIO_gethostbyname)
#endif

#ifndef BN_CTX_free
#define BN_CTX_free __NS_SYMBOL(BN_CTX_free)
#endif

#ifndef CRYPTO_ccm128_encrypt
#define CRYPTO_ccm128_encrypt __NS_SYMBOL(CRYPTO_ccm128_encrypt)
#endif

#ifndef CRYPTO_dbg_set_options
#define CRYPTO_dbg_set_options __NS_SYMBOL(CRYPTO_dbg_set_options)
#endif

#ifndef EVP_CIPHER_type
#define EVP_CIPHER_type __NS_SYMBOL(EVP_CIPHER_type)
#endif

#ifndef EVP_PKEY_meth_free
#define EVP_PKEY_meth_free __NS_SYMBOL(EVP_PKEY_meth_free)
#endif

#ifndef NCONF_load_bio
#define NCONF_load_bio __NS_SYMBOL(NCONF_load_bio)
#endif

#ifndef PEM_SealUpdate
#define PEM_SealUpdate __NS_SYMBOL(PEM_SealUpdate)
#endif

#ifndef PKCS5_pbe_set
#define PKCS5_pbe_set __NS_SYMBOL(PKCS5_pbe_set)
#endif

#ifndef RSA_get_default_method
#define RSA_get_default_method __NS_SYMBOL(RSA_get_default_method)
#endif

#ifndef SMIME_write_CMS
#define SMIME_write_CMS __NS_SYMBOL(SMIME_write_CMS)
#endif

#ifndef TS_CONF_set_serial
#define TS_CONF_set_serial __NS_SYMBOL(TS_CONF_set_serial)
#endif

#ifndef TS_REQ_get_nonce
#define TS_REQ_get_nonce __NS_SYMBOL(TS_REQ_get_nonce)
#endif

#ifndef X509_CRL_verify
#define X509_CRL_verify __NS_SYMBOL(X509_CRL_verify)
#endif

#ifndef X509_REQ_extension_nid
#define X509_REQ_extension_nid __NS_SYMBOL(X509_REQ_extension_nid)
#endif

#ifndef X509_issuer_name_cmp
#define X509_issuer_name_cmp __NS_SYMBOL(X509_issuer_name_cmp)
#endif

#ifndef cms_SignerIdentifier_cert_cmp
#define cms_SignerIdentifier_cert_cmp __NS_SYMBOL(cms_SignerIdentifier_cert_cmp)
#endif

#ifndef cms_content_bio
#define cms_content_bio __NS_SYMBOL(cms_content_bio)
#endif

#ifndef d2i_SXNET
#define d2i_SXNET __NS_SYMBOL(d2i_SXNET)
#endif

#ifndef d2i_TS_REQ_fp
#define d2i_TS_REQ_fp __NS_SYMBOL(d2i_TS_REQ_fp)
#endif

#ifndef i2s_ASN1_ENUMERATED
#define i2s_ASN1_ENUMERATED __NS_SYMBOL(i2s_ASN1_ENUMERATED)
#endif

#ifndef policy_node_match
#define policy_node_match __NS_SYMBOL(policy_node_match)
#endif

#ifndef ASN1_NULL_new
#define ASN1_NULL_new __NS_SYMBOL(ASN1_NULL_new)
#endif

#ifndef BIO_get_port
#define BIO_get_port __NS_SYMBOL(BIO_get_port)
#endif

#ifndef BIO_nwrite0
#define BIO_nwrite0 __NS_SYMBOL(BIO_nwrite0)
#endif

#ifndef BN_sub_word
#define BN_sub_word __NS_SYMBOL(BN_sub_word)
#endif

#ifndef CRYPTO_cts128_encrypt
#define CRYPTO_cts128_encrypt __NS_SYMBOL(CRYPTO_cts128_encrypt)
#endif

#ifndef CRYPTO_dbg_get_options
#define CRYPTO_dbg_get_options __NS_SYMBOL(CRYPTO_dbg_get_options)
#endif

#ifndef ECPARAMETERS_new
#define ECPARAMETERS_new __NS_SYMBOL(ECPARAMETERS_new)
#endif

#ifndef EVP_aes_192_cfb8
#define EVP_aes_192_cfb8 __NS_SYMBOL(EVP_aes_192_cfb8)
#endif

#ifndef EXTENDED_KEY_USAGE_free
#define EXTENDED_KEY_USAGE_free __NS_SYMBOL(EXTENDED_KEY_USAGE_free)
#endif

#ifndef GENERAL_SUBTREE_free
#define GENERAL_SUBTREE_free __NS_SYMBOL(GENERAL_SUBTREE_free)
#endif

#ifndef GOST_CIPHER_PARAMS_new
#define GOST_CIPHER_PARAMS_new __NS_SYMBOL(GOST_CIPHER_PARAMS_new)
#endif

#ifndef KRB5_APREQBODY_new
#define KRB5_APREQBODY_new __NS_SYMBOL(KRB5_APREQBODY_new)
#endif

#ifndef OCSP_BASICRESP_get_ext
#define OCSP_BASICRESP_get_ext __NS_SYMBOL(OCSP_BASICRESP_get_ext)
#endif

#ifndef OCSP_REQUEST_new
#define OCSP_REQUEST_new __NS_SYMBOL(OCSP_REQUEST_new)
#endif

#ifndef PEM_ASN1_read
#define PEM_ASN1_read __NS_SYMBOL(PEM_ASN1_read)
#endif

#ifndef PKCS12_verify_mac
#define PKCS12_verify_mac __NS_SYMBOL(PKCS12_verify_mac)
#endif

#ifndef PKCS7_add0_attrib_signing_time
#define PKCS7_add0_attrib_signing_time __NS_SYMBOL(PKCS7_add0_attrib_signing_time)
#endif

#ifndef RAND_add
#define RAND_add __NS_SYMBOL(RAND_add)
#endif

#ifndef SHA256_Update
#define SHA256_Update __NS_SYMBOL(SHA256_Update)
#endif

#ifndef TS_REQ_set_cert_req
#define TS_REQ_set_cert_req __NS_SYMBOL(TS_REQ_set_cert_req)
#endif

#ifndef X509_NAME_get_index_by_NID
#define X509_NAME_get_index_by_NID __NS_SYMBOL(X509_NAME_get_index_by_NID)
#endif

#ifndef X509_REVOKED_get_ext_count
#define X509_REVOKED_get_ext_count __NS_SYMBOL(X509_REVOKED_get_ext_count)
#endif

#ifndef X509v3_add_ext
#define X509v3_add_ext __NS_SYMBOL(X509v3_add_ext)
#endif

#ifndef bn_sqr_normal
#define bn_sqr_normal __NS_SYMBOL(bn_sqr_normal)
#endif

#ifndef d2i_ASN1_bytes
#define d2i_ASN1_bytes __NS_SYMBOL(d2i_ASN1_bytes)
#endif

#ifndef d2i_PKCS7_ENVELOPE
#define d2i_PKCS7_ENVELOPE __NS_SYMBOL(d2i_PKCS7_ENVELOPE)
#endif

#ifndef engine_cleanup_add_last
#define engine_cleanup_add_last __NS_SYMBOL(engine_cleanup_add_last)
#endif

#ifndef i2d_X509_fp
#define i2d_X509_fp __NS_SYMBOL(i2d_X509_fp)
#endif

#ifndef int_rsa_verify
#define int_rsa_verify __NS_SYMBOL(int_rsa_verify)
#endif

#ifndef pqueue_iterator
#define pqueue_iterator __NS_SYMBOL(pqueue_iterator)
#endif

#ifndef BIO_vfree
#define BIO_vfree __NS_SYMBOL(BIO_vfree)
#endif

#ifndef BN_free
#define BN_free __NS_SYMBOL(BN_free)
#endif

#ifndef CMS_data_create
#define CMS_data_create __NS_SYMBOL(CMS_data_create)
#endif

#ifndef CRYPTO_push_info_
#define CRYPTO_push_info_ __NS_SYMBOL(CRYPTO_push_info_)
#endif

#ifndef EVP_PKEY_CTX_new
#define EVP_PKEY_CTX_new __NS_SYMBOL(EVP_PKEY_CTX_new)
#endif

#ifndef PEM_write_X509_CRL
#define PEM_write_X509_CRL __NS_SYMBOL(PEM_write_X509_CRL)
#endif

#ifndef PKCS12_certbag2x509crl
#define PKCS12_certbag2x509crl __NS_SYMBOL(PKCS12_certbag2x509crl)
#endif

#ifndef RSA_get_method
#define RSA_get_method __NS_SYMBOL(RSA_get_method)
#endif

#ifndef X509_CRL_get0_by_serial
#define X509_CRL_get0_by_serial __NS_SYMBOL(X509_CRL_get0_by_serial)
#endif

#ifndef X509_PKEY_new
#define X509_PKEY_new __NS_SYMBOL(X509_PKEY_new)
#endif

#ifndef X509_REVOKED_get_ext_by_NID
#define X509_REVOKED_get_ext_by_NID __NS_SYMBOL(X509_REVOKED_get_ext_by_NID)
#endif

#ifndef X509_keyid_get0
#define X509_keyid_get0 __NS_SYMBOL(X509_keyid_get0)
#endif

#ifndef hashsum2bn
#define hashsum2bn __NS_SYMBOL(hashsum2bn)
#endif

#ifndef i2d_SXNET
#define i2d_SXNET __NS_SYMBOL(i2d_SXNET)
#endif

#ifndef pqueue_next
#define pqueue_next __NS_SYMBOL(pqueue_next)
#endif

#ifndef ASN1_NULL_free
#define ASN1_NULL_free __NS_SYMBOL(ASN1_NULL_free)
#endif

#ifndef ASN1_STRING_TABLE_add
#define ASN1_STRING_TABLE_add __NS_SYMBOL(ASN1_STRING_TABLE_add)
#endif

#ifndef CRYPTO_new_ex_data
#define CRYPTO_new_ex_data __NS_SYMBOL(CRYPTO_new_ex_data)
#endif

#ifndef DSA_free
#define DSA_free __NS_SYMBOL(DSA_free)
#endif

#ifndef ECPARAMETERS_free
#define ECPARAMETERS_free __NS_SYMBOL(ECPARAMETERS_free)
#endif

#ifndef EC_GROUP_clear_free
#define EC_GROUP_clear_free __NS_SYMBOL(EC_GROUP_clear_free)
#endif

#ifndef GOST_CIPHER_PARAMS_free
#define GOST_CIPHER_PARAMS_free __NS_SYMBOL(GOST_CIPHER_PARAMS_free)
#endif

#ifndef KRB5_APREQBODY_free
#define KRB5_APREQBODY_free __NS_SYMBOL(KRB5_APREQBODY_free)
#endif

#ifndef MD5_Init
#define MD5_Init __NS_SYMBOL(MD5_Init)
#endif

#ifndef NAME_CONSTRAINTS_new
#define NAME_CONSTRAINTS_new __NS_SYMBOL(NAME_CONSTRAINTS_new)
#endif

#ifndef OCSP_BASICRESP_delete_ext
#define OCSP_BASICRESP_delete_ext __NS_SYMBOL(OCSP_BASICRESP_delete_ext)
#endif

#ifndef OCSP_REQUEST_free
#define OCSP_REQUEST_free __NS_SYMBOL(OCSP_REQUEST_free)
#endif

#ifndef OCSP_id_cmp
#define OCSP_id_cmp __NS_SYMBOL(OCSP_id_cmp)
#endif

#ifndef PEM_write_bio_ASN1_stream
#define PEM_write_bio_ASN1_stream __NS_SYMBOL(PEM_write_bio_ASN1_stream)
#endif

#ifndef RSA_set_method
#define RSA_set_method __NS_SYMBOL(RSA_set_method)
#endif

#ifndef TS_MSG_IMPRINT_print_bio
#define TS_MSG_IMPRINT_print_bio __NS_SYMBOL(TS_MSG_IMPRINT_print_bio)
#endif

#ifndef TS_REQ_get_cert_req
#define TS_REQ_get_cert_req __NS_SYMBOL(TS_REQ_get_cert_req)
#endif

#ifndef X509_REVOKED_get_ext_by_OBJ
#define X509_REVOKED_get_ext_by_OBJ __NS_SYMBOL(X509_REVOKED_get_ext_by_OBJ)
#endif

#ifndef d2i_X509_bio
#define d2i_X509_bio __NS_SYMBOL(d2i_X509_bio)
#endif

#ifndef ec_GFp_nist_field_sqr
#define ec_GFp_nist_field_sqr __NS_SYMBOL(ec_GFp_nist_field_sqr)
#endif

#ifndef i2d_PKCS7_ENVELOPE
#define i2d_PKCS7_ENVELOPE __NS_SYMBOL(i2d_PKCS7_ENVELOPE)
#endif

#ifndef i2d_TS_REQ_fp
#define i2d_TS_REQ_fp __NS_SYMBOL(i2d_TS_REQ_fp)
#endif

#ifndef ASN1_GENERALIZEDTIME_set
#define ASN1_GENERALIZEDTIME_set __NS_SYMBOL(ASN1_GENERALIZEDTIME_set)
#endif

#ifndef BN_pseudo_rand
#define BN_pseudo_rand __NS_SYMBOL(BN_pseudo_rand)
#endif

#ifndef CONF_get_section
#define CONF_get_section __NS_SYMBOL(CONF_get_section)
#endif

#ifndef DSO_flags
#define DSO_flags __NS_SYMBOL(DSO_flags)
#endif

#ifndef ECDH_get_ex_new_index
#define ECDH_get_ex_new_index __NS_SYMBOL(ECDH_get_ex_new_index)
#endif

#ifndef ECDSA_size
#define ECDSA_size __NS_SYMBOL(ECDSA_size)
#endif

#ifndef EVP_MD_do_all_sorted
#define EVP_MD_do_all_sorted __NS_SYMBOL(EVP_MD_do_all_sorted)
#endif

#ifndef EVP_PBE_find
#define EVP_PBE_find __NS_SYMBOL(EVP_PBE_find)
#endif

#ifndef EVP_aes_192_ctr
#define EVP_aes_192_ctr __NS_SYMBOL(EVP_aes_192_ctr)
#endif

#ifndef OBJ_sigid_free
#define OBJ_sigid_free __NS_SYMBOL(OBJ_sigid_free)
#endif

#ifndef OPENSSL_ia32_rdrand
#define OPENSSL_ia32_rdrand __NS_SYMBOL(OPENSSL_ia32_rdrand)
#endif

#ifndef PEM_write_bio_PrivateKey
#define PEM_write_bio_PrivateKey __NS_SYMBOL(PEM_write_bio_PrivateKey)
#endif

#ifndef PKCS8_set_broken
#define PKCS8_set_broken __NS_SYMBOL(PKCS8_set_broken)
#endif

#ifndef SXNET_new
#define SXNET_new __NS_SYMBOL(SXNET_new)
#endif

#ifndef TS_REQ_get_exts
#define TS_REQ_get_exts __NS_SYMBOL(TS_REQ_get_exts)
#endif

#ifndef TS_RESP_CTX_free
#define TS_RESP_CTX_free __NS_SYMBOL(TS_RESP_CTX_free)
#endif

#ifndef TS_TST_INFO_get_serial
#define TS_TST_INFO_get_serial __NS_SYMBOL(TS_TST_INFO_get_serial)
#endif

#ifndef X509V3_EXT_add_alias
#define X509V3_EXT_add_alias __NS_SYMBOL(X509V3_EXT_add_alias)
#endif

#ifndef X509_CRL_get0_by_cert
#define X509_CRL_get0_by_cert __NS_SYMBOL(X509_CRL_get0_by_cert)
#endif

#ifndef X509_REQ_get_extension_nids
#define X509_REQ_get_extension_nids __NS_SYMBOL(X509_REQ_get_extension_nids)
#endif

#ifndef X509_REVOKED_get_ext_by_critical
#define X509_REVOKED_get_ext_by_critical __NS_SYMBOL(X509_REVOKED_get_ext_by_critical)
#endif

#ifndef asn1_get_field_ptr
#define asn1_get_field_ptr __NS_SYMBOL(asn1_get_field_ptr)
#endif

#ifndef c2i_ASN1_INTEGER
#define c2i_ASN1_INTEGER __NS_SYMBOL(c2i_ASN1_INTEGER)
#endif

#ifndef lh_node_stats_bio
#define lh_node_stats_bio __NS_SYMBOL(lh_node_stats_bio)
#endif

#ifndef ASN1_GENERALIZEDTIME_adj
#define ASN1_GENERALIZEDTIME_adj __NS_SYMBOL(ASN1_GENERALIZEDTIME_adj)
#endif

#ifndef CRYPTO_get_mem_ex_functions
#define CRYPTO_get_mem_ex_functions __NS_SYMBOL(CRYPTO_get_mem_ex_functions)
#endif

#ifndef DH_free
#define DH_free __NS_SYMBOL(DH_free)
#endif

#ifndef DSO_up_ref
#define DSO_up_ref __NS_SYMBOL(DSO_up_ref)
#endif

#ifndef EVP_PKEY_set_type
#define EVP_PKEY_set_type __NS_SYMBOL(EVP_PKEY_set_type)
#endif

#ifndef NAME_CONSTRAINTS_free
#define NAME_CONSTRAINTS_free __NS_SYMBOL(NAME_CONSTRAINTS_free)
#endif

#ifndef OCSP_BASICRESP_get1_ext_d2i
#define OCSP_BASICRESP_get1_ext_d2i __NS_SYMBOL(OCSP_BASICRESP_get1_ext_d2i)
#endif

#ifndef PKCS7_ENVELOPE_new
#define PKCS7_ENVELOPE_new __NS_SYMBOL(PKCS7_ENVELOPE_new)
#endif

#ifndef SHA1_Init
#define SHA1_Init __NS_SYMBOL(SHA1_Init)
#endif

#ifndef TS_REQ_ext_free
#define TS_REQ_ext_free __NS_SYMBOL(TS_REQ_ext_free)
#endif

#ifndef TS_TST_INFO_set_time
#define TS_TST_INFO_set_time __NS_SYMBOL(TS_TST_INFO_set_time)
#endif

#ifndef X509_REQ_set_extension_nids
#define X509_REQ_set_extension_nids __NS_SYMBOL(X509_REQ_set_extension_nids)
#endif

#ifndef X509_REVOKED_get_ext
#define X509_REVOKED_get_ext __NS_SYMBOL(X509_REVOKED_get_ext)
#endif

#ifndef X509_add1_trust_object
#define X509_add1_trust_object __NS_SYMBOL(X509_add1_trust_object)
#endif

#ifndef X509_load_crl_file
#define X509_load_crl_file __NS_SYMBOL(X509_load_crl_file)
#endif

#ifndef d2i_ASN1_UTF8STRING
#define d2i_ASN1_UTF8STRING __NS_SYMBOL(d2i_ASN1_UTF8STRING)
#endif

#ifndef d2i_ECPKPARAMETERS
#define d2i_ECPKPARAMETERS __NS_SYMBOL(d2i_ECPKPARAMETERS)
#endif

#ifndef d2i_GOST_CLIENT_KEY_EXCHANGE_PARAMS
#define d2i_GOST_CLIENT_KEY_EXCHANGE_PARAMS __NS_SYMBOL(d2i_GOST_CLIENT_KEY_EXCHANGE_PARAMS)
#endif

#ifndef d2i_KRB5_APREQ
#define d2i_KRB5_APREQ __NS_SYMBOL(d2i_KRB5_APREQ)
#endif

#ifndef d2i_OCSP_RESPBYTES
#define d2i_OCSP_RESPBYTES __NS_SYMBOL(d2i_OCSP_RESPBYTES)
#endif

#ifndef d2i_TS_ACCURACY
#define d2i_TS_ACCURACY __NS_SYMBOL(d2i_TS_ACCURACY)
#endif

#ifndef i2d_X509_bio
#define i2d_X509_bio __NS_SYMBOL(i2d_X509_bio)
#endif

#ifndef lh_free
#define lh_free __NS_SYMBOL(lh_free)
#endif

#ifndef pqueue_size
#define pqueue_size __NS_SYMBOL(pqueue_size)
#endif

#ifndef BN_bntest_rand
#define BN_bntest_rand __NS_SYMBOL(BN_bntest_rand)
#endif

#ifndef ENGINE_get_pkey_asn1_meth_str
#define ENGINE_get_pkey_asn1_meth_str __NS_SYMBOL(ENGINE_get_pkey_asn1_meth_str)
#endif

#ifndef EVP_EncodeFinal
#define EVP_EncodeFinal __NS_SYMBOL(EVP_EncodeFinal)
#endif

#ifndef EVP_PKEY_asn1_add0
#define EVP_PKEY_asn1_add0 __NS_SYMBOL(EVP_PKEY_asn1_add0)
#endif

#ifndef HMAC_Init
#define HMAC_Init __NS_SYMBOL(HMAC_Init)
#endif

#ifndef OBJ_NAME_get
#define OBJ_NAME_get __NS_SYMBOL(OBJ_NAME_get)
#endif

#ifndef SXNET_free
#define SXNET_free __NS_SYMBOL(SXNET_free)
#endif

#ifndef X509_REQ_get_extensions
#define X509_REQ_get_extensions __NS_SYMBOL(X509_REQ_get_extensions)
#endif

#ifndef X509_REVOKED_delete_ext
#define X509_REVOKED_delete_ext __NS_SYMBOL(X509_REVOKED_delete_ext)
#endif

#ifndef asn1_do_adb
#define asn1_do_adb __NS_SYMBOL(asn1_do_adb)
#endif

#ifndef bn_sqr_words
#define bn_sqr_words __NS_SYMBOL(bn_sqr_words)
#endif

#ifndef ec_GF2m_simple_group_set_curve
#define ec_GF2m_simple_group_set_curve __NS_SYMBOL(ec_GF2m_simple_group_set_curve)
#endif

#ifndef ASN1_ENUMERATED_to_BN
#define ASN1_ENUMERATED_to_BN __NS_SYMBOL(ASN1_ENUMERATED_to_BN)
#endif

#ifndef BIO_nwrite
#define BIO_nwrite __NS_SYMBOL(BIO_nwrite)
#endif

#ifndef BN_init
#define BN_init __NS_SYMBOL(BN_init)
#endif

#ifndef BN_uadd
#define BN_uadd __NS_SYMBOL(BN_uadd)
#endif

#ifndef CMS_ReceiptRequest_get0_values
#define CMS_ReceiptRequest_get0_values __NS_SYMBOL(CMS_ReceiptRequest_get0_values)
#endif

#ifndef ECDH_set_ex_data
#define ECDH_set_ex_data __NS_SYMBOL(ECDH_set_ex_data)
#endif

#ifndef EC_POINT_hex2point
#define EC_POINT_hex2point __NS_SYMBOL(EC_POINT_hex2point)
#endif

#ifndef ENGINE_cleanup
#define ENGINE_cleanup __NS_SYMBOL(ENGINE_cleanup)
#endif

#ifndef EVP_PKEY_CTX_set_cb
#define EVP_PKEY_CTX_set_cb __NS_SYMBOL(EVP_PKEY_CTX_set_cb)
#endif

#ifndef EVP_PKEY_verify_recover_init
#define EVP_PKEY_verify_recover_init __NS_SYMBOL(EVP_PKEY_verify_recover_init)
#endif

#ifndef EVP_aes_256_cbc
#define EVP_aes_256_cbc __NS_SYMBOL(EVP_aes_256_cbc)
#endif

#ifndef NAME_CONSTRAINTS_check
#define NAME_CONSTRAINTS_check __NS_SYMBOL(NAME_CONSTRAINTS_check)
#endif

#ifndef OCSP_BASICRESP_add1_ext_i2d
#define OCSP_BASICRESP_add1_ext_i2d __NS_SYMBOL(OCSP_BASICRESP_add1_ext_i2d)
#endif

#ifndef PEM_read_bio_PKCS7
#define PEM_read_bio_PKCS7 __NS_SYMBOL(PEM_read_bio_PKCS7)
#endif

#ifndef PEM_write_bio_PKCS8PrivateKey
#define PEM_write_bio_PKCS8PrivateKey __NS_SYMBOL(PEM_write_bio_PKCS8PrivateKey)
#endif

#ifndef PKCS7_ENVELOPE_free
#define PKCS7_ENVELOPE_free __NS_SYMBOL(PKCS7_ENVELOPE_free)
#endif

#ifndef TS_CONF_set_crypto_device
#define TS_CONF_set_crypto_device __NS_SYMBOL(TS_CONF_set_crypto_device)
#endif

#ifndef X509_REVOKED_add_ext
#define X509_REVOKED_add_ext __NS_SYMBOL(X509_REVOKED_add_ext)
#endif

#ifndef X509at_add1_attr_by_OBJ
#define X509at_add1_attr_by_OBJ __NS_SYMBOL(X509at_add1_attr_by_OBJ)
#endif

#ifndef d2i_X509_CRL_fp
#define d2i_X509_CRL_fp __NS_SYMBOL(d2i_X509_CRL_fp)
#endif

#ifndef i2d_ASN1_UTF8STRING
#define i2d_ASN1_UTF8STRING __NS_SYMBOL(i2d_ASN1_UTF8STRING)
#endif

#ifndef i2d_ECPKPARAMETERS
#define i2d_ECPKPARAMETERS __NS_SYMBOL(i2d_ECPKPARAMETERS)
#endif

#ifndef i2d_GOST_CLIENT_KEY_EXCHANGE_PARAMS
#define i2d_GOST_CLIENT_KEY_EXCHANGE_PARAMS __NS_SYMBOL(i2d_GOST_CLIENT_KEY_EXCHANGE_PARAMS)
#endif

#ifndef i2d_KRB5_APREQ
#define i2d_KRB5_APREQ __NS_SYMBOL(i2d_KRB5_APREQ)
#endif

#ifndef i2d_OCSP_RESPBYTES
#define i2d_OCSP_RESPBYTES __NS_SYMBOL(i2d_OCSP_RESPBYTES)
#endif

#ifndef i2d_TS_ACCURACY
#define i2d_TS_ACCURACY __NS_SYMBOL(i2d_TS_ACCURACY)
#endif

#ifndef i2s_ASN1_INTEGER
#define i2s_ASN1_INTEGER __NS_SYMBOL(i2s_ASN1_INTEGER)
#endif

#ifndef ASN1_item_sign
#define ASN1_item_sign __NS_SYMBOL(ASN1_item_sign)
#endif

#ifndef BN_rand_range
#define BN_rand_range __NS_SYMBOL(BN_rand_range)
#endif

#ifndef BUF_reverse
#define BUF_reverse __NS_SYMBOL(BUF_reverse)
#endif

#ifndef CMS_final
#define CMS_final __NS_SYMBOL(CMS_final)
#endif

#ifndef CRYPTO_gcm128_setiv
#define CRYPTO_gcm128_setiv __NS_SYMBOL(CRYPTO_gcm128_setiv)
#endif

#ifndef EVP_PKEY_CTX_get_cb
#define EVP_PKEY_CTX_get_cb __NS_SYMBOL(EVP_PKEY_CTX_get_cb)
#endif

#ifndef OCSP_sendreq_nbio
#define OCSP_sendreq_nbio __NS_SYMBOL(OCSP_sendreq_nbio)
#endif

#ifndef PKCS12_item_i2d_encrypt
#define PKCS12_item_i2d_encrypt __NS_SYMBOL(PKCS12_item_i2d_encrypt)
#endif

#ifndef PKCS7_add1_attrib_digest
#define PKCS7_add1_attrib_digest __NS_SYMBOL(PKCS7_add1_attrib_digest)
#endif

#ifndef POLICY_MAPPING_new
#define POLICY_MAPPING_new __NS_SYMBOL(POLICY_MAPPING_new)
#endif

#ifndef RSA_padding_check_PKCS1_type_2
#define RSA_padding_check_PKCS1_type_2 __NS_SYMBOL(RSA_padding_check_PKCS1_type_2)
#endif

#ifndef SMIME_read_CMS
#define SMIME_read_CMS __NS_SYMBOL(SMIME_read_CMS)
#endif

#ifndef SXNET_add_id_asc
#define SXNET_add_id_asc __NS_SYMBOL(SXNET_add_id_asc)
#endif

#ifndef TS_REQ_get_ext_count
#define TS_REQ_get_ext_count __NS_SYMBOL(TS_REQ_get_ext_count)
#endif

#ifndef ASN1_UTF8STRING_new
#define ASN1_UTF8STRING_new __NS_SYMBOL(ASN1_UTF8STRING_new)
#endif

#ifndef ASN1_item_pack
#define ASN1_item_pack __NS_SYMBOL(ASN1_item_pack)
#endif

#ifndef BN_BLINDING_create_param
#define BN_BLINDING_create_param __NS_SYMBOL(BN_BLINDING_create_param)
#endif

#ifndef BN_new
#define BN_new __NS_SYMBOL(BN_new)
#endif

#ifndef ECPKPARAMETERS_new
#define ECPKPARAMETERS_new __NS_SYMBOL(ECPKPARAMETERS_new)
#endif

#ifndef EVP_DigestUpdate
#define EVP_DigestUpdate __NS_SYMBOL(EVP_DigestUpdate)
#endif

#ifndef EVP_PKEY_get_attr_count
#define EVP_PKEY_get_attr_count __NS_SYMBOL(EVP_PKEY_get_attr_count)
#endif

#ifndef GOST_CLIENT_KEY_EXCHANGE_PARAMS_new
#define GOST_CLIENT_KEY_EXCHANGE_PARAMS_new __NS_SYMBOL(GOST_CLIENT_KEY_EXCHANGE_PARAMS_new)
#endif

#ifndef KRB5_APREQ_new
#define KRB5_APREQ_new __NS_SYMBOL(KRB5_APREQ_new)
#endif

#ifndef OCSP_BASICRESP_add_ext
#define OCSP_BASICRESP_add_ext __NS_SYMBOL(OCSP_BASICRESP_add_ext)
#endif

#ifndef OCSP_RESPBYTES_new
#define OCSP_RESPBYTES_new __NS_SYMBOL(OCSP_RESPBYTES_new)
#endif

#ifndef OCSP_parse_url
#define OCSP_parse_url __NS_SYMBOL(OCSP_parse_url)
#endif

#ifndef RAND_file_name
#define RAND_file_name __NS_SYMBOL(RAND_file_name)
#endif

#ifndef RSA_free
#define RSA_free __NS_SYMBOL(RSA_free)
#endif

#ifndef TS_ACCURACY_new
#define TS_ACCURACY_new __NS_SYMBOL(TS_ACCURACY_new)
#endif

#ifndef TS_REQ_get_ext_by_NID
#define TS_REQ_get_ext_by_NID __NS_SYMBOL(TS_REQ_get_ext_by_NID)
#endif

#ifndef X509_REVOKED_get_ext_d2i
#define X509_REVOKED_get_ext_d2i __NS_SYMBOL(X509_REVOKED_get_ext_d2i)
#endif

#ifndef X509_subject_name_cmp
#define X509_subject_name_cmp __NS_SYMBOL(X509_subject_name_cmp)
#endif

#ifndef _CONF_free_data
#define _CONF_free_data __NS_SYMBOL(_CONF_free_data)
#endif

#ifndef b2i_PublicKey_bio
#define b2i_PublicKey_bio __NS_SYMBOL(b2i_PublicKey_bio)
#endif

#ifndef bn_add_part_words
#define bn_add_part_words __NS_SYMBOL(bn_add_part_words)
#endif

#ifndef d2i_PKCS7_RECIP_INFO
#define d2i_PKCS7_RECIP_INFO __NS_SYMBOL(d2i_PKCS7_RECIP_INFO)
#endif

#ifndef ec_GF2m_simple_point2oct
#define ec_GF2m_simple_point2oct __NS_SYMBOL(ec_GF2m_simple_point2oct)
#endif

#ifndef engine_table_unregister
#define engine_table_unregister __NS_SYMBOL(engine_table_unregister)
#endif

#ifndef evp_pkey_set_cb_translate
#define evp_pkey_set_cb_translate __NS_SYMBOL(evp_pkey_set_cb_translate)
#endif

#ifndef i2d_X509_CRL_fp
#define i2d_X509_CRL_fp __NS_SYMBOL(i2d_X509_CRL_fp)
#endif

#ifndef ASN1_TIME_set_string
#define ASN1_TIME_set_string __NS_SYMBOL(ASN1_TIME_set_string)
#endif

#ifndef EVP_DigestFinal
#define EVP_DigestFinal __NS_SYMBOL(EVP_DigestFinal)
#endif

#ifndef EVP_DigestVerifyFinal
#define EVP_DigestVerifyFinal __NS_SYMBOL(EVP_DigestVerifyFinal)
#endif

#ifndef EVP_PKEY_get_attr_by_NID
#define EVP_PKEY_get_attr_by_NID __NS_SYMBOL(EVP_PKEY_get_attr_by_NID)
#endif

#ifndef EVP_aes_256_ecb
#define EVP_aes_256_ecb __NS_SYMBOL(EVP_aes_256_ecb)
#endif

#ifndef OCSP_basic_add1_cert
#define OCSP_basic_add1_cert __NS_SYMBOL(OCSP_basic_add1_cert)
#endif

#ifndef PEM_read_PKCS7
#define PEM_read_PKCS7 __NS_SYMBOL(PEM_read_PKCS7)
#endif

#ifndef POLICY_MAPPING_free
#define POLICY_MAPPING_free __NS_SYMBOL(POLICY_MAPPING_free)
#endif

#ifndef SRP_Calc_B
#define SRP_Calc_B __NS_SYMBOL(SRP_Calc_B)
#endif

#ifndef TS_REQ_get_ext_by_OBJ
#define TS_REQ_get_ext_by_OBJ __NS_SYMBOL(TS_REQ_get_ext_by_OBJ)
#endif

#ifndef X509_NAME_delete_entry
#define X509_NAME_delete_entry __NS_SYMBOL(X509_NAME_delete_entry)
#endif

#ifndef X509_REVOKED_add1_ext_i2d
#define X509_REVOKED_add1_ext_i2d __NS_SYMBOL(X509_REVOKED_add1_ext_i2d)
#endif

#ifndef bn_GF2m_mul_2x2
#define bn_GF2m_mul_2x2 __NS_SYMBOL(bn_GF2m_mul_2x2)
#endif

#ifndef i2b_PrivateKey_bio
#define i2b_PrivateKey_bio __NS_SYMBOL(i2b_PrivateKey_bio)
#endif

#ifndef sk_insert
#define sk_insert __NS_SYMBOL(sk_insert)
#endif

#ifndef ASN1_UTF8STRING_free
#define ASN1_UTF8STRING_free __NS_SYMBOL(ASN1_UTF8STRING_free)
#endif

#ifndef BIO_clear_flags
#define BIO_clear_flags __NS_SYMBOL(BIO_clear_flags)
#endif

#ifndef CMS_add1_signer
#define CMS_add1_signer __NS_SYMBOL(CMS_add1_signer)
#endif

#ifndef CRYPTO_cfb128_1_encrypt
#define CRYPTO_cfb128_1_encrypt __NS_SYMBOL(CRYPTO_cfb128_1_encrypt)
#endif

#ifndef CRYPTO_get_locked_mem_functions
#define CRYPTO_get_locked_mem_functions __NS_SYMBOL(CRYPTO_get_locked_mem_functions)
#endif

#ifndef CRYPTO_lock
#define CRYPTO_lock __NS_SYMBOL(CRYPTO_lock)
#endif

#ifndef DSO_load
#define DSO_load __NS_SYMBOL(DSO_load)
#endif

#ifndef ECDH_get_ex_data
#define ECDH_get_ex_data __NS_SYMBOL(ECDH_get_ex_data)
#endif

#ifndef ECPKPARAMETERS_free
#define ECPKPARAMETERS_free __NS_SYMBOL(ECPKPARAMETERS_free)
#endif

#ifndef EVP_DecodeInit
#define EVP_DecodeInit __NS_SYMBOL(EVP_DecodeInit)
#endif

#ifndef EVP_PKEY_get_attr_by_OBJ
#define EVP_PKEY_get_attr_by_OBJ __NS_SYMBOL(EVP_PKEY_get_attr_by_OBJ)
#endif

#ifndef GOST_CLIENT_KEY_EXCHANGE_PARAMS_free
#define GOST_CLIENT_KEY_EXCHANGE_PARAMS_free __NS_SYMBOL(GOST_CLIENT_KEY_EXCHANGE_PARAMS_free)
#endif

#ifndef KRB5_APREQ_free
#define KRB5_APREQ_free __NS_SYMBOL(KRB5_APREQ_free)
#endif

#ifndef OCSP_RESPBYTES_free
#define OCSP_RESPBYTES_free __NS_SYMBOL(OCSP_RESPBYTES_free)
#endif

#ifndef OCSP_SINGLERESP_get_ext_count
#define OCSP_SINGLERESP_get_ext_count __NS_SYMBOL(OCSP_SINGLERESP_get_ext_count)
#endif

#ifndef PKCS12_unpack_p7data
#define PKCS12_unpack_p7data __NS_SYMBOL(PKCS12_unpack_p7data)
#endif

#ifndef RAND_bytes
#define RAND_bytes __NS_SYMBOL(RAND_bytes)
#endif

#ifndef TS_ACCURACY_free
#define TS_ACCURACY_free __NS_SYMBOL(TS_ACCURACY_free)
#endif

#ifndef TS_REQ_get_ext_by_critical
#define TS_REQ_get_ext_by_critical __NS_SYMBOL(TS_REQ_get_ext_by_critical)
#endif

#ifndef X509_CRL_set_default_method
#define X509_CRL_set_default_method __NS_SYMBOL(X509_CRL_set_default_method)
#endif

#ifndef X509_VERIFY_PARAM_set1
#define X509_VERIFY_PARAM_set1 __NS_SYMBOL(X509_VERIFY_PARAM_set1)
#endif

#ifndef d2i_ASN1_SET
#define d2i_ASN1_SET __NS_SYMBOL(d2i_ASN1_SET)
#endif

#ifndef d2i_X509_CRL_bio
#define d2i_X509_CRL_bio __NS_SYMBOL(d2i_X509_CRL_bio)
#endif

#ifndef i2d_PKCS7_RECIP_INFO
#define i2d_PKCS7_RECIP_INFO __NS_SYMBOL(i2d_PKCS7_RECIP_INFO)
#endif

#ifndef i2d_PKCS8PrivateKey_bio
#define i2d_PKCS8PrivateKey_bio __NS_SYMBOL(i2d_PKCS8PrivateKey_bio)
#endif

#ifndef ASN1_BIT_STRING_set_bit
#define ASN1_BIT_STRING_set_bit __NS_SYMBOL(ASN1_BIT_STRING_set_bit)
#endif

#ifndef BIO_test_flags
#define BIO_test_flags __NS_SYMBOL(BIO_test_flags)
#endif

#ifndef BN_mod_sqr
#define BN_mod_sqr __NS_SYMBOL(BN_mod_sqr)
#endif

#ifndef CRYPTO_dup_ex_data
#define CRYPTO_dup_ex_data __NS_SYMBOL(CRYPTO_dup_ex_data)
#endif

#ifndef ENGINE_get_ex_new_index
#define ENGINE_get_ex_new_index __NS_SYMBOL(ENGINE_get_ex_new_index)
#endif

#ifndef ENGINE_load_ssl_client_cert
#define ENGINE_load_ssl_client_cert __NS_SYMBOL(ENGINE_load_ssl_client_cert)
#endif

#ifndef EVP_PKEY_get_attr
#define EVP_PKEY_get_attr __NS_SYMBOL(EVP_PKEY_get_attr)
#endif

#ifndef HMAC_CTX_init
#define HMAC_CTX_init __NS_SYMBOL(HMAC_CTX_init)
#endif

#ifndef NCONF_get_section
#define NCONF_get_section __NS_SYMBOL(NCONF_get_section)
#endif

#ifndef OCSP_SINGLERESP_get_ext_by_NID
#define OCSP_SINGLERESP_get_ext_by_NID __NS_SYMBOL(OCSP_SINGLERESP_get_ext_by_NID)
#endif

#ifndef PEM_bytes_read_bio
#define PEM_bytes_read_bio __NS_SYMBOL(PEM_bytes_read_bio)
#endif

#ifndef RAND_egd_bytes
#define RAND_egd_bytes __NS_SYMBOL(RAND_egd_bytes)
#endif

#ifndef TS_REQ_get_ext
#define TS_REQ_get_ext __NS_SYMBOL(TS_REQ_get_ext)
#endif

#ifndef TS_TST_INFO_get_time
#define TS_TST_INFO_get_time __NS_SYMBOL(TS_TST_INFO_get_time)
#endif

#ifndef lh_node_usage_stats
#define lh_node_usage_stats __NS_SYMBOL(lh_node_usage_stats)
#endif

#ifndef BIO_set_flags
#define BIO_set_flags __NS_SYMBOL(BIO_set_flags)
#endif

#ifndef EVP_DecodeUpdate
#define EVP_DecodeUpdate __NS_SYMBOL(EVP_DecodeUpdate)
#endif

#ifndef EVP_PKEY_CTX_get_keygen_info
#define EVP_PKEY_CTX_get_keygen_info __NS_SYMBOL(EVP_PKEY_CTX_get_keygen_info)
#endif

#ifndef EVP_PKEY_asn1_add_alias
#define EVP_PKEY_asn1_add_alias __NS_SYMBOL(EVP_PKEY_asn1_add_alias)
#endif

#ifndef EVP_PKEY_delete_attr
#define EVP_PKEY_delete_attr __NS_SYMBOL(EVP_PKEY_delete_attr)
#endif

#ifndef EVP_aes_256_ofb
#define EVP_aes_256_ofb __NS_SYMBOL(EVP_aes_256_ofb)
#endif

#ifndef OCSP_SINGLERESP_get_ext_by_OBJ
#define OCSP_SINGLERESP_get_ext_by_OBJ __NS_SYMBOL(OCSP_SINGLERESP_get_ext_by_OBJ)
#endif

#ifndef OTHERNAME_cmp
#define OTHERNAME_cmp __NS_SYMBOL(OTHERNAME_cmp)
#endif

#ifndef PEM_write_bio_PKCS7
#define PEM_write_bio_PKCS7 __NS_SYMBOL(PEM_write_bio_PKCS7)
#endif

#ifndef PKCS12_set_mac
#define PKCS12_set_mac __NS_SYMBOL(PKCS12_set_mac)
#endif

#ifndef PKCS7_RECIP_INFO_new
#define PKCS7_RECIP_INFO_new __NS_SYMBOL(PKCS7_RECIP_INFO_new)
#endif

#ifndef RSA_padding_check_PKCS1_OAEP
#define RSA_padding_check_PKCS1_OAEP __NS_SYMBOL(RSA_padding_check_PKCS1_OAEP)
#endif

#ifndef TS_ACCURACY_dup
#define TS_ACCURACY_dup __NS_SYMBOL(TS_ACCURACY_dup)
#endif

#ifndef TS_REQ_delete_ext
#define TS_REQ_delete_ext __NS_SYMBOL(TS_REQ_delete_ext)
#endif

#ifndef TS_RESP_CTX_set_signer_cert
#define TS_RESP_CTX_set_signer_cert __NS_SYMBOL(TS_RESP_CTX_set_signer_cert)
#endif

#ifndef TS_TST_INFO_set_accuracy
#define TS_TST_INFO_set_accuracy __NS_SYMBOL(TS_TST_INFO_set_accuracy)
#endif

#ifndef X509_CRL_METHOD_new
#define X509_CRL_METHOD_new __NS_SYMBOL(X509_CRL_METHOD_new)
#endif

#ifndef X509_add1_reject_object
#define X509_add1_reject_object __NS_SYMBOL(X509_add1_reject_object)
#endif

#ifndef cms_msgSigDigest_add1
#define cms_msgSigDigest_add1 __NS_SYMBOL(cms_msgSigDigest_add1)
#endif

#ifndef d2i_ASN1_PRINTABLESTRING
#define d2i_ASN1_PRINTABLESTRING __NS_SYMBOL(d2i_ASN1_PRINTABLESTRING)
#endif

#ifndef d2i_EC_PRIVATEKEY
#define d2i_EC_PRIVATEKEY __NS_SYMBOL(d2i_EC_PRIVATEKEY)
#endif

#ifndef d2i_KRB5_CHECKSUM
#define d2i_KRB5_CHECKSUM __NS_SYMBOL(d2i_KRB5_CHECKSUM)
#endif

#ifndef d2i_OCSP_RESPONSE
#define d2i_OCSP_RESPONSE __NS_SYMBOL(d2i_OCSP_RESPONSE)
#endif

#ifndef i2d_X509_CRL_bio
#define i2d_X509_CRL_bio __NS_SYMBOL(i2d_X509_CRL_bio)
#endif

#ifndef lh_insert
#define lh_insert __NS_SYMBOL(lh_insert)
#endif

#ifndef BIO_get_callback
#define BIO_get_callback __NS_SYMBOL(BIO_get_callback)
#endif

#ifndef BN_mul_word
#define BN_mul_word __NS_SYMBOL(BN_mul_word)
#endif

#ifndef EVP_PKEY_add1_attr
#define EVP_PKEY_add1_attr __NS_SYMBOL(EVP_PKEY_add1_attr)
#endif

#ifndef OCSP_SINGLERESP_get_ext_by_critical
#define OCSP_SINGLERESP_get_ext_by_critical __NS_SYMBOL(OCSP_SINGLERESP_get_ext_by_critical)
#endif

#ifndef TS_CONF_set_default_engine
#define TS_CONF_set_default_engine __NS_SYMBOL(TS_CONF_set_default_engine)
#endif

#ifndef TS_REQ_add_ext
#define TS_REQ_add_ext __NS_SYMBOL(TS_REQ_add_ext)
#endif

#ifndef X509_VERIFY_PARAM_set1_name
#define X509_VERIFY_PARAM_set1_name __NS_SYMBOL(X509_VERIFY_PARAM_set1_name)
#endif

#ifndef pack_sign_cp
#define pack_sign_cp __NS_SYMBOL(pack_sign_cp)
#endif

#ifndef pkey_GOST01cp_encrypt
#define pkey_GOST01cp_encrypt __NS_SYMBOL(pkey_GOST01cp_encrypt)
#endif

#ifndef s2i_ASN1_INTEGER
#define s2i_ASN1_INTEGER __NS_SYMBOL(s2i_ASN1_INTEGER)
#endif

#ifndef ASN1_put_eoc
#define ASN1_put_eoc __NS_SYMBOL(ASN1_put_eoc)
#endif

#ifndef BIO_set_callback
#define BIO_set_callback __NS_SYMBOL(BIO_set_callback)
#endif

#ifndef BN_nist_mod_224
#define BN_nist_mod_224 __NS_SYMBOL(BN_nist_mod_224)
#endif

#ifndef CRYPTO_get_locked_mem_ex_functions
#define CRYPTO_get_locked_mem_ex_functions __NS_SYMBOL(CRYPTO_get_locked_mem_ex_functions)
#endif

#ifndef ECDSA_get_ex_new_index
#define ECDSA_get_ex_new_index __NS_SYMBOL(ECDSA_get_ex_new_index)
#endif

#ifndef ENGINE_set_ex_data
#define ENGINE_set_ex_data __NS_SYMBOL(ENGINE_set_ex_data)
#endif

#ifndef EVP_PKEY_verify_recover
#define EVP_PKEY_verify_recover __NS_SYMBOL(EVP_PKEY_verify_recover)
#endif

#ifndef HMAC_Update
#define HMAC_Update __NS_SYMBOL(HMAC_Update)
#endif

#ifndef OCSP_SINGLERESP_get_ext
#define OCSP_SINGLERESP_get_ext __NS_SYMBOL(OCSP_SINGLERESP_get_ext)
#endif

#ifndef PKCS7_RECIP_INFO_free
#define PKCS7_RECIP_INFO_free __NS_SYMBOL(PKCS7_RECIP_INFO_free)
#endif

#ifndef SXNET_add_id_INTEGER
#define SXNET_add_id_INTEGER __NS_SYMBOL(SXNET_add_id_INTEGER)
#endif

#ifndef X509_PKEY_free
#define X509_PKEY_free __NS_SYMBOL(X509_PKEY_free)
#endif

#ifndef X509_STORE_free
#define X509_STORE_free __NS_SYMBOL(X509_STORE_free)
#endif

#ifndef d2i_PKCS7_fp
#define d2i_PKCS7_fp __NS_SYMBOL(d2i_PKCS7_fp)
#endif

#ifndef d2i_TS_TST_INFO
#define d2i_TS_TST_INFO __NS_SYMBOL(d2i_TS_TST_INFO)
#endif

#ifndef i2d_ASN1_PRINTABLESTRING
#define i2d_ASN1_PRINTABLESTRING __NS_SYMBOL(i2d_ASN1_PRINTABLESTRING)
#endif

#ifndef i2d_EC_PRIVATEKEY
#define i2d_EC_PRIVATEKEY __NS_SYMBOL(i2d_EC_PRIVATEKEY)
#endif

#ifndef i2d_KRB5_CHECKSUM
#define i2d_KRB5_CHECKSUM __NS_SYMBOL(i2d_KRB5_CHECKSUM)
#endif

#ifndef i2d_OCSP_RESPONSE
#define i2d_OCSP_RESPONSE __NS_SYMBOL(i2d_OCSP_RESPONSE)
#endif

#ifndef i2d_PKCS8PrivateKey_nid_bio
#define i2d_PKCS8PrivateKey_nid_bio __NS_SYMBOL(i2d_PKCS8PrivateKey_nid_bio)
#endif

#ifndef BIO_set_callback_arg
#define BIO_set_callback_arg __NS_SYMBOL(BIO_set_callback_arg)
#endif

#ifndef CRYPTO_nistcts128_encrypt
#define CRYPTO_nistcts128_encrypt __NS_SYMBOL(CRYPTO_nistcts128_encrypt)
#endif

#ifndef ENGINE_register_complete
#define ENGINE_register_complete __NS_SYMBOL(ENGINE_register_complete)
#endif

#ifndef EVP_PBE_alg_add_type
#define EVP_PBE_alg_add_type __NS_SYMBOL(EVP_PBE_alg_add_type)
#endif

#ifndef EVP_PKEY_add1_attr_by_OBJ
#define EVP_PKEY_add1_attr_by_OBJ __NS_SYMBOL(EVP_PKEY_add1_attr_by_OBJ)
#endif

#ifndef EVP_PKEY_new_mac_key
#define EVP_PKEY_new_mac_key __NS_SYMBOL(EVP_PKEY_new_mac_key)
#endif

#ifndef EVP_aes_256_cfb128
#define EVP_aes_256_cfb128 __NS_SYMBOL(EVP_aes_256_cfb128)
#endif

#ifndef HMAC_Final
#define HMAC_Final __NS_SYMBOL(HMAC_Final)
#endif

#ifndef MDC2_Final
#define MDC2_Final __NS_SYMBOL(MDC2_Final)
#endif

#ifndef OCSP_SINGLERESP_delete_ext
#define OCSP_SINGLERESP_delete_ext __NS_SYMBOL(OCSP_SINGLERESP_delete_ext)
#endif

#ifndef RAND_egd
#define RAND_egd __NS_SYMBOL(RAND_egd)
#endif

#ifndef TS_REQ_get_ext_d2i
#define TS_REQ_get_ext_d2i __NS_SYMBOL(TS_REQ_get_ext_d2i)
#endif

#ifndef bn_dup_expand
#define bn_dup_expand __NS_SYMBOL(bn_dup_expand)
#endif

#ifndef ec_GFp_simple_group_get_curve
#define ec_GFp_simple_group_get_curve __NS_SYMBOL(ec_GFp_simple_group_get_curve)
#endif

#ifndef i2b_PublicKey_bio
#define i2b_PublicKey_bio __NS_SYMBOL(i2b_PublicKey_bio)
#endif

#ifndef ASN1_PRINTABLESTRING_new
#define ASN1_PRINTABLESTRING_new __NS_SYMBOL(ASN1_PRINTABLESTRING_new)
#endif

#ifndef ASN1_item_sign_ctx
#define ASN1_item_sign_ctx __NS_SYMBOL(ASN1_item_sign_ctx)
#endif

#ifndef ASN1_object_size
#define ASN1_object_size __NS_SYMBOL(ASN1_object_size)
#endif

#ifndef BIO_get_callback_arg
#define BIO_get_callback_arg __NS_SYMBOL(BIO_get_callback_arg)
#endif

#ifndef BN_hex2bn
#define BN_hex2bn __NS_SYMBOL(BN_hex2bn)
#endif

#ifndef BN_mod_lshift1
#define BN_mod_lshift1 __NS_SYMBOL(BN_mod_lshift1)
#endif

#ifndef CMS_get0_content
#define CMS_get0_content __NS_SYMBOL(CMS_get0_content)
#endif

#ifndef DSA_up_ref
#define DSA_up_ref __NS_SYMBOL(DSA_up_ref)
#endif

#ifndef EC_PRIVATEKEY_new
#define EC_PRIVATEKEY_new __NS_SYMBOL(EC_PRIVATEKEY_new)
#endif

#ifndef ENGINE_get_ex_data
#define ENGINE_get_ex_data __NS_SYMBOL(ENGINE_get_ex_data)
#endif

#ifndef KRB5_CHECKSUM_new
#define KRB5_CHECKSUM_new __NS_SYMBOL(KRB5_CHECKSUM_new)
#endif

#ifndef OCSP_RESPONSE_new
#define OCSP_RESPONSE_new __NS_SYMBOL(OCSP_RESPONSE_new)
#endif

#ifndef OCSP_SINGLERESP_get1_ext_d2i
#define OCSP_SINGLERESP_get1_ext_d2i __NS_SYMBOL(OCSP_SINGLERESP_get1_ext_d2i)
#endif

#ifndef OCSP_basic_sign
#define OCSP_basic_sign __NS_SYMBOL(OCSP_basic_sign)
#endif

#ifndef PKCS12_pack_p7encdata
#define PKCS12_pack_p7encdata __NS_SYMBOL(PKCS12_pack_p7encdata)
#endif

#ifndef d2i_PKCS7_ENC_CONTENT
#define d2i_PKCS7_ENC_CONTENT __NS_SYMBOL(d2i_PKCS7_ENC_CONTENT)
#endif

#ifndef d2i_PUBKEY
#define d2i_PUBKEY __NS_SYMBOL(d2i_PUBKEY)
#endif

#ifndef i2d_PKCS7_fp
#define i2d_PKCS7_fp __NS_SYMBOL(i2d_PKCS7_fp)
#endif

#ifndef i2d_TS_TST_INFO
#define i2d_TS_TST_INFO __NS_SYMBOL(i2d_TS_TST_INFO)
#endif

#ifndef BIO_method_name
#define BIO_method_name __NS_SYMBOL(BIO_method_name)
#endif

#ifndef CONF_get_string
#define CONF_get_string __NS_SYMBOL(CONF_get_string)
#endif

#ifndef ECDSA_set_ex_data
#define ECDSA_set_ex_data __NS_SYMBOL(ECDSA_set_ex_data)
#endif

#ifndef ERR_load_strings
#define ERR_load_strings __NS_SYMBOL(ERR_load_strings)
#endif

#ifndef EVP_CIPHER_nid
#define EVP_CIPHER_nid __NS_SYMBOL(EVP_CIPHER_nid)
#endif

#ifndef EVP_PKEY_add1_attr_by_NID
#define EVP_PKEY_add1_attr_by_NID __NS_SYMBOL(EVP_PKEY_add1_attr_by_NID)
#endif

#ifndef GENERAL_NAME_set0_value
#define GENERAL_NAME_set0_value __NS_SYMBOL(GENERAL_NAME_set0_value)
#endif

#ifndef OCSP_SINGLERESP_add1_ext_i2d
#define OCSP_SINGLERESP_add1_ext_i2d __NS_SYMBOL(OCSP_SINGLERESP_add1_ext_i2d)
#endif

#ifndef PEM_SealFinal
#define PEM_SealFinal __NS_SYMBOL(PEM_SealFinal)
#endif

#ifndef PEM_read_bio_Parameters
#define PEM_read_bio_Parameters __NS_SYMBOL(PEM_read_bio_Parameters)
#endif

#ifndef PEM_write_PKCS7
#define PEM_write_PKCS7 __NS_SYMBOL(PEM_write_PKCS7)
#endif

#ifndef X509_ATTRIBUTE_create_by_OBJ
#define X509_ATTRIBUTE_create_by_OBJ __NS_SYMBOL(X509_ATTRIBUTE_create_by_OBJ)
#endif

#ifndef X509_CRL_cmp
#define X509_CRL_cmp __NS_SYMBOL(X509_CRL_cmp)
#endif

#ifndef X509_VERIFY_PARAM_set_flags
#define X509_VERIFY_PARAM_set_flags __NS_SYMBOL(X509_VERIFY_PARAM_set_flags)
#endif

#ifndef bn_sqr_recursive
#define bn_sqr_recursive __NS_SYMBOL(bn_sqr_recursive)
#endif

#ifndef ec_GFp_mont_field_mul
#define ec_GFp_mont_field_mul __NS_SYMBOL(ec_GFp_mont_field_mul)
#endif

#ifndef lh_node_usage_stats_bio
#define lh_node_usage_stats_bio __NS_SYMBOL(lh_node_usage_stats_bio)
#endif

#ifndef ASN1_PRINTABLESTRING_free
#define ASN1_PRINTABLESTRING_free __NS_SYMBOL(ASN1_PRINTABLESTRING_free)
#endif

#ifndef BIO_method_type
#define BIO_method_type __NS_SYMBOL(BIO_method_type)
#endif

#ifndef CRYPTO_get_mem_debug_functions
#define CRYPTO_get_mem_debug_functions __NS_SYMBOL(CRYPTO_get_mem_debug_functions)
#endif

#ifndef EC_EX_DATA_clear_free_all_data
#define EC_EX_DATA_clear_free_all_data __NS_SYMBOL(EC_EX_DATA_clear_free_all_data)
#endif

#ifndef EC_PRIVATEKEY_free
#define EC_PRIVATEKEY_free __NS_SYMBOL(EC_PRIVATEKEY_free)
#endif

#ifndef ENGINE_pkey_asn1_find_str
#define ENGINE_pkey_asn1_find_str __NS_SYMBOL(ENGINE_pkey_asn1_find_str)
#endif

#ifndef ENGINE_set_id
#define ENGINE_set_id __NS_SYMBOL(ENGINE_set_id)
#endif

#ifndef EVP_CIPHER_block_size
#define EVP_CIPHER_block_size __NS_SYMBOL(EVP_CIPHER_block_size)
#endif

#ifndef EVP_aes_256_cfb1
#define EVP_aes_256_cfb1 __NS_SYMBOL(EVP_aes_256_cfb1)
#endif

#ifndef KRB5_CHECKSUM_free
#define KRB5_CHECKSUM_free __NS_SYMBOL(KRB5_CHECKSUM_free)
#endif

#ifndef OCSP_RESPONSE_free
#define OCSP_RESPONSE_free __NS_SYMBOL(OCSP_RESPONSE_free)
#endif

#ifndef OCSP_SINGLERESP_add_ext
#define OCSP_SINGLERESP_add_ext __NS_SYMBOL(OCSP_SINGLERESP_add_ext)
#endif

#ifndef TS_TST_INFO_new
#define TS_TST_INFO_new __NS_SYMBOL(TS_TST_INFO_new)
#endif

#ifndef X509_CRL_METHOD_free
#define X509_CRL_METHOD_free __NS_SYMBOL(X509_CRL_METHOD_free)
#endif

#ifndef X509_EXTENSION_create_by_NID
#define X509_EXTENSION_create_by_NID __NS_SYMBOL(X509_EXTENSION_create_by_NID)
#endif

#ifndef d2i_PKCS7_bio
#define d2i_PKCS7_bio __NS_SYMBOL(d2i_PKCS7_bio)
#endif

#ifndef d2i_PKCS8PrivateKey_bio
#define d2i_PKCS8PrivateKey_bio __NS_SYMBOL(d2i_PKCS8PrivateKey_bio)
#endif

#ifndef i2d_PKCS7_ENC_CONTENT
#define i2d_PKCS7_ENC_CONTENT __NS_SYMBOL(i2d_PKCS7_ENC_CONTENT)
#endif

#ifndef BIO_read
#define BIO_read __NS_SYMBOL(BIO_read)
#endif

#ifndef BN_X931_generate_Xpq
#define BN_X931_generate_Xpq __NS_SYMBOL(BN_X931_generate_Xpq)
#endif

#ifndef Camellia_DecryptBlock
#define Camellia_DecryptBlock __NS_SYMBOL(Camellia_DecryptBlock)
#endif

#ifndef DH_up_ref
#define DH_up_ref __NS_SYMBOL(DH_up_ref)
#endif

#ifndef DSA_size
#define DSA_size __NS_SYMBOL(DSA_size)
#endif

#ifndef EVP_CIPHER_CTX_block_size
#define EVP_CIPHER_CTX_block_size __NS_SYMBOL(EVP_CIPHER_CTX_block_size)
#endif

#ifndef EVP_DigestFinal_ex
#define EVP_DigestFinal_ex __NS_SYMBOL(EVP_DigestFinal_ex)
#endif

#ifndef EVP_PKEY_add1_attr_by_txt
#define EVP_PKEY_add1_attr_by_txt __NS_SYMBOL(EVP_PKEY_add1_attr_by_txt)
#endif

#ifndef OBJ_NAME_add
#define OBJ_NAME_add __NS_SYMBOL(OBJ_NAME_add)
#endif

#ifndef OCSP_RESPONSE_print
#define OCSP_RESPONSE_print __NS_SYMBOL(OCSP_RESPONSE_print)
#endif

#ifndef RAND_pseudo_bytes
#define RAND_pseudo_bytes __NS_SYMBOL(RAND_pseudo_bytes)
#endif

#ifndef TS_TST_INFO_get_accuracy
#define TS_TST_INFO_get_accuracy __NS_SYMBOL(TS_TST_INFO_get_accuracy)
#endif

#ifndef UI_dup_input_string
#define UI_dup_input_string __NS_SYMBOL(UI_dup_input_string)
#endif

#ifndef engine_table_cleanup
#define engine_table_cleanup __NS_SYMBOL(engine_table_cleanup)
#endif

#ifndef CRYPTO_free_ex_data
#define CRYPTO_free_ex_data __NS_SYMBOL(CRYPTO_free_ex_data)
#endif

#ifndef EC_KEY_dup
#define EC_KEY_dup __NS_SYMBOL(EC_KEY_dup)
#endif

#ifndef EVP_Cipher
#define EVP_Cipher __NS_SYMBOL(EVP_Cipher)
#endif

#ifndef OCSP_request_add1_nonce
#define OCSP_request_add1_nonce __NS_SYMBOL(OCSP_request_add1_nonce)
#endif

#ifndef PKCS7_ENC_CONTENT_new
#define PKCS7_ENC_CONTENT_new __NS_SYMBOL(PKCS7_ENC_CONTENT_new)
#endif

#ifndef SMIME_write_ASN1
#define SMIME_write_ASN1 __NS_SYMBOL(SMIME_write_ASN1)
#endif

#ifndef TS_ACCURACY_set_seconds
#define TS_ACCURACY_set_seconds __NS_SYMBOL(TS_ACCURACY_set_seconds)
#endif

#ifndef TS_TST_INFO_free
#define TS_TST_INFO_free __NS_SYMBOL(TS_TST_INFO_free)
#endif

#ifndef UTF8_putc
#define UTF8_putc __NS_SYMBOL(UTF8_putc)
#endif

#ifndef X509_CRL_set_meth_data
#define X509_CRL_set_meth_data __NS_SYMBOL(X509_CRL_set_meth_data)
#endif

#ifndef X509_REQ_get_attr_by_NID
#define X509_REQ_get_attr_by_NID __NS_SYMBOL(X509_REQ_get_attr_by_NID)
#endif

#ifndef X509_VERIFY_PARAM_clear_flags
#define X509_VERIFY_PARAM_clear_flags __NS_SYMBOL(X509_VERIFY_PARAM_clear_flags)
#endif

#ifndef asn1_Finish
#define asn1_Finish __NS_SYMBOL(asn1_Finish)
#endif

#ifndef bn_div_words
#define bn_div_words __NS_SYMBOL(bn_div_words)
#endif

#ifndef d2i_ASN1_T61STRING
#define d2i_ASN1_T61STRING __NS_SYMBOL(d2i_ASN1_T61STRING)
#endif

#ifndef d2i_ECPKParameters
#define d2i_ECPKParameters __NS_SYMBOL(d2i_ECPKParameters)
#endif

#ifndef d2i_KRB5_ENCKEY
#define d2i_KRB5_ENCKEY __NS_SYMBOL(d2i_KRB5_ENCKEY)
#endif

#ifndef d2i_OCSP_RESPID
#define d2i_OCSP_RESPID __NS_SYMBOL(d2i_OCSP_RESPID)
#endif

#ifndef i2d_PKCS7_bio
#define i2d_PKCS7_bio __NS_SYMBOL(i2d_PKCS7_bio)
#endif

#ifndef Camellia_DecryptBlock_Rounds
#define Camellia_DecryptBlock_Rounds __NS_SYMBOL(Camellia_DecryptBlock_Rounds)
#endif

#ifndef ECDSA_get_ex_data
#define ECDSA_get_ex_data __NS_SYMBOL(ECDSA_get_ex_data)
#endif

#ifndef ENGINE_register_all_complete
#define ENGINE_register_all_complete __NS_SYMBOL(ENGINE_register_all_complete)
#endif

#ifndef EVP_CIPHER_CTX_cipher
#define EVP_CIPHER_CTX_cipher __NS_SYMBOL(EVP_CIPHER_CTX_cipher)
#endif

#ifndef EVP_aes_256_cfb8
#define EVP_aes_256_cfb8 __NS_SYMBOL(EVP_aes_256_cfb8)
#endif

#ifndef X509_CRL_get_meth_data
#define X509_CRL_get_meth_data __NS_SYMBOL(X509_CRL_get_meth_data)
#endif

#ifndef X509_NAME_add_entry_by_OBJ
#define X509_NAME_add_entry_by_OBJ __NS_SYMBOL(X509_NAME_add_entry_by_OBJ)
#endif

#ifndef X509_trust_clear
#define X509_trust_clear __NS_SYMBOL(X509_trust_clear)
#endif

#ifndef b2i_PVK_bio
#define b2i_PVK_bio __NS_SYMBOL(b2i_PVK_bio)
#endif

#ifndef sk_delete_ptr
#define sk_delete_ptr __NS_SYMBOL(sk_delete_ptr)
#endif

#ifndef ASN1_UTCTIME_cmp_time_t
#define ASN1_UTCTIME_cmp_time_t __NS_SYMBOL(ASN1_UTCTIME_cmp_time_t)
#endif

#ifndef ASN1_item_unpack
#define ASN1_item_unpack __NS_SYMBOL(ASN1_item_unpack)
#endif

#ifndef CAST_decrypt
#define CAST_decrypt __NS_SYMBOL(CAST_decrypt)
#endif

#ifndef CMS_digest_verify
#define CMS_digest_verify __NS_SYMBOL(CMS_digest_verify)
#endif

#ifndef DH_get_ex_new_index
#define DH_get_ex_new_index __NS_SYMBOL(DH_get_ex_new_index)
#endif

#ifndef ENGINE_set_name
#define ENGINE_set_name __NS_SYMBOL(ENGINE_set_name)
#endif

#ifndef EVP_CIPHER_flags
#define EVP_CIPHER_flags __NS_SYMBOL(EVP_CIPHER_flags)
#endif

#ifndef GENERAL_NAME_get0_value
#define GENERAL_NAME_get0_value __NS_SYMBOL(GENERAL_NAME_get0_value)
#endif

#ifndef PEM_read_bio_NETSCAPE_CERT_SEQUENCE
#define PEM_read_bio_NETSCAPE_CERT_SEQUENCE __NS_SYMBOL(PEM_read_bio_NETSCAPE_CERT_SEQUENCE)
#endif

#ifndef PKCS7_ENC_CONTENT_free
#define PKCS7_ENC_CONTENT_free __NS_SYMBOL(PKCS7_ENC_CONTENT_free)
#endif

#ifndef SHA256_Final
#define SHA256_Final __NS_SYMBOL(SHA256_Final)
#endif

#ifndef TS_RESP_CTX_set_signer_key
#define TS_RESP_CTX_set_signer_key __NS_SYMBOL(TS_RESP_CTX_set_signer_key)
#endif

#ifndef TS_TST_INFO_dup
#define TS_TST_INFO_dup __NS_SYMBOL(TS_TST_INFO_dup)
#endif

#ifndef X509_REQ_get_attr
#define X509_REQ_get_attr __NS_SYMBOL(X509_REQ_get_attr)
#endif

#ifndef X509_VERIFY_PARAM_get_flags
#define X509_VERIFY_PARAM_get_flags __NS_SYMBOL(X509_VERIFY_PARAM_get_flags)
#endif

#ifndef bn_add_words
#define bn_add_words __NS_SYMBOL(bn_add_words)
#endif

#ifndef d2i_X509_REQ_fp
#define d2i_X509_REQ_fp __NS_SYMBOL(d2i_X509_REQ_fp)
#endif

#ifndef ec_GFp_mont_field_sqr
#define ec_GFp_mont_field_sqr __NS_SYMBOL(ec_GFp_mont_field_sqr)
#endif

#ifndef i2d_ASN1_T61STRING
#define i2d_ASN1_T61STRING __NS_SYMBOL(i2d_ASN1_T61STRING)
#endif

#ifndef i2d_KRB5_ENCKEY
#define i2d_KRB5_ENCKEY __NS_SYMBOL(i2d_KRB5_ENCKEY)
#endif

#ifndef i2d_OCSP_RESPID
#define i2d_OCSP_RESPID __NS_SYMBOL(i2d_OCSP_RESPID)
#endif

#ifndef EC_POINT_clear_free
#define EC_POINT_clear_free __NS_SYMBOL(EC_POINT_clear_free)
#endif

#ifndef EVP_CIPHER_CTX_flags
#define EVP_CIPHER_CTX_flags __NS_SYMBOL(EVP_CIPHER_CTX_flags)
#endif

#ifndef OBJ_nid2obj
#define OBJ_nid2obj __NS_SYMBOL(OBJ_nid2obj)
#endif

#ifndef X509_VERIFY_PARAM_set_purpose
#define X509_VERIFY_PARAM_set_purpose __NS_SYMBOL(X509_VERIFY_PARAM_set_purpose)
#endif

#ifndef i2d_PUBKEY
#define i2d_PUBKEY __NS_SYMBOL(i2d_PUBKEY)
#endif

#ifndef ASN1_T61STRING_new
#define ASN1_T61STRING_new __NS_SYMBOL(ASN1_T61STRING_new)
#endif

#ifndef BF_decrypt
#define BF_decrypt __NS_SYMBOL(BF_decrypt)
#endif

#ifndef BN_mod_lshift1_quick
#define BN_mod_lshift1_quick __NS_SYMBOL(BN_mod_lshift1_quick)
#endif

#ifndef CRYPTO_malloc_locked
#define CRYPTO_malloc_locked __NS_SYMBOL(CRYPTO_malloc_locked)
#endif

#ifndef EVP_CIPHER_CTX_get_app_data
#define EVP_CIPHER_CTX_get_app_data __NS_SYMBOL(EVP_CIPHER_CTX_get_app_data)
#endif

#ifndef EVP_PKEY_set_type_str
#define EVP_PKEY_set_type_str __NS_SYMBOL(EVP_PKEY_set_type_str)
#endif

#ifndef EVP_aes_256_ctr
#define EVP_aes_256_ctr __NS_SYMBOL(EVP_aes_256_ctr)
#endif

#ifndef KRB5_ENCKEY_new
#define KRB5_ENCKEY_new __NS_SYMBOL(KRB5_ENCKEY_new)
#endif

#ifndef OCSP_RESPID_new
#define OCSP_RESPID_new __NS_SYMBOL(OCSP_RESPID_new)
#endif

#ifndef X509_REQ_add_extensions_nid
#define X509_REQ_add_extensions_nid __NS_SYMBOL(X509_REQ_add_extensions_nid)
#endif

#ifndef X509_VERIFY_PARAM_set_trust
#define X509_VERIFY_PARAM_set_trust __NS_SYMBOL(X509_VERIFY_PARAM_set_trust)
#endif

#ifndef d2i_PKCS7_SIGN_ENVELOPE
#define d2i_PKCS7_SIGN_ENVELOPE __NS_SYMBOL(d2i_PKCS7_SIGN_ENVELOPE)
#endif

#ifndef d2i_TS_TST_INFO_bio
#define d2i_TS_TST_INFO_bio __NS_SYMBOL(d2i_TS_TST_INFO_bio)
#endif

#ifndef i2d_X509_REQ_fp
#define i2d_X509_REQ_fp __NS_SYMBOL(i2d_X509_REQ_fp)
#endif

#ifndef ASN1_STRING_TABLE_cleanup
#define ASN1_STRING_TABLE_cleanup __NS_SYMBOL(ASN1_STRING_TABLE_cleanup)
#endif

#ifndef DH_set_ex_data
#define DH_set_ex_data __NS_SYMBOL(DH_set_ex_data)
#endif

#ifndef DSA_get_ex_new_index
#define DSA_get_ex_new_index __NS_SYMBOL(DSA_get_ex_new_index)
#endif

#ifndef EVP_CIPHER_CTX_set_app_data
#define EVP_CIPHER_CTX_set_app_data __NS_SYMBOL(EVP_CIPHER_CTX_set_app_data)
#endif

#ifndef HMAC_CTX_copy
#define HMAC_CTX_copy __NS_SYMBOL(HMAC_CTX_copy)
#endif

#ifndef OCSP_response_status
#define OCSP_response_status __NS_SYMBOL(OCSP_response_status)
#endif

#ifndef PEM_read_NETSCAPE_CERT_SEQUENCE
#define PEM_read_NETSCAPE_CERT_SEQUENCE __NS_SYMBOL(PEM_read_NETSCAPE_CERT_SEQUENCE)
#endif

#ifndef PKCS7_set_content
#define PKCS7_set_content __NS_SYMBOL(PKCS7_set_content)
#endif

#ifndef X509_EXTENSION_create_by_OBJ
#define X509_EXTENSION_create_by_OBJ __NS_SYMBOL(X509_EXTENSION_create_by_OBJ)
#endif

#ifndef X509_TRUST_cleanup
#define X509_TRUST_cleanup __NS_SYMBOL(X509_TRUST_cleanup)
#endif

#ifndef X509_VERIFY_PARAM_set_depth
#define X509_VERIFY_PARAM_set_depth __NS_SYMBOL(X509_VERIFY_PARAM_set_depth)
#endif

#ifndef X509_reject_clear
#define X509_reject_clear __NS_SYMBOL(X509_reject_clear)
#endif

#ifndef _CONF_new_section
#define _CONF_new_section __NS_SYMBOL(_CONF_new_section)
#endif

#ifndef bn_sub_words
#define bn_sub_words __NS_SYMBOL(bn_sub_words)
#endif

#ifndef policy_cache_find_data
#define policy_cache_find_data __NS_SYMBOL(policy_cache_find_data)
#endif

#ifndef ASN1_T61STRING_free
#define ASN1_T61STRING_free __NS_SYMBOL(ASN1_T61STRING_free)
#endif

#ifndef BN_CTX_start
#define BN_CTX_start __NS_SYMBOL(BN_CTX_start)
#endif

#ifndef BN_rshift
#define BN_rshift __NS_SYMBOL(BN_rshift)
#endif

#ifndef CRYPTO_cbc128_decrypt
#define CRYPTO_cbc128_decrypt __NS_SYMBOL(CRYPTO_cbc128_decrypt)
#endif

#ifndef DH_get_ex_data
#define DH_get_ex_data __NS_SYMBOL(DH_get_ex_data)
#endif

#ifndef ENGINE_remove
#define ENGINE_remove __NS_SYMBOL(ENGINE_remove)
#endif

#ifndef ENGINE_set_destroy_function
#define ENGINE_set_destroy_function __NS_SYMBOL(ENGINE_set_destroy_function)
#endif

#ifndef ERR_unload_strings
#define ERR_unload_strings __NS_SYMBOL(ERR_unload_strings)
#endif

#ifndef EVP_CIPHER_iv_length
#define EVP_CIPHER_iv_length __NS_SYMBOL(EVP_CIPHER_iv_length)
#endif

#ifndef EVP_PKEY_assign
#define EVP_PKEY_assign __NS_SYMBOL(EVP_PKEY_assign)
#endif

#ifndef KRB5_ENCKEY_free
#define KRB5_ENCKEY_free __NS_SYMBOL(KRB5_ENCKEY_free)
#endif

#ifndef OCSP_RESPID_free
#define OCSP_RESPID_free __NS_SYMBOL(OCSP_RESPID_free)
#endif

#ifndef OCSP_response_get1_basic
#define OCSP_response_get1_basic __NS_SYMBOL(OCSP_response_get1_basic)
#endif

#ifndef RSA_up_ref
#define RSA_up_ref __NS_SYMBOL(RSA_up_ref)
#endif

#ifndef TS_CONF_set_signer_cert
#define TS_CONF_set_signer_cert __NS_SYMBOL(TS_CONF_set_signer_cert)
#endif

#ifndef TXT_DB_get_by_index
#define TXT_DB_get_by_index __NS_SYMBOL(TXT_DB_get_by_index)
#endif

#ifndef X509_CRL_match
#define X509_CRL_match __NS_SYMBOL(X509_CRL_match)
#endif

#ifndef X509_NAME_ENTRY_create_by_OBJ
#define X509_NAME_ENTRY_create_by_OBJ __NS_SYMBOL(X509_NAME_ENTRY_create_by_OBJ)
#endif

#ifndef X509_VERIFY_PARAM_set_time
#define X509_VERIFY_PARAM_set_time __NS_SYMBOL(X509_VERIFY_PARAM_set_time)
#endif

#ifndef cms_Receipt_verify
#define cms_Receipt_verify __NS_SYMBOL(cms_Receipt_verify)
#endif

#ifndef d2i_X509_REQ_bio
#define d2i_X509_REQ_bio __NS_SYMBOL(d2i_X509_REQ_bio)
#endif

#ifndef i2d_PKCS7_SIGN_ENVELOPE
#define i2d_PKCS7_SIGN_ENVELOPE __NS_SYMBOL(i2d_PKCS7_SIGN_ENVELOPE)
#endif

#ifndef CMS_RecipientInfo_ktri_get0_algs
#define CMS_RecipientInfo_ktri_get0_algs __NS_SYMBOL(CMS_RecipientInfo_ktri_get0_algs)
#endif

#ifndef DH_size
#define DH_size __NS_SYMBOL(DH_size)
#endif

#ifndef ENGINE_set_init_function
#define ENGINE_set_init_function __NS_SYMBOL(ENGINE_set_init_function)
#endif

#ifndef EVP_CIPHER_key_length
#define EVP_CIPHER_key_length __NS_SYMBOL(EVP_CIPHER_key_length)
#endif

#ifndef EVP_aes_128_gcm
#define EVP_aes_128_gcm __NS_SYMBOL(EVP_aes_128_gcm)
#endif

#ifndef TS_ACCURACY_get_seconds
#define TS_ACCURACY_get_seconds __NS_SYMBOL(TS_ACCURACY_get_seconds)
#endif

#ifndef TS_RESP_CTX_set_def_policy
#define TS_RESP_CTX_set_def_policy __NS_SYMBOL(TS_RESP_CTX_set_def_policy)
#endif

#ifndef X509_VERIFY_PARAM_add0_policy
#define X509_VERIFY_PARAM_add0_policy __NS_SYMBOL(X509_VERIFY_PARAM_add0_policy)
#endif

#ifndef asn1_const_Finish
#define asn1_const_Finish __NS_SYMBOL(asn1_const_Finish)
#endif

#ifndef ec_GFp_mont_field_encode
#define ec_GFp_mont_field_encode __NS_SYMBOL(ec_GFp_mont_field_encode)
#endif

#ifndef i2d_TS_TST_INFO_bio
#define i2d_TS_TST_INFO_bio __NS_SYMBOL(i2d_TS_TST_INFO_bio)
#endif

#ifndef i2v_GENERAL_NAME
#define i2v_GENERAL_NAME __NS_SYMBOL(i2v_GENERAL_NAME)
#endif

#ifndef CRYPTO_cts128_decrypt_block
#define CRYPTO_cts128_decrypt_block __NS_SYMBOL(CRYPTO_cts128_decrypt_block)
#endif

#ifndef DES_key_sched
#define DES_key_sched __NS_SYMBOL(DES_key_sched)
#endif

#ifndef DSA_set_ex_data
#define DSA_set_ex_data __NS_SYMBOL(DSA_set_ex_data)
#endif

#ifndef EC_GROUP_copy
#define EC_GROUP_copy __NS_SYMBOL(EC_GROUP_copy)
#endif

#ifndef ENGINE_set_finish_function
#define ENGINE_set_finish_function __NS_SYMBOL(ENGINE_set_finish_function)
#endif

#ifndef EVP_CIPHER_CTX_key_length
#define EVP_CIPHER_CTX_key_length __NS_SYMBOL(EVP_CIPHER_CTX_key_length)
#endif

#ifndef EVP_MD_CTX_cleanup
#define EVP_MD_CTX_cleanup __NS_SYMBOL(EVP_MD_CTX_cleanup)
#endif

#ifndef EVP_PBE_alg_add
#define EVP_PBE_alg_add __NS_SYMBOL(EVP_PBE_alg_add)
#endif

#ifndef GENERAL_NAME_set0_othername
#define GENERAL_NAME_set0_othername __NS_SYMBOL(GENERAL_NAME_set0_othername)
#endif

#ifndef PEM_write_bio_NETSCAPE_CERT_SEQUENCE
#define PEM_write_bio_NETSCAPE_CERT_SEQUENCE __NS_SYMBOL(PEM_write_bio_NETSCAPE_CERT_SEQUENCE)
#endif

#ifndef PKCS12_add_cert
#define PKCS12_add_cert __NS_SYMBOL(PKCS12_add_cert)
#endif

#ifndef PKCS7_SIGN_ENVELOPE_new
#define PKCS7_SIGN_ENVELOPE_new __NS_SYMBOL(PKCS7_SIGN_ENVELOPE_new)
#endif

#ifndef RAND_status
#define RAND_status __NS_SYMBOL(RAND_status)
#endif

#ifndef TS_ACCURACY_set_millis
#define TS_ACCURACY_set_millis __NS_SYMBOL(TS_ACCURACY_set_millis)
#endif

#ifndef X509V3_EXT_cleanup
#define X509V3_EXT_cleanup __NS_SYMBOL(X509V3_EXT_cleanup)
#endif

#ifndef X509_get_issuer_name
#define X509_get_issuer_name __NS_SYMBOL(X509_get_issuer_name)
#endif

#ifndef bn_mul_comba8
#define bn_mul_comba8 __NS_SYMBOL(bn_mul_comba8)
#endif

#ifndef d2i_ACCESS_DESCRIPTION
#define d2i_ACCESS_DESCRIPTION __NS_SYMBOL(d2i_ACCESS_DESCRIPTION)
#endif

#ifndef d2i_ASN1_IA5STRING
#define d2i_ASN1_IA5STRING __NS_SYMBOL(d2i_ASN1_IA5STRING)
#endif

#ifndef d2i_KRB5_AUTHDATA
#define d2i_KRB5_AUTHDATA __NS_SYMBOL(d2i_KRB5_AUTHDATA)
#endif

#ifndef d2i_OCSP_REVOKEDINFO
#define d2i_OCSP_REVOKEDINFO __NS_SYMBOL(d2i_OCSP_REVOKEDINFO)
#endif

#ifndef i2d_X509_REQ_bio
#define i2d_X509_REQ_bio __NS_SYMBOL(i2d_X509_REQ_bio)
#endif

#ifndef store_bignum
#define store_bignum __NS_SYMBOL(store_bignum)
#endif

#ifndef ASN1_item_ex_free
#define ASN1_item_ex_free __NS_SYMBOL(ASN1_item_ex_free)
#endif

#ifndef BN_mod_lshift
#define BN_mod_lshift __NS_SYMBOL(BN_mod_lshift)
#endif

#ifndef CRYPTO_set_ex_data
#define CRYPTO_set_ex_data __NS_SYMBOL(CRYPTO_set_ex_data)
#endif

#ifndef DSA_get_ex_data
#define DSA_get_ex_data __NS_SYMBOL(DSA_get_ex_data)
#endif

#ifndef ENGINE_cmd_is_executable
#define ENGINE_cmd_is_executable __NS_SYMBOL(ENGINE_cmd_is_executable)
#endif

#ifndef ENGINE_set_ctrl_function
#define ENGINE_set_ctrl_function __NS_SYMBOL(ENGINE_set_ctrl_function)
#endif

#ifndef EVP_CIPHER_CTX_nid
#define EVP_CIPHER_CTX_nid __NS_SYMBOL(EVP_CIPHER_CTX_nid)
#endif

#ifndef RSA_get_ex_new_index
#define RSA_get_ex_new_index __NS_SYMBOL(RSA_get_ex_new_index)
#endif

#ifndef X509_issuer_name_hash
#define X509_issuer_name_hash __NS_SYMBOL(X509_issuer_name_hash)
#endif

#ifndef d2i_RSA_PUBKEY
#define d2i_RSA_PUBKEY __NS_SYMBOL(d2i_RSA_PUBKEY)
#endif

#ifndef d2i_TS_TST_INFO_fp
#define d2i_TS_TST_INFO_fp __NS_SYMBOL(d2i_TS_TST_INFO_fp)
#endif

#ifndef d2i_X509_CERT_PAIR
#define d2i_X509_CERT_PAIR __NS_SYMBOL(d2i_X509_CERT_PAIR)
#endif

#ifndef engine_table_select
#define engine_table_select __NS_SYMBOL(engine_table_select)
#endif

#ifndef sk_delete
#define sk_delete __NS_SYMBOL(sk_delete)
#endif

#ifndef ASN1_template_free
#define ASN1_template_free __NS_SYMBOL(ASN1_template_free)
#endif

#ifndef BN_sub
#define BN_sub __NS_SYMBOL(BN_sub)
#endif

#ifndef DSA_dup_DH
#define DSA_dup_DH __NS_SYMBOL(DSA_dup_DH)
#endif

#ifndef EVP_MD_block_size
#define EVP_MD_block_size __NS_SYMBOL(EVP_MD_block_size)
#endif

#ifndef EVP_PKEY_get0
#define EVP_PKEY_get0 __NS_SYMBOL(EVP_PKEY_get0)
#endif

#ifndef EVP_aes_192_gcm
#define EVP_aes_192_gcm __NS_SYMBOL(EVP_aes_192_gcm)
#endif

#ifndef PKCS12_setup_mac
#define PKCS12_setup_mac __NS_SYMBOL(PKCS12_setup_mac)
#endif

#ifndef PKCS7_SIGN_ENVELOPE_free
#define PKCS7_SIGN_ENVELOPE_free __NS_SYMBOL(PKCS7_SIGN_ENVELOPE_free)
#endif

#ifndef X509at_add1_attr_by_NID
#define X509at_add1_attr_by_NID __NS_SYMBOL(X509at_add1_attr_by_NID)
#endif

#ifndef d2i_RSAPrivateKey_fp
#define d2i_RSAPrivateKey_fp __NS_SYMBOL(d2i_RSAPrivateKey_fp)
#endif

#ifndef i2d_ACCESS_DESCRIPTION
#define i2d_ACCESS_DESCRIPTION __NS_SYMBOL(i2d_ACCESS_DESCRIPTION)
#endif

#ifndef i2d_ASN1_IA5STRING
#define i2d_ASN1_IA5STRING __NS_SYMBOL(i2d_ASN1_IA5STRING)
#endif

#ifndef i2d_KRB5_AUTHDATA
#define i2d_KRB5_AUTHDATA __NS_SYMBOL(i2d_KRB5_AUTHDATA)
#endif

#ifndef i2d_OCSP_REVOKEDINFO
#define i2d_OCSP_REVOKEDINFO __NS_SYMBOL(i2d_OCSP_REVOKEDINFO)
#endif

#ifndef ASN1_template_new
#define ASN1_template_new __NS_SYMBOL(ASN1_template_new)
#endif

#ifndef CMS_dataInit
#define CMS_dataInit __NS_SYMBOL(CMS_dataInit)
#endif

#ifndef EC_KEY_up_ref
#define EC_KEY_up_ref __NS_SYMBOL(EC_KEY_up_ref)
#endif

#ifndef ENGINE_set_flags
#define ENGINE_set_flags __NS_SYMBOL(ENGINE_set_flags)
#endif

#ifndef EVP_MD_type
#define EVP_MD_type __NS_SYMBOL(EVP_MD_type)
#endif

#ifndef EVP_PKEY_asn1_new
#define EVP_PKEY_asn1_new __NS_SYMBOL(EVP_PKEY_asn1_new)
#endif

#ifndef EVP_PKEY_set1_RSA
#define EVP_PKEY_set1_RSA __NS_SYMBOL(EVP_PKEY_set1_RSA)
#endif

#ifndef TXT_DB_create_index
#define TXT_DB_create_index __NS_SYMBOL(TXT_DB_create_index)
#endif

#ifndef X509_VERIFY_PARAM_get_depth
#define X509_VERIFY_PARAM_get_depth __NS_SYMBOL(X509_VERIFY_PARAM_get_depth)
#endif

#ifndef i2d_X509_CERT_PAIR
#define i2d_X509_CERT_PAIR __NS_SYMBOL(i2d_X509_CERT_PAIR)
#endif

#ifndef ACCESS_DESCRIPTION_new
#define ACCESS_DESCRIPTION_new __NS_SYMBOL(ACCESS_DESCRIPTION_new)
#endif

#ifndef ASN1_IA5STRING_new
#define ASN1_IA5STRING_new __NS_SYMBOL(ASN1_IA5STRING_new)
#endif

#ifndef CRYPTO_destroy_dynlockid
#define CRYPTO_destroy_dynlockid __NS_SYMBOL(CRYPTO_destroy_dynlockid)
#endif

#ifndef DSO_ctrl
#define DSO_ctrl __NS_SYMBOL(DSO_ctrl)
#endif

#ifndef EVP_MD_pkey_type
#define EVP_MD_pkey_type __NS_SYMBOL(EVP_MD_pkey_type)
#endif

#ifndef EVP_PKEY_encrypt_init
#define EVP_PKEY_encrypt_init __NS_SYMBOL(EVP_PKEY_encrypt_init)
#endif

#ifndef KRB5_AUTHDATA_new
#define KRB5_AUTHDATA_new __NS_SYMBOL(KRB5_AUTHDATA_new)
#endif

#ifndef NCONF_get_string
#define NCONF_get_string __NS_SYMBOL(NCONF_get_string)
#endif

#ifndef OCSP_REVOKEDINFO_new
#define OCSP_REVOKEDINFO_new __NS_SYMBOL(OCSP_REVOKEDINFO_new)
#endif

#ifndef PKCS5_PBKDF2_HMAC_SHA1
#define PKCS5_PBKDF2_HMAC_SHA1 __NS_SYMBOL(PKCS5_PBKDF2_HMAC_SHA1)
#endif

#ifndef RSA_set_ex_data
#define RSA_set_ex_data __NS_SYMBOL(RSA_set_ex_data)
#endif

#ifndef WHIRLPOOL_Final
#define WHIRLPOOL_Final __NS_SYMBOL(WHIRLPOOL_Final)
#endif

#ifndef X509_STORE_add_lookup
#define X509_STORE_add_lookup __NS_SYMBOL(X509_STORE_add_lookup)
#endif

#ifndef X509_VERIFY_PARAM_add0_table
#define X509_VERIFY_PARAM_add0_table __NS_SYMBOL(X509_VERIFY_PARAM_add0_table)
#endif

#ifndef X509_load_cert_crl_file
#define X509_load_cert_crl_file __NS_SYMBOL(X509_load_cert_crl_file)
#endif

#ifndef d2i_PKCS7_ENCRYPT
#define d2i_PKCS7_ENCRYPT __NS_SYMBOL(d2i_PKCS7_ENCRYPT)
#endif

#ifndef ec_GFp_mont_field_decode
#define ec_GFp_mont_field_decode __NS_SYMBOL(ec_GFp_mont_field_decode)
#endif

#ifndef i2d_RSAPrivateKey_fp
#define i2d_RSAPrivateKey_fp __NS_SYMBOL(i2d_RSAPrivateKey_fp)
#endif

#ifndef i2d_TS_TST_INFO_fp
#define i2d_TS_TST_INFO_fp __NS_SYMBOL(i2d_TS_TST_INFO_fp)
#endif

#ifndef ASN1_BIT_STRING_get_bit
#define ASN1_BIT_STRING_get_bit __NS_SYMBOL(ASN1_BIT_STRING_get_bit)
#endif

#ifndef BIO_sock_error
#define BIO_sock_error __NS_SYMBOL(BIO_sock_error)
#endif

#ifndef BIO_write
#define BIO_write __NS_SYMBOL(BIO_write)
#endif

#ifndef CMS_RecipientInfo_ktri_get0_signer_id
#define CMS_RecipientInfo_ktri_get0_signer_id __NS_SYMBOL(CMS_RecipientInfo_ktri_get0_signer_id)
#endif

#ifndef CRYPTO_free_locked
#define CRYPTO_free_locked __NS_SYMBOL(CRYPTO_free_locked)
#endif

#ifndef ENGINE_set_cmd_defns
#define ENGINE_set_cmd_defns __NS_SYMBOL(ENGINE_set_cmd_defns)
#endif

#ifndef ERR_free_strings
#define ERR_free_strings __NS_SYMBOL(ERR_free_strings)
#endif

#ifndef EVP_MD_size
#define EVP_MD_size __NS_SYMBOL(EVP_MD_size)
#endif

#ifndef EVP_aes_256_gcm
#define EVP_aes_256_gcm __NS_SYMBOL(EVP_aes_256_gcm)
#endif

#ifndef GENERAL_NAME_get0_otherName
#define GENERAL_NAME_get0_otherName __NS_SYMBOL(GENERAL_NAME_get0_otherName)
#endif

#ifndef PEM_write_NETSCAPE_CERT_SEQUENCE
#define PEM_write_NETSCAPE_CERT_SEQUENCE __NS_SYMBOL(PEM_write_NETSCAPE_CERT_SEQUENCE)
#endif

#ifndef RSA_get_ex_data
#define RSA_get_ex_data __NS_SYMBOL(RSA_get_ex_data)
#endif

#ifndef TS_RESP_CTX_set_certs
#define TS_RESP_CTX_set_certs __NS_SYMBOL(TS_RESP_CTX_set_certs)
#endif

#ifndef X509V3_add_standard_extensions
#define X509V3_add_standard_extensions __NS_SYMBOL(X509V3_add_standard_extensions)
#endif

#ifndef X509V3_add_value_int
#define X509V3_add_value_int __NS_SYMBOL(X509V3_add_value_int)
#endif

#ifndef X509_CERT_PAIR_new
#define X509_CERT_PAIR_new __NS_SYMBOL(X509_CERT_PAIR_new)
#endif

#ifndef ec_GF2m_simple_group_get_curve
#define ec_GF2m_simple_group_get_curve __NS_SYMBOL(ec_GF2m_simple_group_get_curve)
#endif

#ifndef ACCESS_DESCRIPTION_free
#define ACCESS_DESCRIPTION_free __NS_SYMBOL(ACCESS_DESCRIPTION_free)
#endif

#ifndef AES_encrypt
#define AES_encrypt __NS_SYMBOL(AES_encrypt)
#endif

#ifndef ASN1_IA5STRING_free
#define ASN1_IA5STRING_free __NS_SYMBOL(ASN1_IA5STRING_free)
#endif

#ifndef BN_X931_generate_prime_ex
#define BN_X931_generate_prime_ex __NS_SYMBOL(BN_X931_generate_prime_ex)
#endif

#ifndef CMAC_Update
#define CMAC_Update __NS_SYMBOL(CMAC_Update)
#endif

#ifndef CRYPTO_pop_info
#define CRYPTO_pop_info __NS_SYMBOL(CRYPTO_pop_info)
#endif

#ifndef EC_KEY_generate_key
#define EC_KEY_generate_key __NS_SYMBOL(EC_KEY_generate_key)
#endif

#ifndef ENGINE_ctrl_cmd
#define ENGINE_ctrl_cmd __NS_SYMBOL(ENGINE_ctrl_cmd)
#endif

#ifndef HMAC_CTX_cleanup
#define HMAC_CTX_cleanup __NS_SYMBOL(HMAC_CTX_cleanup)
#endif

#ifndef KRB5_AUTHDATA_free
#define KRB5_AUTHDATA_free __NS_SYMBOL(KRB5_AUTHDATA_free)
#endif

#ifndef OCSP_REVOKEDINFO_free
#define OCSP_REVOKEDINFO_free __NS_SYMBOL(OCSP_REVOKEDINFO_free)
#endif

#ifndef OCSP_resp_count
#define OCSP_resp_count __NS_SYMBOL(OCSP_resp_count)
#endif

#ifndef PKCS7_set0_type_other
#define PKCS7_set0_type_other __NS_SYMBOL(PKCS7_set0_type_other)
#endif

#ifndef RSA_memory_lock
#define RSA_memory_lock __NS_SYMBOL(RSA_memory_lock)
#endif

#ifndef X509V3_EXT_d2i
#define X509V3_EXT_d2i __NS_SYMBOL(X509V3_EXT_d2i)
#endif

#ifndef asm_AES_encrypt
#define asm_AES_encrypt __NS_SYMBOL(asm_AES_encrypt)
#endif

#ifndef asn1_GetSequence
#define asn1_GetSequence __NS_SYMBOL(asn1_GetSequence)
#endif

#ifndef d2i_RSAPublicKey_fp
#define d2i_RSAPublicKey_fp __NS_SYMBOL(d2i_RSAPublicKey_fp)
#endif

#ifndef d2i_TS_STATUS_INFO
#define d2i_TS_STATUS_INFO __NS_SYMBOL(d2i_TS_STATUS_INFO)
#endif

#ifndef i2d_PKCS7_ENCRYPT
#define i2d_PKCS7_ENCRYPT __NS_SYMBOL(i2d_PKCS7_ENCRYPT)
#endif

#ifndef ENGINE_get_id
#define ENGINE_get_id __NS_SYMBOL(ENGINE_get_id)
#endif

#ifndef OBJ_nid2sn
#define OBJ_nid2sn __NS_SYMBOL(OBJ_nid2sn)
#endif

#ifndef OCSP_basic_add1_nonce
#define OCSP_basic_add1_nonce __NS_SYMBOL(OCSP_basic_add1_nonce)
#endif

#ifndef OCSP_request_verify
#define OCSP_request_verify __NS_SYMBOL(OCSP_request_verify)
#endif

#ifndef PEM_write_bio_Parameters
#define PEM_write_bio_Parameters __NS_SYMBOL(PEM_write_bio_Parameters)
#endif

#ifndef PKCS5_pbkdf2_set
#define PKCS5_pbkdf2_set __NS_SYMBOL(PKCS5_pbkdf2_set)
#endif

#ifndef X509_CERT_PAIR_free
#define X509_CERT_PAIR_free __NS_SYMBOL(X509_CERT_PAIR_free)
#endif

#ifndef ec_GFp_simple_group_get_degree
#define ec_GFp_simple_group_get_degree __NS_SYMBOL(ec_GFp_simple_group_get_degree)
#endif

#ifndef gost_do_verify
#define gost_do_verify __NS_SYMBOL(gost_do_verify)
#endif

#ifndef sk_find
#define sk_find __NS_SYMBOL(sk_find)
#endif

#ifndef ENGINE_get_name
#define ENGINE_get_name __NS_SYMBOL(ENGINE_get_name)
#endif

#ifndef EVP_PKEY_get1_RSA
#define EVP_PKEY_get1_RSA __NS_SYMBOL(EVP_PKEY_get1_RSA)
#endif

#ifndef EVP_aes_128_xts
#define EVP_aes_128_xts __NS_SYMBOL(EVP_aes_128_xts)
#endif

#ifndef OBJ_NAME_remove
#define OBJ_NAME_remove __NS_SYMBOL(OBJ_NAME_remove)
#endif

#ifndef OCSP_resp_get0
#define OCSP_resp_get0 __NS_SYMBOL(OCSP_resp_get0)
#endif

#ifndef PKCS7_ENCRYPT_new
#define PKCS7_ENCRYPT_new __NS_SYMBOL(PKCS7_ENCRYPT_new)
#endif

#ifndef TS_ACCURACY_get_millis
#define TS_ACCURACY_get_millis __NS_SYMBOL(TS_ACCURACY_get_millis)
#endif

#ifndef cms_RecipientInfo_pwri_crypt
#define cms_RecipientInfo_pwri_crypt __NS_SYMBOL(cms_RecipientInfo_pwri_crypt)
#endif

#ifndef d2i_ASN1_GENERALSTRING
#define d2i_ASN1_GENERALSTRING __NS_SYMBOL(d2i_ASN1_GENERALSTRING)
#endif

#ifndef d2i_AUTHORITY_INFO_ACCESS
#define d2i_AUTHORITY_INFO_ACCESS __NS_SYMBOL(d2i_AUTHORITY_INFO_ACCESS)
#endif

#ifndef d2i_KRB5_AUTHENTBODY
#define d2i_KRB5_AUTHENTBODY __NS_SYMBOL(d2i_KRB5_AUTHENTBODY)
#endif

#ifndef d2i_OCSP_CERTSTATUS
#define d2i_OCSP_CERTSTATUS __NS_SYMBOL(d2i_OCSP_CERTSTATUS)
#endif

#ifndef d2i_RSA_PUBKEY_fp
#define d2i_RSA_PUBKEY_fp __NS_SYMBOL(d2i_RSA_PUBKEY_fp)
#endif

#ifndef ec_GFp_simple_group_check_discriminant
#define ec_GFp_simple_group_check_discriminant __NS_SYMBOL(ec_GFp_simple_group_check_discriminant)
#endif

#ifndef i2d_PKCS8PrivateKey_fp
#define i2d_PKCS8PrivateKey_fp __NS_SYMBOL(i2d_PKCS8PrivateKey_fp)
#endif

#ifndef i2d_TS_STATUS_INFO
#define i2d_TS_STATUS_INFO __NS_SYMBOL(i2d_TS_STATUS_INFO)
#endif

#ifndef BIO_sock_cleanup
#define BIO_sock_cleanup __NS_SYMBOL(BIO_sock_cleanup)
#endif

#ifndef CMS_RecipientInfo_ktri_cert_cmp
#define CMS_RecipientInfo_ktri_cert_cmp __NS_SYMBOL(CMS_RecipientInfo_ktri_cert_cmp)
#endif

#ifndef ENGINE_get_destroy_function
#define ENGINE_get_destroy_function __NS_SYMBOL(ENGINE_get_destroy_function)
#endif

#ifndef EVP_MD_flags
#define EVP_MD_flags __NS_SYMBOL(EVP_MD_flags)
#endif

#ifndef OCSP_check_nonce
#define OCSP_check_nonce __NS_SYMBOL(OCSP_check_nonce)
#endif

#ifndef PKCS7_add_signer
#define PKCS7_add_signer __NS_SYMBOL(PKCS7_add_signer)
#endif

#ifndef TS_ACCURACY_set_micros
#define TS_ACCURACY_set_micros __NS_SYMBOL(TS_ACCURACY_set_micros)
#endif

#ifndef X509V3_extensions_print
#define X509V3_extensions_print __NS_SYMBOL(X509V3_extensions_print)
#endif

#ifndef X509_TRUST_get_flags
#define X509_TRUST_get_flags __NS_SYMBOL(X509_TRUST_get_flags)
#endif

#ifndef ec_GFp_mont_field_set_to_one
#define ec_GFp_mont_field_set_to_one __NS_SYMBOL(ec_GFp_mont_field_set_to_one)
#endif

#ifndef ASN1_BIT_STRING_check
#define ASN1_BIT_STRING_check __NS_SYMBOL(ASN1_BIT_STRING_check)
#endif

#ifndef ASN1_item_d2i_bio
#define ASN1_item_d2i_bio __NS_SYMBOL(ASN1_item_d2i_bio)
#endif

#ifndef BIO_socket_ioctl
#define BIO_socket_ioctl __NS_SYMBOL(BIO_socket_ioctl)
#endif

#ifndef CRYPTO_malloc
#define CRYPTO_malloc __NS_SYMBOL(CRYPTO_malloc)
#endif

#ifndef ENGINE_get_init_function
#define ENGINE_get_init_function __NS_SYMBOL(ENGINE_get_init_function)
#endif

#ifndef EVP_MD_CTX_md
#define EVP_MD_CTX_md __NS_SYMBOL(EVP_MD_CTX_md)
#endif

#ifndef HMAC
#define HMAC __NS_SYMBOL(HMAC)
#endif

#ifndef OCSP_resp_find
#define OCSP_resp_find __NS_SYMBOL(OCSP_resp_find)
#endif

#ifndef PEM_read_bio_RSAPrivateKey
#define PEM_read_bio_RSAPrivateKey __NS_SYMBOL(PEM_read_bio_RSAPrivateKey)
#endif

#ifndef PKCS5_v2_PBE_keyivgen
#define PKCS5_v2_PBE_keyivgen __NS_SYMBOL(PKCS5_v2_PBE_keyivgen)
#endif

#ifndef PKCS7_ENCRYPT_free
#define PKCS7_ENCRYPT_free __NS_SYMBOL(PKCS7_ENCRYPT_free)
#endif

#ifndef TS_STATUS_INFO_new
#define TS_STATUS_INFO_new __NS_SYMBOL(TS_STATUS_INFO_new)
#endif

#ifndef X509_TRUST_get0_name
#define X509_TRUST_get0_name __NS_SYMBOL(X509_TRUST_get0_name)
#endif

#ifndef i2d_ASN1_GENERALSTRING
#define i2d_ASN1_GENERALSTRING __NS_SYMBOL(i2d_ASN1_GENERALSTRING)
#endif

#ifndef i2d_AUTHORITY_INFO_ACCESS
#define i2d_AUTHORITY_INFO_ACCESS __NS_SYMBOL(i2d_AUTHORITY_INFO_ACCESS)
#endif

#ifndef i2d_KRB5_AUTHENTBODY
#define i2d_KRB5_AUTHENTBODY __NS_SYMBOL(i2d_KRB5_AUTHENTBODY)
#endif

#ifndef i2d_OCSP_CERTSTATUS
#define i2d_OCSP_CERTSTATUS __NS_SYMBOL(i2d_OCSP_CERTSTATUS)
#endif

#ifndef BN_pseudo_rand_range
#define BN_pseudo_rand_range __NS_SYMBOL(BN_pseudo_rand_range)
#endif

#ifndef ENGINE_get_finish_function
#define ENGINE_get_finish_function __NS_SYMBOL(ENGINE_get_finish_function)
#endif

#ifndef EVP_MD_CTX_set_flags
#define EVP_MD_CTX_set_flags __NS_SYMBOL(EVP_MD_CTX_set_flags)
#endif

#ifndef EVP_aes_256_xts
#define EVP_aes_256_xts __NS_SYMBOL(EVP_aes_256_xts)
#endif

#ifndef SHA384_Final
#define SHA384_Final __NS_SYMBOL(SHA384_Final)
#endif

#ifndef X509_EXTENSION_set_object
#define X509_EXTENSION_set_object __NS_SYMBOL(X509_EXTENSION_set_object)
#endif

#ifndef X509_NAME_add_entry
#define X509_NAME_add_entry __NS_SYMBOL(X509_NAME_add_entry)
#endif

#ifndef X509_NAME_hash
#define X509_NAME_hash __NS_SYMBOL(X509_NAME_hash)
#endif

#ifndef X509_TRUST_get_trust
#define X509_TRUST_get_trust __NS_SYMBOL(X509_TRUST_get_trust)
#endif

#ifndef gost2001_do_verify
#define gost2001_do_verify __NS_SYMBOL(gost2001_do_verify)
#endif

#ifndef i2d_RSAPublicKey_fp
#define i2d_RSAPublicKey_fp __NS_SYMBOL(i2d_RSAPublicKey_fp)
#endif

#ifndef ASN1_GENERALSTRING_new
#define ASN1_GENERALSTRING_new __NS_SYMBOL(ASN1_GENERALSTRING_new)
#endif

#ifndef ASN1_primitive_free
#define ASN1_primitive_free __NS_SYMBOL(ASN1_primitive_free)
#endif

#ifndef AUTHORITY_INFO_ACCESS_new
#define AUTHORITY_INFO_ACCESS_new __NS_SYMBOL(AUTHORITY_INFO_ACCESS_new)
#endif

#ifndef BN_CTX_end
#define BN_CTX_end __NS_SYMBOL(BN_CTX_end)
#endif

#ifndef CMS_digest_create
#define CMS_digest_create __NS_SYMBOL(CMS_digest_create)
#endif

#ifndef ENGINE_get_ctrl_function
#define ENGINE_get_ctrl_function __NS_SYMBOL(ENGINE_get_ctrl_function)
#endif

#ifndef ERR_put_error
#define ERR_put_error __NS_SYMBOL(ERR_put_error)
#endif

#ifndef EVP_MD_CTX_clear_flags
#define EVP_MD_CTX_clear_flags __NS_SYMBOL(EVP_MD_CTX_clear_flags)
#endif

#ifndef EVP_PKEY_encrypt
#define EVP_PKEY_encrypt __NS_SYMBOL(EVP_PKEY_encrypt)
#endif

#ifndef KRB5_AUTHENTBODY_new
#define KRB5_AUTHENTBODY_new __NS_SYMBOL(KRB5_AUTHENTBODY_new)
#endif

#ifndef OCSP_CERTSTATUS_new
#define OCSP_CERTSTATUS_new __NS_SYMBOL(OCSP_CERTSTATUS_new)
#endif

#ifndef PKCS12_unpack_p7encdata
#define PKCS12_unpack_p7encdata __NS_SYMBOL(PKCS12_unpack_p7encdata)
#endif

#ifndef SHA512_Update
#define SHA512_Update __NS_SYMBOL(SHA512_Update)
#endif

#ifndef TS_CONF_set_certs
#define TS_CONF_set_certs __NS_SYMBOL(TS_CONF_set_certs)
#endif

#ifndef TS_RESP_verify_response
#define TS_RESP_verify_response __NS_SYMBOL(TS_RESP_verify_response)
#endif

#ifndef TS_STATUS_INFO_free
#define TS_STATUS_INFO_free __NS_SYMBOL(TS_STATUS_INFO_free)
#endif

#ifndef d2i_PKCS7_DIGEST
#define d2i_PKCS7_DIGEST __NS_SYMBOL(d2i_PKCS7_DIGEST)
#endif

#ifndef i2d_RSA_PUBKEY
#define i2d_RSA_PUBKEY __NS_SYMBOL(i2d_RSA_PUBKEY)
#endif

#ifndef BN_from_montgomery
#define BN_from_montgomery __NS_SYMBOL(BN_from_montgomery)
#endif

#ifndef BN_mod_lshift_quick
#define BN_mod_lshift_quick __NS_SYMBOL(BN_mod_lshift_quick)
#endif

#ifndef BN_reciprocal
#define BN_reciprocal __NS_SYMBOL(BN_reciprocal)
#endif

#ifndef CMS_RecipientInfo_set0_pkey
#define CMS_RecipientInfo_set0_pkey __NS_SYMBOL(CMS_RecipientInfo_set0_pkey)
#endif

#ifndef CONF_get_number
#define CONF_get_number __NS_SYMBOL(CONF_get_number)
#endif

#ifndef CRYPTO_get_ex_data
#define CRYPTO_get_ex_data __NS_SYMBOL(CRYPTO_get_ex_data)
#endif

#ifndef DSO_set_filename
#define DSO_set_filename __NS_SYMBOL(DSO_set_filename)
#endif

#ifndef ENGINE_get_flags
#define ENGINE_get_flags __NS_SYMBOL(ENGINE_get_flags)
#endif

#ifndef EVP_MD_CTX_copy
#define EVP_MD_CTX_copy __NS_SYMBOL(EVP_MD_CTX_copy)
#endif

#ifndef EVP_MD_CTX_test_flags
#define EVP_MD_CTX_test_flags __NS_SYMBOL(EVP_MD_CTX_test_flags)
#endif

#ifndef EVP_PKEY_set1_DSA
#define EVP_PKEY_set1_DSA __NS_SYMBOL(EVP_PKEY_set1_DSA)
#endif

#ifndef ec_GF2m_simple_group_get_degree
#define ec_GF2m_simple_group_get_degree __NS_SYMBOL(ec_GF2m_simple_group_get_degree)
#endif

#ifndef ec_GFp_simple_point2oct
#define ec_GFp_simple_point2oct __NS_SYMBOL(ec_GFp_simple_point2oct)
#endif

#ifndef i2d_RSA_PUBKEY_fp
#define i2d_RSA_PUBKEY_fp __NS_SYMBOL(i2d_RSA_PUBKEY_fp)
#endif

#ifndef ASN1_GENERALSTRING_free
#define ASN1_GENERALSTRING_free __NS_SYMBOL(ASN1_GENERALSTRING_free)
#endif

#ifndef AUTHORITY_INFO_ACCESS_free
#define AUTHORITY_INFO_ACCESS_free __NS_SYMBOL(AUTHORITY_INFO_ACCESS_free)
#endif

#ifndef BIO_get_accept_socket
#define BIO_get_accept_socket __NS_SYMBOL(BIO_get_accept_socket)
#endif

#ifndef ENGINE_get_cmd_defns
#define ENGINE_get_cmd_defns __NS_SYMBOL(ENGINE_get_cmd_defns)
#endif

#ifndef EVP_CIPHER_CTX_cleanup
#define EVP_CIPHER_CTX_cleanup __NS_SYMBOL(EVP_CIPHER_CTX_cleanup)
#endif

#ifndef EVP_CIPHER_CTX_set_flags
#define EVP_CIPHER_CTX_set_flags __NS_SYMBOL(EVP_CIPHER_CTX_set_flags)
#endif

#ifndef EVP_PBE_cleanup
#define EVP_PBE_cleanup __NS_SYMBOL(EVP_PBE_cleanup)
#endif

#ifndef EVP_PKEY_CTX_new_id
#define EVP_PKEY_CTX_new_id __NS_SYMBOL(EVP_PKEY_CTX_new_id)
#endif

#ifndef EVP_aes_128_ccm
#define EVP_aes_128_ccm __NS_SYMBOL(EVP_aes_128_ccm)
#endif

#ifndef KRB5_AUTHENTBODY_free
#define KRB5_AUTHENTBODY_free __NS_SYMBOL(KRB5_AUTHENTBODY_free)
#endif

#ifndef OCSP_CERTID_dup
#define OCSP_CERTID_dup __NS_SYMBOL(OCSP_CERTID_dup)
#endif

#ifndef OCSP_CERTSTATUS_free
#define OCSP_CERTSTATUS_free __NS_SYMBOL(OCSP_CERTSTATUS_free)
#endif

#ifndef PKCS12_add_safe
#define PKCS12_add_safe __NS_SYMBOL(PKCS12_add_safe)
#endif

#ifndef TS_STATUS_INFO_dup
#define TS_STATUS_INFO_dup __NS_SYMBOL(TS_STATUS_INFO_dup)
#endif

#ifndef X509_REQ_add_extensions
#define X509_REQ_add_extensions __NS_SYMBOL(X509_REQ_add_extensions)
#endif

#ifndef i2d_PKCS7_DIGEST
#define i2d_PKCS7_DIGEST __NS_SYMBOL(i2d_PKCS7_DIGEST)
#endif

#ifndef BIO_dump_fp
#define BIO_dump_fp __NS_SYMBOL(BIO_dump_fp)
#endif

#ifndef BN_BLINDING_convert
#define BN_BLINDING_convert __NS_SYMBOL(BN_BLINDING_convert)
#endif

#ifndef CRYPTO_ccm128_decrypt
#define CRYPTO_ccm128_decrypt __NS_SYMBOL(CRYPTO_ccm128_decrypt)
#endif

#ifndef CRYPTO_cfb128_8_encrypt
#define CRYPTO_cfb128_8_encrypt __NS_SYMBOL(CRYPTO_cfb128_8_encrypt)
#endif

#ifndef EC_get_builtin_curves
#define EC_get_builtin_curves __NS_SYMBOL(EC_get_builtin_curves)
#endif

#ifndef ENGINE_get_static_state
#define ENGINE_get_static_state __NS_SYMBOL(ENGINE_get_static_state)
#endif

#ifndef EVP_CIPHER_CTX_clear_flags
#define EVP_CIPHER_CTX_clear_flags __NS_SYMBOL(EVP_CIPHER_CTX_clear_flags)
#endif

#ifndef EVP_PKEY_CTX_dup
#define EVP_PKEY_CTX_dup __NS_SYMBOL(EVP_PKEY_CTX_dup)
#endif

#ifndef RSA_padding_add_PKCS1_PSS
#define RSA_padding_add_PKCS1_PSS __NS_SYMBOL(RSA_padding_add_PKCS1_PSS)
#endif

#ifndef X509_EXTENSION_set_critical
#define X509_EXTENSION_set_critical __NS_SYMBOL(X509_EXTENSION_set_critical)
#endif

#ifndef X509_REQ_get_attr_count
#define X509_REQ_get_attr_count __NS_SYMBOL(X509_REQ_get_attr_count)
#endif

#ifndef cms_EncryptedContent_init
#define cms_EncryptedContent_init __NS_SYMBOL(cms_EncryptedContent_init)
#endif

#ifndef d2i_RSAPrivateKey_bio
#define d2i_RSAPrivateKey_bio __NS_SYMBOL(d2i_RSAPrivateKey_bio)
#endif

#ifndef ec_GF2m_simple_group_check_discriminant
#define ec_GF2m_simple_group_check_discriminant __NS_SYMBOL(ec_GF2m_simple_group_check_discriminant)
#endif

#ifndef AES_bi_ige_encrypt
#define AES_bi_ige_encrypt __NS_SYMBOL(AES_bi_ige_encrypt)
#endif

#ifndef ASN1_STRING_copy
#define ASN1_STRING_copy __NS_SYMBOL(ASN1_STRING_copy)
#endif

#ifndef EVP_CIPHER_CTX_test_flags
#define EVP_CIPHER_CTX_test_flags __NS_SYMBOL(EVP_CIPHER_CTX_test_flags)
#endif

#ifndef PEM_read_RSAPrivateKey
#define PEM_read_RSAPrivateKey __NS_SYMBOL(PEM_read_RSAPrivateKey)
#endif

#ifndef PKCS7_DIGEST_new
#define PKCS7_DIGEST_new __NS_SYMBOL(PKCS7_DIGEST_new)
#endif

#ifndef X509V3_get_value_bool
#define X509V3_get_value_bool __NS_SYMBOL(X509V3_get_value_bool)
#endif

#ifndef d2i_ASN1_UTCTIME
#define d2i_ASN1_UTCTIME __NS_SYMBOL(d2i_ASN1_UTCTIME)
#endif

#ifndef d2i_KRB5_AUTHENT
#define d2i_KRB5_AUTHENT __NS_SYMBOL(d2i_KRB5_AUTHENT)
#endif

#ifndef d2i_OCSP_SINGLERESP
#define d2i_OCSP_SINGLERESP __NS_SYMBOL(d2i_OCSP_SINGLERESP)
#endif

#ifndef d2i_TS_RESP
#define d2i_TS_RESP __NS_SYMBOL(d2i_TS_RESP)
#endif

#ifndef i2a_ACCESS_DESCRIPTION
#define i2a_ACCESS_DESCRIPTION __NS_SYMBOL(i2a_ACCESS_DESCRIPTION)
#endif

#ifndef CMS_RecipientInfo_kekri_id_cmp
#define CMS_RecipientInfo_kekri_id_cmp __NS_SYMBOL(CMS_RecipientInfo_kekri_id_cmp)
#endif

#ifndef EVP_MD_CTX_copy_ex
#define EVP_MD_CTX_copy_ex __NS_SYMBOL(EVP_MD_CTX_copy_ex)
#endif

#ifndef EVP_aes_192_ccm
#define EVP_aes_192_ccm __NS_SYMBOL(EVP_aes_192_ccm)
#endif

#ifndef OBJ_NAME_do_all
#define OBJ_NAME_do_all __NS_SYMBOL(OBJ_NAME_do_all)
#endif

#ifndef OCSP_single_get0_status
#define OCSP_single_get0_status __NS_SYMBOL(OCSP_single_get0_status)
#endif

#ifndef RSA_padding_add_PKCS1_PSS_mgf1
#define RSA_padding_add_PKCS1_PSS_mgf1 __NS_SYMBOL(RSA_padding_add_PKCS1_PSS_mgf1)
#endif

#ifndef TS_ACCURACY_get_micros
#define TS_ACCURACY_get_micros __NS_SYMBOL(TS_ACCURACY_get_micros)
#endif

#ifndef UI_add_verify_string
#define UI_add_verify_string __NS_SYMBOL(UI_add_verify_string)
#endif

#ifndef X509_ATTRIBUTE_create_by_NID
#define X509_ATTRIBUTE_create_by_NID __NS_SYMBOL(X509_ATTRIBUTE_create_by_NID)
#endif

#ifndef X509_EXTENSION_set_data
#define X509_EXTENSION_set_data __NS_SYMBOL(X509_EXTENSION_set_data)
#endif

#ifndef X509_REQ_get_attr_by_OBJ
#define X509_REQ_get_attr_by_OBJ __NS_SYMBOL(X509_REQ_get_attr_by_OBJ)
#endif

#ifndef i2d_RSAPrivateKey_bio
#define i2d_RSAPrivateKey_bio __NS_SYMBOL(i2d_RSAPrivateKey_bio)
#endif

#ifndef ASN1_item_d2i_fp
#define ASN1_item_d2i_fp __NS_SYMBOL(ASN1_item_d2i_fp)
#endif

#ifndef EVP_PKEY_get1_DSA
#define EVP_PKEY_get1_DSA __NS_SYMBOL(EVP_PKEY_get1_DSA)
#endif

#ifndef PEM_read_PrivateKey
#define PEM_read_PrivateKey __NS_SYMBOL(PEM_read_PrivateKey)
#endif

#ifndef PKCS12_decrypt_skey
#define PKCS12_decrypt_skey __NS_SYMBOL(PKCS12_decrypt_skey)
#endif

#ifndef PKCS7_DIGEST_free
#define PKCS7_DIGEST_free __NS_SYMBOL(PKCS7_DIGEST_free)
#endif

#ifndef TS_TST_INFO_set_ordering
#define TS_TST_INFO_set_ordering __NS_SYMBOL(TS_TST_INFO_set_ordering)
#endif

#ifndef i2d_ASN1_UTCTIME
#define i2d_ASN1_UTCTIME __NS_SYMBOL(i2d_ASN1_UTCTIME)
#endif

#ifndef i2d_KRB5_AUTHENT
#define i2d_KRB5_AUTHENT __NS_SYMBOL(i2d_KRB5_AUTHENT)
#endif

#ifndef i2d_OCSP_SINGLERESP
#define i2d_OCSP_SINGLERESP __NS_SYMBOL(i2d_OCSP_SINGLERESP)
#endif

#ifndef i2d_PKCS8PrivateKey_nid_fp
#define i2d_PKCS8PrivateKey_nid_fp __NS_SYMBOL(i2d_PKCS8PrivateKey_nid_fp)
#endif

#ifndef i2d_TS_RESP
#define i2d_TS_RESP __NS_SYMBOL(i2d_TS_RESP)
#endif

#ifndef sk_find_ex
#define sk_find_ex __NS_SYMBOL(sk_find_ex)
#endif

#ifndef BIO_puts
#define BIO_puts __NS_SYMBOL(BIO_puts)
#endif

#ifndef BN_dup
#define BN_dup __NS_SYMBOL(BN_dup)
#endif

#ifndef CRYPTO_strdup
#define CRYPTO_strdup __NS_SYMBOL(CRYPTO_strdup)
#endif

#ifndef ENGINE_ctrl_cmd_string
#define ENGINE_ctrl_cmd_string __NS_SYMBOL(ENGINE_ctrl_cmd_string)
#endif

#ifndef OBJ_nid2ln
#define OBJ_nid2ln __NS_SYMBOL(OBJ_nid2ln)
#endif

#ifndef PKCS12_pack_authsafes
#define PKCS12_pack_authsafes __NS_SYMBOL(PKCS12_pack_authsafes)
#endif

#ifndef TS_RESP_CTX_add_policy
#define TS_RESP_CTX_add_policy __NS_SYMBOL(TS_RESP_CTX_add_policy)
#endif

#ifndef X509_REQ_delete_attr
#define X509_REQ_delete_attr __NS_SYMBOL(X509_REQ_delete_attr)
#endif

#ifndef X509_STORE_get_by_subject
#define X509_STORE_get_by_subject __NS_SYMBOL(X509_STORE_get_by_subject)
#endif

#ifndef d2i_RSAPublicKey_bio
#define d2i_RSAPublicKey_bio __NS_SYMBOL(d2i_RSAPublicKey_bio)
#endif

#ifndef lh_delete
#define lh_delete __NS_SYMBOL(lh_delete)
#endif

#ifndef ASN1_UTCTIME_new
#define ASN1_UTCTIME_new __NS_SYMBOL(ASN1_UTCTIME_new)
#endif

#ifndef BIO_dump_indent_fp
#define BIO_dump_indent_fp __NS_SYMBOL(BIO_dump_indent_fp)
#endif

#ifndef CMS_EncryptedData_decrypt
#define CMS_EncryptedData_decrypt __NS_SYMBOL(CMS_EncryptedData_decrypt)
#endif

#ifndef CMS_dataFinal
#define CMS_dataFinal __NS_SYMBOL(CMS_dataFinal)
#endif

#ifndef ENGINE_by_id
#define ENGINE_by_id __NS_SYMBOL(ENGINE_by_id)
#endif

#ifndef EVP_aes_256_ccm
#define EVP_aes_256_ccm __NS_SYMBOL(EVP_aes_256_ccm)
#endif

#ifndef KRB5_AUTHENT_new
#define KRB5_AUTHENT_new __NS_SYMBOL(KRB5_AUTHENT_new)
#endif

#ifndef OCSP_SINGLERESP_new
#define OCSP_SINGLERESP_new __NS_SYMBOL(OCSP_SINGLERESP_new)
#endif

#ifndef OCSP_copy_nonce
#define OCSP_copy_nonce __NS_SYMBOL(OCSP_copy_nonce)
#endif

#ifndef PKCS7_print_ctx
#define PKCS7_print_ctx __NS_SYMBOL(PKCS7_print_ctx)
#endif

#ifndef TS_CONF_set_signer_key
#define TS_CONF_set_signer_key __NS_SYMBOL(TS_CONF_set_signer_key)
#endif

#ifndef TS_RESP_new
#define TS_RESP_new __NS_SYMBOL(TS_RESP_new)
#endif

#ifndef TS_TST_INFO_get_ordering
#define TS_TST_INFO_get_ordering __NS_SYMBOL(TS_TST_INFO_get_ordering)
#endif

#ifndef X509V3_get_d2i
#define X509V3_get_d2i __NS_SYMBOL(X509V3_get_d2i)
#endif

#ifndef X509_EXTENSION_get_object
#define X509_EXTENSION_get_object __NS_SYMBOL(X509_EXTENSION_get_object)
#endif

#ifndef ASN1_STRING_set
#define ASN1_STRING_set __NS_SYMBOL(ASN1_STRING_set)
#endif

#ifndef BN_CTX_get
#define BN_CTX_get __NS_SYMBOL(BN_CTX_get)
#endif

#ifndef BN_MONT_CTX_new
#define BN_MONT_CTX_new __NS_SYMBOL(BN_MONT_CTX_new)
#endif

#ifndef SXNET_add_id_ulong
#define SXNET_add_id_ulong __NS_SYMBOL(SXNET_add_id_ulong)
#endif

#ifndef TS_TST_INFO_set_nonce
#define TS_TST_INFO_set_nonce __NS_SYMBOL(TS_TST_INFO_set_nonce)
#endif

#ifndef X509_EXTENSION_get_data
#define X509_EXTENSION_get_data __NS_SYMBOL(X509_EXTENSION_get_data)
#endif

#ifndef X509_REQ_add1_attr
#define X509_REQ_add1_attr __NS_SYMBOL(X509_REQ_add1_attr)
#endif

#ifndef X509_VERIFY_PARAM_lookup
#define X509_VERIFY_PARAM_lookup __NS_SYMBOL(X509_VERIFY_PARAM_lookup)
#endif

#ifndef X509_issuer_name_hash_old
#define X509_issuer_name_hash_old __NS_SYMBOL(X509_issuer_name_hash_old)
#endif

#ifndef d2i_RSA_PUBKEY_bio
#define d2i_RSA_PUBKEY_bio __NS_SYMBOL(d2i_RSA_PUBKEY_bio)
#endif

#ifndef ASN1_UTCTIME_free
#define ASN1_UTCTIME_free __NS_SYMBOL(ASN1_UTCTIME_free)
#endif

#ifndef BIO_dump
#define BIO_dump __NS_SYMBOL(BIO_dump)
#endif

#ifndef EVP_CIPHER_CTX_ctrl
#define EVP_CIPHER_CTX_ctrl __NS_SYMBOL(EVP_CIPHER_CTX_ctrl)
#endif

#ifndef KRB5_AUTHENT_free
#define KRB5_AUTHENT_free __NS_SYMBOL(KRB5_AUTHENT_free)
#endif

#ifndef OBJ_NAME_do_all_sorted
#define OBJ_NAME_do_all_sorted __NS_SYMBOL(OBJ_NAME_do_all_sorted)
#endif

#ifndef OCSP_SINGLERESP_free
#define OCSP_SINGLERESP_free __NS_SYMBOL(OCSP_SINGLERESP_free)
#endif

#ifndef PEM_write_bio_RSAPrivateKey
#define PEM_write_bio_RSAPrivateKey __NS_SYMBOL(PEM_write_bio_RSAPrivateKey)
#endif

#ifndef PKCS12_unpack_authsafes
#define PKCS12_unpack_authsafes __NS_SYMBOL(PKCS12_unpack_authsafes)
#endif

#ifndef TS_RESP_free
#define TS_RESP_free __NS_SYMBOL(TS_RESP_free)
#endif

#ifndef CMAC_Final
#define CMAC_Final __NS_SYMBOL(CMAC_Final)
#endif

#ifndef CMS_EncryptedData_set1_key
#define CMS_EncryptedData_set1_key __NS_SYMBOL(CMS_EncryptedData_set1_key)
#endif

#ifndef CRYPTO_get_dynlock_value
#define CRYPTO_get_dynlock_value __NS_SYMBOL(CRYPTO_get_dynlock_value)
#endif

#ifndef EVP_PKEY_set1_EC_KEY
#define EVP_PKEY_set1_EC_KEY __NS_SYMBOL(EVP_PKEY_set1_EC_KEY)
#endif

#ifndef SHA256
#define SHA256 __NS_SYMBOL(SHA256)
#endif

#ifndef X509_EXTENSION_get_critical
#define X509_EXTENSION_get_critical __NS_SYMBOL(X509_EXTENSION_get_critical)
#endif

#ifndef X509_NAME_hash_old
#define X509_NAME_hash_old __NS_SYMBOL(X509_NAME_hash_old)
#endif

#ifndef X509_REQ_add1_attr_by_OBJ
#define X509_REQ_add1_attr_by_OBJ __NS_SYMBOL(X509_REQ_add1_attr_by_OBJ)
#endif

#ifndef engine_table_doall
#define engine_table_doall __NS_SYMBOL(engine_table_doall)
#endif

#ifndef ASN1_primitive_new
#define ASN1_primitive_new __NS_SYMBOL(ASN1_primitive_new)
#endif

#ifndef BN_dec2bn
#define BN_dec2bn __NS_SYMBOL(BN_dec2bn)
#endif

#ifndef CMS_add0_recipient_key
#define CMS_add0_recipient_key __NS_SYMBOL(CMS_add0_recipient_key)
#endif

#ifndef CONF_modules_load_file
#define CONF_modules_load_file __NS_SYMBOL(CONF_modules_load_file)
#endif

#ifndef TS_RESP_dup
#define TS_RESP_dup __NS_SYMBOL(TS_RESP_dup)
#endif

#ifndef TXT_DB_write
#define TXT_DB_write __NS_SYMBOL(TXT_DB_write)
#endif

#ifndef d2i_ASN1_GENERALIZEDTIME
#define d2i_ASN1_GENERALIZEDTIME __NS_SYMBOL(d2i_ASN1_GENERALIZEDTIME)
#endif

#ifndef d2i_DIST_POINT_NAME
#define d2i_DIST_POINT_NAME __NS_SYMBOL(d2i_DIST_POINT_NAME)
#endif

#ifndef d2i_DSA_PUBKEY
#define d2i_DSA_PUBKEY __NS_SYMBOL(d2i_DSA_PUBKEY)
#endif

#ifndef d2i_OCSP_RESPDATA
#define d2i_OCSP_RESPDATA __NS_SYMBOL(d2i_OCSP_RESPDATA)
#endif

#ifndef d2i_X509_NAME
#define d2i_X509_NAME __NS_SYMBOL(d2i_X509_NAME)
#endif

#ifndef i2d_RSAPublicKey_bio
#define i2d_RSAPublicKey_bio __NS_SYMBOL(i2d_RSAPublicKey_bio)
#endif

#ifndef BN_BLINDING_convert_ex
#define BN_BLINDING_convert_ex __NS_SYMBOL(BN_BLINDING_convert_ex)
#endif

#ifndef NCONF_get_number_e
#define NCONF_get_number_e __NS_SYMBOL(NCONF_get_number_e)
#endif

#ifndef PKCS7_final
#define PKCS7_final __NS_SYMBOL(PKCS7_final)
#endif

#ifndef X509_REQ_add1_attr_by_NID
#define X509_REQ_add1_attr_by_NID __NS_SYMBOL(X509_REQ_add1_attr_by_NID)
#endif

#ifndef X509at_add1_attr_by_txt
#define X509at_add1_attr_by_txt __NS_SYMBOL(X509at_add1_attr_by_txt)
#endif

#ifndef d2i_ASN1_UINTEGER
#define d2i_ASN1_UINTEGER __NS_SYMBOL(d2i_ASN1_UINTEGER)
#endif

#ifndef OCSP_crlID_new
#define OCSP_crlID_new __NS_SYMBOL(OCSP_crlID_new)
#endif

#ifndef OCSP_resp_find_status
#define OCSP_resp_find_status __NS_SYMBOL(OCSP_resp_find_status)
#endif

#ifndef SRP_Calc_x
#define SRP_Calc_x __NS_SYMBOL(SRP_Calc_x)
#endif

#ifndef d2i_TS_RESP_bio
#define d2i_TS_RESP_bio __NS_SYMBOL(d2i_TS_RESP_bio)
#endif

#ifndef i2d_ASN1_GENERALIZEDTIME
#define i2d_ASN1_GENERALIZEDTIME __NS_SYMBOL(i2d_ASN1_GENERALIZEDTIME)
#endif

#ifndef i2d_DIST_POINT_NAME
#define i2d_DIST_POINT_NAME __NS_SYMBOL(i2d_DIST_POINT_NAME)
#endif

#ifndef i2d_OCSP_RESPDATA
#define i2d_OCSP_RESPDATA __NS_SYMBOL(i2d_OCSP_RESPDATA)
#endif

#ifndef i2d_RSA_PUBKEY_bio
#define i2d_RSA_PUBKEY_bio __NS_SYMBOL(i2d_RSA_PUBKEY_bio)
#endif

#ifndef i2d_X509_NAME
#define i2d_X509_NAME __NS_SYMBOL(i2d_X509_NAME)
#endif

#ifndef BIO_dump_indent
#define BIO_dump_indent __NS_SYMBOL(BIO_dump_indent)
#endif

#ifndef PEM_write_RSAPrivateKey
#define PEM_write_RSAPrivateKey __NS_SYMBOL(PEM_write_RSAPrivateKey)
#endif

#ifndef X509V3_EXT_nconf_nid
#define X509V3_EXT_nconf_nid __NS_SYMBOL(X509V3_EXT_nconf_nid)
#endif

#ifndef X509_REQ_add1_attr_by_txt
#define X509_REQ_add1_attr_by_txt __NS_SYMBOL(X509_REQ_add1_attr_by_txt)
#endif

#ifndef X509_VERIFY_PARAM_table_cleanup
#define X509_VERIFY_PARAM_table_cleanup __NS_SYMBOL(X509_VERIFY_PARAM_table_cleanup)
#endif

#ifndef ec_GF2m_simple_point_init
#define ec_GF2m_simple_point_init __NS_SYMBOL(ec_GF2m_simple_point_init)
#endif

#ifndef ASN1_GENERALIZEDTIME_new
#define ASN1_GENERALIZEDTIME_new __NS_SYMBOL(ASN1_GENERALIZEDTIME_new)
#endif

#ifndef BN_MONT_CTX_init
#define BN_MONT_CTX_init __NS_SYMBOL(BN_MONT_CTX_init)
#endif

#ifndef CRYPTO_gcm128_aad
#define CRYPTO_gcm128_aad __NS_SYMBOL(CRYPTO_gcm128_aad)
#endif

#ifndef DIST_POINT_NAME_new
#define DIST_POINT_NAME_new __NS_SYMBOL(DIST_POINT_NAME_new)
#endif

#ifndef DSO_bind_var
#define DSO_bind_var __NS_SYMBOL(DSO_bind_var)
#endif

#ifndef EVP_PKEY_get1_EC_KEY
#define EVP_PKEY_get1_EC_KEY __NS_SYMBOL(EVP_PKEY_get1_EC_KEY)
#endif

#ifndef OCSP_RESPDATA_new
#define OCSP_RESPDATA_new __NS_SYMBOL(OCSP_RESPDATA_new)
#endif

#ifndef PEM_write_PKCS8PrivateKey_nid
#define PEM_write_PKCS8PrivateKey_nid __NS_SYMBOL(PEM_write_PKCS8PrivateKey_nid)
#endif

#ifndef PEM_write_PrivateKey
#define PEM_write_PrivateKey __NS_SYMBOL(PEM_write_PrivateKey)
#endif

#ifndef PKCS12_add_key
#define PKCS12_add_key __NS_SYMBOL(PKCS12_add_key)
#endif

#ifndef TS_RESP_CTX_add_md
#define TS_RESP_CTX_add_md __NS_SYMBOL(TS_RESP_CTX_add_md)
#endif

#ifndef TS_TST_INFO_get_nonce
#define TS_TST_INFO_get_nonce __NS_SYMBOL(TS_TST_INFO_get_nonce)
#endif

#ifndef X509_NAME_new
#define X509_NAME_new __NS_SYMBOL(X509_NAME_new)
#endif

#ifndef X509_NAME_print_ex_fp
#define X509_NAME_print_ex_fp __NS_SYMBOL(X509_NAME_print_ex_fp)
#endif

#ifndef bn_mul_recursive
#define bn_mul_recursive __NS_SYMBOL(bn_mul_recursive)
#endif

#ifndef d2i_DSAPrivateKey_fp
#define d2i_DSAPrivateKey_fp __NS_SYMBOL(d2i_DSAPrivateKey_fp)
#endif

#ifndef CRYPTO_realloc
#define CRYPTO_realloc __NS_SYMBOL(CRYPTO_realloc)
#endif

#ifndef SHA384_Update
#define SHA384_Update __NS_SYMBOL(SHA384_Update)
#endif

#ifndef TS_TST_INFO_set_tsa
#define TS_TST_INFO_set_tsa __NS_SYMBOL(TS_TST_INFO_set_tsa)
#endif

#ifndef i2d_TS_RESP_bio
#define i2d_TS_RESP_bio __NS_SYMBOL(i2d_TS_RESP_bio)
#endif

#ifndef sk_push
#define sk_push __NS_SYMBOL(sk_push)
#endif

#ifndef ASN1_GENERALIZEDTIME_free
#define ASN1_GENERALIZEDTIME_free __NS_SYMBOL(ASN1_GENERALIZEDTIME_free)
#endif

#ifndef DIST_POINT_NAME_free
#define DIST_POINT_NAME_free __NS_SYMBOL(DIST_POINT_NAME_free)
#endif

#ifndef ERR_get_state
#define ERR_get_state __NS_SYMBOL(ERR_get_state)
#endif

#ifndef EVP_CipherUpdate
#define EVP_CipherUpdate __NS_SYMBOL(EVP_CipherUpdate)
#endif

#ifndef EVP_PKEY_asn1_free
#define EVP_PKEY_asn1_free __NS_SYMBOL(EVP_PKEY_asn1_free)
#endif

#ifndef OCSP_RESPDATA_free
#define OCSP_RESPDATA_free __NS_SYMBOL(OCSP_RESPDATA_free)
#endif

#ifndef PKCS7_add_certificate
#define PKCS7_add_certificate __NS_SYMBOL(PKCS7_add_certificate)
#endif

#ifndef SHA512_Transform
#define SHA512_Transform __NS_SYMBOL(SHA512_Transform)
#endif

#ifndef X509_NAME_free
#define X509_NAME_free __NS_SYMBOL(X509_NAME_free)
#endif

#ifndef BN_GF2m_mod
#define BN_GF2m_mod __NS_SYMBOL(BN_GF2m_mod)
#endif

#ifndef EVP_PKEY_decrypt_init
#define EVP_PKEY_decrypt_init __NS_SYMBOL(EVP_PKEY_decrypt_init)
#endif

#ifndef OBJ_obj2nid
#define OBJ_obj2nid __NS_SYMBOL(OBJ_obj2nid)
#endif

#ifndef SHA384
#define SHA384 __NS_SYMBOL(SHA384)
#endif

#ifndef SXNET_get_id_INTEGER
#define SXNET_get_id_INTEGER __NS_SYMBOL(SXNET_get_id_INTEGER)
#endif

#ifndef bn_expand2
#define bn_expand2 __NS_SYMBOL(bn_expand2)
#endif

#ifndef d2i_Netscape_RSA
#define d2i_Netscape_RSA __NS_SYMBOL(d2i_Netscape_RSA)
#endif

#ifndef d2i_TS_RESP_fp
#define d2i_TS_RESP_fp __NS_SYMBOL(d2i_TS_RESP_fp)
#endif

#ifndef ec_GF2m_simple_point_finish
#define ec_GF2m_simple_point_finish __NS_SYMBOL(ec_GF2m_simple_point_finish)
#endif

#ifndef i2d_DSAPrivateKey_fp
#define i2d_DSAPrivateKey_fp __NS_SYMBOL(i2d_DSAPrivateKey_fp)
#endif

#ifndef EC_KEY_check_key
#define EC_KEY_check_key __NS_SYMBOL(EC_KEY_check_key)
#endif

#ifndef EVP_DecodeBlock
#define EVP_DecodeBlock __NS_SYMBOL(EVP_DecodeBlock)
#endif

#ifndef EVP_EncryptUpdate
#define EVP_EncryptUpdate __NS_SYMBOL(EVP_EncryptUpdate)
#endif

#ifndef PEM_read_bio_RSAPublicKey
#define PEM_read_bio_RSAPublicKey __NS_SYMBOL(PEM_read_bio_RSAPublicKey)
#endif

#ifndef X509_NAME_dup
#define X509_NAME_dup __NS_SYMBOL(X509_NAME_dup)
#endif

#ifndef d2i_ASN1_VISIBLESTRING
#define d2i_ASN1_VISIBLESTRING __NS_SYMBOL(d2i_ASN1_VISIBLESTRING)
#endif

#ifndef d2i_DIST_POINT
#define d2i_DIST_POINT __NS_SYMBOL(d2i_DIST_POINT)
#endif

#ifndef d2i_OCSP_BASICRESP
#define d2i_OCSP_BASICRESP __NS_SYMBOL(d2i_OCSP_BASICRESP)
#endif

#ifndef d2i_RSA_NET
#define d2i_RSA_NET __NS_SYMBOL(d2i_RSA_NET)
#endif

#ifndef BIO_gets
#define BIO_gets __NS_SYMBOL(BIO_gets)
#endif

#ifndef BN_MONT_CTX_free
#define BN_MONT_CTX_free __NS_SYMBOL(BN_MONT_CTX_free)
#endif

#ifndef CRYPTO_remove_all_info
#define CRYPTO_remove_all_info __NS_SYMBOL(CRYPTO_remove_all_info)
#endif

#ifndef EVP_PKEY_set1_DH
#define EVP_PKEY_set1_DH __NS_SYMBOL(EVP_PKEY_set1_DH)
#endif

#ifndef X509_NAME_add_entry_by_NID
#define X509_NAME_add_entry_by_NID __NS_SYMBOL(X509_NAME_add_entry_by_NID)
#endif

#ifndef d2i_DSA_PUBKEY_fp
#define d2i_DSA_PUBKEY_fp __NS_SYMBOL(d2i_DSA_PUBKEY_fp)
#endif

#ifndef pkey_GOST94cp_decrypt
#define pkey_GOST94cp_decrypt __NS_SYMBOL(pkey_GOST94cp_decrypt)
#endif

#ifndef CRYPTO_nistcts128_decrypt_block
#define CRYPTO_nistcts128_decrypt_block __NS_SYMBOL(CRYPTO_nistcts128_decrypt_block)
#endif

#ifndef X509_NAME_set
#define X509_NAME_set __NS_SYMBOL(X509_NAME_set)
#endif

#ifndef ec_GF2m_simple_point_clear_finish
#define ec_GF2m_simple_point_clear_finish __NS_SYMBOL(ec_GF2m_simple_point_clear_finish)
#endif

#ifndef i2d_ASN1_VISIBLESTRING
#define i2d_ASN1_VISIBLESTRING __NS_SYMBOL(i2d_ASN1_VISIBLESTRING)
#endif

#ifndef i2d_DIST_POINT
#define i2d_DIST_POINT __NS_SYMBOL(i2d_DIST_POINT)
#endif

#ifndef i2d_OCSP_BASICRESP
#define i2d_OCSP_BASICRESP __NS_SYMBOL(i2d_OCSP_BASICRESP)
#endif

#ifndef i2d_TS_RESP_fp
#define i2d_TS_RESP_fp __NS_SYMBOL(i2d_TS_RESP_fp)
#endif

#ifndef CRYPTO_get_dynlock_create_callback
#define CRYPTO_get_dynlock_create_callback __NS_SYMBOL(CRYPTO_get_dynlock_create_callback)
#endif

#ifndef EVP_PKEY_asn1_get0_info
#define EVP_PKEY_asn1_get0_info __NS_SYMBOL(EVP_PKEY_asn1_get0_info)
#endif

#ifndef PEM_read_RSAPublicKey
#define PEM_read_RSAPublicKey __NS_SYMBOL(PEM_read_RSAPublicKey)
#endif

#ifndef RAND_SSLeay
#define RAND_SSLeay __NS_SYMBOL(RAND_SSLeay)
#endif

#ifndef SHA224_Update
#define SHA224_Update __NS_SYMBOL(SHA224_Update)
#endif

#ifndef TS_CONF_set_def_policy
#define TS_CONF_set_def_policy __NS_SYMBOL(TS_CONF_set_def_policy)
#endif

#ifndef TS_RESP_CTX_set_accuracy
#define TS_RESP_CTX_set_accuracy __NS_SYMBOL(TS_RESP_CTX_set_accuracy)
#endif

#ifndef i2d_DSA_PUBKEY
#define i2d_DSA_PUBKEY __NS_SYMBOL(i2d_DSA_PUBKEY)
#endif

#ifndef ASN1_VISIBLESTRING_new
#define ASN1_VISIBLESTRING_new __NS_SYMBOL(ASN1_VISIBLESTRING_new)
#endif

#ifndef BN_copy
#define BN_copy __NS_SYMBOL(BN_copy)
#endif

#ifndef CONF_get1_default_config_file
#define CONF_get1_default_config_file __NS_SYMBOL(CONF_get1_default_config_file)
#endif

#ifndef CRYPTO_get_dynlock_lock_callback
#define CRYPTO_get_dynlock_lock_callback __NS_SYMBOL(CRYPTO_get_dynlock_lock_callback)
#endif

#ifndef DIST_POINT_new
#define DIST_POINT_new __NS_SYMBOL(DIST_POINT_new)
#endif

#ifndef GENERAL_NAME_print
#define GENERAL_NAME_print __NS_SYMBOL(GENERAL_NAME_print)
#endif

#ifndef OCSP_BASICRESP_new
#define OCSP_BASICRESP_new __NS_SYMBOL(OCSP_BASICRESP_new)
#endif

#ifndef PEM_X509_INFO_write_bio
#define PEM_X509_INFO_write_bio __NS_SYMBOL(PEM_X509_INFO_write_bio)
#endif

#ifndef SHA224_Final
#define SHA224_Final __NS_SYMBOL(SHA224_Final)
#endif

#ifndef TS_TST_INFO_get_tsa
#define TS_TST_INFO_get_tsa __NS_SYMBOL(TS_TST_INFO_get_tsa)
#endif

#ifndef d2i_ESS_ISSUER_SERIAL
#define d2i_ESS_ISSUER_SERIAL __NS_SYMBOL(d2i_ESS_ISSUER_SERIAL)
#endif

#ifndef i2d_DSA_PUBKEY_fp
#define i2d_DSA_PUBKEY_fp __NS_SYMBOL(i2d_DSA_PUBKEY_fp)
#endif

#ifndef ssleay_rand_bytes
#define ssleay_rand_bytes __NS_SYMBOL(ssleay_rand_bytes)
#endif

#ifndef BN_BLINDING_invert
#define BN_BLINDING_invert __NS_SYMBOL(BN_BLINDING_invert)
#endif

#ifndef CRYPTO_get_dynlock_destroy_callback
#define CRYPTO_get_dynlock_destroy_callback __NS_SYMBOL(CRYPTO_get_dynlock_destroy_callback)
#endif

#ifndef DSO_bind_func
#define DSO_bind_func __NS_SYMBOL(DSO_bind_func)
#endif

#ifndef HMAC_CTX_set_flags
#define HMAC_CTX_set_flags __NS_SYMBOL(HMAC_CTX_set_flags)
#endif

#ifndef PKCS7_verify
#define PKCS7_verify __NS_SYMBOL(PKCS7_verify)
#endif

#ifndef RC2_encrypt
#define RC2_encrypt __NS_SYMBOL(RC2_encrypt)
#endif

#ifndef SHA256_Transform
#define SHA256_Transform __NS_SYMBOL(SHA256_Transform)
#endif

#ifndef TS_TST_INFO_get_exts
#define TS_TST_INFO_get_exts __NS_SYMBOL(TS_TST_INFO_get_exts)
#endif

#ifndef X509_get_subject_name
#define X509_get_subject_name __NS_SYMBOL(X509_get_subject_name)
#endif

#ifndef ASN1_STRING_dup
#define ASN1_STRING_dup __NS_SYMBOL(ASN1_STRING_dup)
#endif

#ifndef ASN1_VISIBLESTRING_free
#define ASN1_VISIBLESTRING_free __NS_SYMBOL(ASN1_VISIBLESTRING_free)
#endif

#ifndef BN_MONT_CTX_set
#define BN_MONT_CTX_set __NS_SYMBOL(BN_MONT_CTX_set)
#endif

#ifndef CRYPTO_set_dynlock_create_callback
#define CRYPTO_set_dynlock_create_callback __NS_SYMBOL(CRYPTO_set_dynlock_create_callback)
#endif

#ifndef DIST_POINT_free
#define DIST_POINT_free __NS_SYMBOL(DIST_POINT_free)
#endif

#ifndef EVP_PKEY_CTX_free
#define EVP_PKEY_CTX_free __NS_SYMBOL(EVP_PKEY_CTX_free)
#endif

#ifndef EVP_PKEY_get1_DH
#define EVP_PKEY_get1_DH __NS_SYMBOL(EVP_PKEY_get1_DH)
#endif

#ifndef OCSP_BASICRESP_free
#define OCSP_BASICRESP_free __NS_SYMBOL(OCSP_BASICRESP_free)
#endif

#ifndef PEM_write_PKCS8PrivateKey
#define PEM_write_PKCS8PrivateKey __NS_SYMBOL(PEM_write_PKCS8PrivateKey)
#endif

#ifndef PEM_write_bio_RSAPublicKey
#define PEM_write_bio_RSAPublicKey __NS_SYMBOL(PEM_write_bio_RSAPublicKey)
#endif

#ifndef PKCS5_v2_PBKDF2_keyivgen
#define PKCS5_v2_PBKDF2_keyivgen __NS_SYMBOL(PKCS5_v2_PBKDF2_keyivgen)
#endif

#ifndef TS_TST_INFO_ext_free
#define TS_TST_INFO_ext_free __NS_SYMBOL(TS_TST_INFO_ext_free)
#endif

#ifndef WHIRLPOOL
#define WHIRLPOOL __NS_SYMBOL(WHIRLPOOL)
#endif

#ifndef X509_get_serialNumber
#define X509_get_serialNumber __NS_SYMBOL(X509_get_serialNumber)
#endif

#ifndef d2i_DSAPrivateKey_bio
#define d2i_DSAPrivateKey_bio __NS_SYMBOL(d2i_DSAPrivateKey_bio)
#endif

#ifndef ec_GF2m_simple_point_copy
#define ec_GF2m_simple_point_copy __NS_SYMBOL(ec_GF2m_simple_point_copy)
#endif

#ifndef i2d_ESS_ISSUER_SERIAL
#define i2d_ESS_ISSUER_SERIAL __NS_SYMBOL(i2d_ESS_ISSUER_SERIAL)
#endif

#ifndef idea_encrypt
#define idea_encrypt __NS_SYMBOL(idea_encrypt)
#endif

#ifndef CMS_EncryptedData_encrypt
#define CMS_EncryptedData_encrypt __NS_SYMBOL(CMS_EncryptedData_encrypt)
#endif

#ifndef CRYPTO_set_dynlock_lock_callback
#define CRYPTO_set_dynlock_lock_callback __NS_SYMBOL(CRYPTO_set_dynlock_lock_callback)
#endif

#ifndef EVP_PKEY_decrypt
#define EVP_PKEY_decrypt __NS_SYMBOL(EVP_PKEY_decrypt)
#endif

#ifndef OBJ_NAME_cleanup
#define OBJ_NAME_cleanup __NS_SYMBOL(OBJ_NAME_cleanup)
#endif

#ifndef OCSP_accept_responses_new
#define OCSP_accept_responses_new __NS_SYMBOL(OCSP_accept_responses_new)
#endif

#ifndef RSA_verify
#define RSA_verify __NS_SYMBOL(RSA_verify)
#endif

#ifndef SXNET_get_id_asc
#define SXNET_get_id_asc __NS_SYMBOL(SXNET_get_id_asc)
#endif

#ifndef UI_dup_verify_string
#define UI_dup_verify_string __NS_SYMBOL(UI_dup_verify_string)
#endif

#ifndef X509_PURPOSE_get_by_id
#define X509_PURPOSE_get_by_id __NS_SYMBOL(X509_PURPOSE_get_by_id)
#endif

#ifndef X509_subject_name_hash
#define X509_subject_name_hash __NS_SYMBOL(X509_subject_name_hash)
#endif

#ifndef vpaes_set_encrypt_key
#define vpaes_set_encrypt_key __NS_SYMBOL(vpaes_set_encrypt_key)
#endif

#ifndef ASN1_STRING_print_ex
#define ASN1_STRING_print_ex __NS_SYMBOL(ASN1_STRING_print_ex)
#endif

#ifndef CRYPTO_set_dynlock_destroy_callback
#define CRYPTO_set_dynlock_destroy_callback __NS_SYMBOL(CRYPTO_set_dynlock_destroy_callback)
#endif

#ifndef ESS_ISSUER_SERIAL_new
#define ESS_ISSUER_SERIAL_new __NS_SYMBOL(ESS_ISSUER_SERIAL_new)
#endif

#ifndef EVP_PKEY_get0_asn1
#define EVP_PKEY_get0_asn1 __NS_SYMBOL(EVP_PKEY_get0_asn1)
#endif

#ifndef PKCS5_pbe2_set
#define PKCS5_pbe2_set __NS_SYMBOL(PKCS5_pbe2_set)
#endif

#ifndef aesni_ecb_encrypt
#define aesni_ecb_encrypt __NS_SYMBOL(aesni_ecb_encrypt)
#endif

#ifndef d2i_ASN1_UNIVERSALSTRING
#define d2i_ASN1_UNIVERSALSTRING __NS_SYMBOL(d2i_ASN1_UNIVERSALSTRING)
#endif

#ifndef d2i_CRL_DIST_POINTS
#define d2i_CRL_DIST_POINTS __NS_SYMBOL(d2i_CRL_DIST_POINTS)
#endif

#ifndef d2i_OCSP_CRLID
#define d2i_OCSP_CRLID __NS_SYMBOL(d2i_OCSP_CRLID)
#endif

#ifndef ec_GF2m_simple_oct2point
#define ec_GF2m_simple_oct2point __NS_SYMBOL(ec_GF2m_simple_oct2point)
#endif

#ifndef CRYPTO_get_locking_callback
#define CRYPTO_get_locking_callback __NS_SYMBOL(CRYPTO_get_locking_callback)
#endif

#ifndef EVP_PKEY_asn1_copy
#define EVP_PKEY_asn1_copy __NS_SYMBOL(EVP_PKEY_asn1_copy)
#endif

#ifndef TS_TST_INFO_get_ext_count
#define TS_TST_INFO_get_ext_count __NS_SYMBOL(TS_TST_INFO_get_ext_count)
#endif

#ifndef i2d_DSAPrivateKey_bio
#define i2d_DSAPrivateKey_bio __NS_SYMBOL(i2d_DSAPrivateKey_bio)
#endif

#ifndef sk_unshift
#define sk_unshift __NS_SYMBOL(sk_unshift)
#endif

#ifndef BN_BLINDING_invert_ex
#define BN_BLINDING_invert_ex __NS_SYMBOL(BN_BLINDING_invert_ex)
#endif

#ifndef CRYPTO_get_add_lock_callback
#define CRYPTO_get_add_lock_callback __NS_SYMBOL(CRYPTO_get_add_lock_callback)
#endif

#ifndef ESS_ISSUER_SERIAL_free
#define ESS_ISSUER_SERIAL_free __NS_SYMBOL(ESS_ISSUER_SERIAL_free)
#endif

#ifndef PKCS1_MGF1
#define PKCS1_MGF1 __NS_SYMBOL(PKCS1_MGF1)
#endif

#ifndef TS_TST_INFO_get_ext_by_NID
#define TS_TST_INFO_get_ext_by_NID __NS_SYMBOL(TS_TST_INFO_get_ext_by_NID)
#endif

#ifndef X509V3_add1_i2d
#define X509V3_add1_i2d __NS_SYMBOL(X509V3_add1_i2d)
#endif

#ifndef X509_ATTRIBUTE_create_by_txt
#define X509_ATTRIBUTE_create_by_txt __NS_SYMBOL(X509_ATTRIBUTE_create_by_txt)
#endif

#ifndef i2d_ASN1_UNIVERSALSTRING
#define i2d_ASN1_UNIVERSALSTRING __NS_SYMBOL(i2d_ASN1_UNIVERSALSTRING)
#endif

#ifndef i2d_CRL_DIST_POINTS
#define i2d_CRL_DIST_POINTS __NS_SYMBOL(i2d_CRL_DIST_POINTS)
#endif

#ifndef i2d_OCSP_CRLID
#define i2d_OCSP_CRLID __NS_SYMBOL(i2d_OCSP_CRLID)
#endif

#ifndef vpaes_set_decrypt_key
#define vpaes_set_decrypt_key __NS_SYMBOL(vpaes_set_decrypt_key)
#endif

#ifndef CRYPTO_set_locking_callback
#define CRYPTO_set_locking_callback __NS_SYMBOL(CRYPTO_set_locking_callback)
#endif

#ifndef EVP_PKEY_type
#define EVP_PKEY_type __NS_SYMBOL(EVP_PKEY_type)
#endif

#ifndef PEM_write_RSAPublicKey
#define PEM_write_RSAPublicKey __NS_SYMBOL(PEM_write_RSAPublicKey)
#endif

#ifndef TS_TST_INFO_get_ext_by_OBJ
#define TS_TST_INFO_get_ext_by_OBJ __NS_SYMBOL(TS_TST_INFO_get_ext_by_OBJ)
#endif

#ifndef X509V3_get_value_int
#define X509V3_get_value_int __NS_SYMBOL(X509V3_get_value_int)
#endif

#ifndef X509_PURPOSE_get0
#define X509_PURPOSE_get0 __NS_SYMBOL(X509_PURPOSE_get0)
#endif

#ifndef cms_EncryptedData_init_bio
#define cms_EncryptedData_init_bio __NS_SYMBOL(cms_EncryptedData_init_bio)
#endif

#ifndef d2i_DSA_PUBKEY_bio
#define d2i_DSA_PUBKEY_bio __NS_SYMBOL(d2i_DSA_PUBKEY_bio)
#endif

#ifndef ec_GFp_simple_point_init
#define ec_GFp_simple_point_init __NS_SYMBOL(ec_GFp_simple_point_init)
#endif

#ifndef ASN1_UNIVERSALSTRING_new
#define ASN1_UNIVERSALSTRING_new __NS_SYMBOL(ASN1_UNIVERSALSTRING_new)
#endif

#ifndef CONF_free
#define CONF_free __NS_SYMBOL(CONF_free)
#endif

#ifndef CRL_DIST_POINTS_new
#define CRL_DIST_POINTS_new __NS_SYMBOL(CRL_DIST_POINTS_new)
#endif

#ifndef ESS_ISSUER_SERIAL_dup
#define ESS_ISSUER_SERIAL_dup __NS_SYMBOL(ESS_ISSUER_SERIAL_dup)
#endif

#ifndef EVP_Digest
#define EVP_Digest __NS_SYMBOL(EVP_Digest)
#endif

#ifndef OCSP_CRLID_new
#define OCSP_CRLID_new __NS_SYMBOL(OCSP_CRLID_new)
#endif

#ifndef PKCS7_add_crl
#define PKCS7_add_crl __NS_SYMBOL(PKCS7_add_crl)
#endif

#ifndef TS_TST_INFO_get_ext_by_critical
#define TS_TST_INFO_get_ext_by_critical __NS_SYMBOL(TS_TST_INFO_get_ext_by_critical)
#endif

#ifndef X509_NAME_ENTRY_create_by_NID
#define X509_NAME_ENTRY_create_by_NID __NS_SYMBOL(X509_NAME_ENTRY_create_by_NID)
#endif

#ifndef BN_mod_exp_mont
#define BN_mod_exp_mont __NS_SYMBOL(BN_mod_exp_mont)
#endif

#ifndef CRYPTO_realloc_clean
#define CRYPTO_realloc_clean __NS_SYMBOL(CRYPTO_realloc_clean)
#endif

#ifndef CRYPTO_set_add_lock_callback
#define CRYPTO_set_add_lock_callback __NS_SYMBOL(CRYPTO_set_add_lock_callback)
#endif

#ifndef EVP_PKEY_meth_add0
#define EVP_PKEY_meth_add0 __NS_SYMBOL(EVP_PKEY_meth_add0)
#endif

#ifndef PKCS12_add_safes
#define PKCS12_add_safes __NS_SYMBOL(PKCS12_add_safes)
#endif

#ifndef TS_TST_INFO_get_ext
#define TS_TST_INFO_get_ext __NS_SYMBOL(TS_TST_INFO_get_ext)
#endif

#ifndef X509_print
#define X509_print __NS_SYMBOL(X509_print)
#endif

#ifndef ec_GF2m_simple_point_set_to_infinity
#define ec_GF2m_simple_point_set_to_infinity __NS_SYMBOL(ec_GF2m_simple_point_set_to_infinity)
#endif

#ifndef ASN1_UNIVERSALSTRING_free
#define ASN1_UNIVERSALSTRING_free __NS_SYMBOL(ASN1_UNIVERSALSTRING_free)
#endif

#ifndef BIO_indent
#define BIO_indent __NS_SYMBOL(BIO_indent)
#endif

#ifndef CRL_DIST_POINTS_free
#define CRL_DIST_POINTS_free __NS_SYMBOL(CRL_DIST_POINTS_free)
#endif

#ifndef CRYPTO_THREADID_set_numeric
#define CRYPTO_THREADID_set_numeric __NS_SYMBOL(CRYPTO_THREADID_set_numeric)
#endif

#ifndef Camellia_Ekeygen
#define Camellia_Ekeygen __NS_SYMBOL(Camellia_Ekeygen)
#endif

#ifndef DSO_set_name_converter
#define DSO_set_name_converter __NS_SYMBOL(DSO_set_name_converter)
#endif

#ifndef OCSP_CRLID_free
#define OCSP_CRLID_free __NS_SYMBOL(OCSP_CRLID_free)
#endif

#ifndef OCSP_check_validity
#define OCSP_check_validity __NS_SYMBOL(OCSP_check_validity)
#endif

#ifndef TS_CONF_set_policies
#define TS_CONF_set_policies __NS_SYMBOL(TS_CONF_set_policies)
#endif

#ifndef TS_TST_INFO_delete_ext
#define TS_TST_INFO_delete_ext __NS_SYMBOL(TS_TST_INFO_delete_ext)
#endif

#ifndef X509_signature_print
#define X509_signature_print __NS_SYMBOL(X509_signature_print)
#endif

#ifndef d2i_ESS_CERT_ID
#define d2i_ESS_CERT_ID __NS_SYMBOL(d2i_ESS_CERT_ID)
#endif

#ifndef i2d_DSA_PUBKEY_bio
#define i2d_DSA_PUBKEY_bio __NS_SYMBOL(i2d_DSA_PUBKEY_bio)
#endif

#ifndef i2t_ASN1_OBJECT
#define i2t_ASN1_OBJECT __NS_SYMBOL(i2t_ASN1_OBJECT)
#endif

#ifndef lh_retrieve
#define lh_retrieve __NS_SYMBOL(lh_retrieve)
#endif

#ifndef vpaes_encrypt
#define vpaes_encrypt __NS_SYMBOL(vpaes_encrypt)
#endif

#ifndef ASN1_INTEGER_set
#define ASN1_INTEGER_set __NS_SYMBOL(ASN1_INTEGER_set)
#endif

#ifndef BN_BLINDING_get_thread_id
#define BN_BLINDING_get_thread_id __NS_SYMBOL(BN_BLINDING_get_thread_id)
#endif

#ifndef BN_GF2m_poly2arr
#define BN_GF2m_poly2arr __NS_SYMBOL(BN_GF2m_poly2arr)
#endif

#ifndef CONF_modules_unload
#define CONF_modules_unload __NS_SYMBOL(CONF_modules_unload)
#endif

#ifndef EVP_PKEY_id
#define EVP_PKEY_id __NS_SYMBOL(EVP_PKEY_id)
#endif

#ifndef OCSP_archive_cutoff_new
#define OCSP_archive_cutoff_new __NS_SYMBOL(OCSP_archive_cutoff_new)
#endif

#ifndef TS_TST_INFO_add_ext
#define TS_TST_INFO_add_ext __NS_SYMBOL(TS_TST_INFO_add_ext)
#endif

#ifndef X509_LOOKUP_hash_dir
#define X509_LOOKUP_hash_dir __NS_SYMBOL(X509_LOOKUP_hash_dir)
#endif

#ifndef X509_PURPOSE_set
#define X509_PURPOSE_set __NS_SYMBOL(X509_PURPOSE_set)
#endif

#ifndef d2i_EC_PUBKEY
#define d2i_EC_PUBKEY __NS_SYMBOL(d2i_EC_PUBKEY)
#endif

#ifndef ec_GF2m_simple_point_set_affine_coordinates
#define ec_GF2m_simple_point_set_affine_coordinates __NS_SYMBOL(ec_GF2m_simple_point_set_affine_coordinates)
#endif

#ifndef ec_GFp_simple_point_finish
#define ec_GFp_simple_point_finish __NS_SYMBOL(ec_GFp_simple_point_finish)
#endif

#ifndef i2a_ASN1_OBJECT
#define i2a_ASN1_OBJECT __NS_SYMBOL(i2a_ASN1_OBJECT)
#endif

#ifndef BN_BLINDING_set_thread_id
#define BN_BLINDING_set_thread_id __NS_SYMBOL(BN_BLINDING_set_thread_id)
#endif

#ifndef CRYPTO_THREADID_set_pointer
#define CRYPTO_THREADID_set_pointer __NS_SYMBOL(CRYPTO_THREADID_set_pointer)
#endif

#ifndef EVP_PKEY_base_id
#define EVP_PKEY_base_id __NS_SYMBOL(EVP_PKEY_base_id)
#endif

#ifndef PEM_read_bio_RSA_PUBKEY
#define PEM_read_bio_RSA_PUBKEY __NS_SYMBOL(PEM_read_bio_RSA_PUBKEY)
#endif

#ifndef SHA512
#define SHA512 __NS_SYMBOL(SHA512)
#endif

#ifndef d2i_ASN1_BMPSTRING
#define d2i_ASN1_BMPSTRING __NS_SYMBOL(d2i_ASN1_BMPSTRING)
#endif

#ifndef d2i_EC_PUBKEY_fp
#define d2i_EC_PUBKEY_fp __NS_SYMBOL(d2i_EC_PUBKEY_fp)
#endif

#ifndef d2i_ISSUING_DIST_POINT
#define d2i_ISSUING_DIST_POINT __NS_SYMBOL(d2i_ISSUING_DIST_POINT)
#endif

#ifndef d2i_OCSP_SERVICELOC
#define d2i_OCSP_SERVICELOC __NS_SYMBOL(d2i_OCSP_SERVICELOC)
#endif

#ifndef d2i_PKCS8PrivateKey_fp
#define d2i_PKCS8PrivateKey_fp __NS_SYMBOL(d2i_PKCS8PrivateKey_fp)
#endif

#ifndef i2d_ESS_CERT_ID
#define i2d_ESS_CERT_ID __NS_SYMBOL(i2d_ESS_CERT_ID)
#endif

#ifndef pkey_GOST01cp_decrypt
#define pkey_GOST01cp_decrypt __NS_SYMBOL(pkey_GOST01cp_decrypt)
#endif

#ifndef vpaes_decrypt
#define vpaes_decrypt __NS_SYMBOL(vpaes_decrypt)
#endif

#ifndef BN_BLINDING_thread_id
#define BN_BLINDING_thread_id __NS_SYMBOL(BN_BLINDING_thread_id)
#endif

#ifndef CAST_cbc_encrypt
#define CAST_cbc_encrypt __NS_SYMBOL(CAST_cbc_encrypt)
#endif

#ifndef NCONF_free_data
#define NCONF_free_data __NS_SYMBOL(NCONF_free_data)
#endif

#ifndef TS_TST_INFO_get_ext_d2i
#define TS_TST_INFO_get_ext_d2i __NS_SYMBOL(TS_TST_INFO_get_ext_d2i)
#endif

#ifndef X509_subject_name_hash_old
#define X509_subject_name_hash_old __NS_SYMBOL(X509_subject_name_hash_old)
#endif

#ifndef ASN1_STRING_new
#define ASN1_STRING_new __NS_SYMBOL(ASN1_STRING_new)
#endif

#ifndef BN_BLINDING_get_flags
#define BN_BLINDING_get_flags __NS_SYMBOL(BN_BLINDING_get_flags)
#endif

#ifndef CRYPTO_THREADID_set_callback
#define CRYPTO_THREADID_set_callback __NS_SYMBOL(CRYPTO_THREADID_set_callback)
#endif

#ifndef ESS_CERT_ID_new
#define ESS_CERT_ID_new __NS_SYMBOL(ESS_CERT_ID_new)
#endif

#ifndef OBJ_txt2obj
#define OBJ_txt2obj __NS_SYMBOL(OBJ_txt2obj)
#endif

#ifndef X509V3_EXT_print_fp
#define X509V3_EXT_print_fp __NS_SYMBOL(X509V3_EXT_print_fp)
#endif

#ifndef X509V3_parse_list
#define X509V3_parse_list __NS_SYMBOL(X509V3_parse_list)
#endif

#ifndef ec_GFp_simple_point_clear_finish
#define ec_GFp_simple_point_clear_finish __NS_SYMBOL(ec_GFp_simple_point_clear_finish)
#endif

#ifndef i2d_ASN1_BMPSTRING
#define i2d_ASN1_BMPSTRING __NS_SYMBOL(i2d_ASN1_BMPSTRING)
#endif

#ifndef i2d_ISSUING_DIST_POINT
#define i2d_ISSUING_DIST_POINT __NS_SYMBOL(i2d_ISSUING_DIST_POINT)
#endif

#ifndef i2d_OCSP_SERVICELOC
#define i2d_OCSP_SERVICELOC __NS_SYMBOL(i2d_OCSP_SERVICELOC)
#endif

#ifndef vpaes_cbc_encrypt
#define vpaes_cbc_encrypt __NS_SYMBOL(vpaes_cbc_encrypt)
#endif

#ifndef BN_BLINDING_set_flags
#define BN_BLINDING_set_flags __NS_SYMBOL(BN_BLINDING_set_flags)
#endif

#ifndef BN_is_prime_fasttest_ex
#define BN_is_prime_fasttest_ex __NS_SYMBOL(BN_is_prime_fasttest_ex)
#endif

#ifndef CMS_verify
#define CMS_verify __NS_SYMBOL(CMS_verify)
#endif

#ifndef CONF_dump_fp
#define CONF_dump_fp __NS_SYMBOL(CONF_dump_fp)
#endif

#ifndef DSO_get_filename
#define DSO_get_filename __NS_SYMBOL(DSO_get_filename)
#endif

#ifndef PEM_read_RSA_PUBKEY
#define PEM_read_RSA_PUBKEY __NS_SYMBOL(PEM_read_RSA_PUBKEY)
#endif

#ifndef PEM_read_bio
#define PEM_read_bio __NS_SYMBOL(PEM_read_bio)
#endif

#ifndef SRP_Calc_A
#define SRP_Calc_A __NS_SYMBOL(SRP_Calc_A)
#endif

#ifndef SXNET_get_id_ulong
#define SXNET_get_id_ulong __NS_SYMBOL(SXNET_get_id_ulong)
#endif

#ifndef X509_cmp
#define X509_cmp __NS_SYMBOL(X509_cmp)
#endif

#ifndef i2d_EC_PUBKEY_fp
#define i2d_EC_PUBKEY_fp __NS_SYMBOL(i2d_EC_PUBKEY_fp)
#endif

#ifndef ASN1_BMPSTRING_new
#define ASN1_BMPSTRING_new __NS_SYMBOL(ASN1_BMPSTRING_new)
#endif

#ifndef BIO_int_ctrl
#define BIO_int_ctrl __NS_SYMBOL(BIO_int_ctrl)
#endif

#ifndef BN_swap
#define BN_swap __NS_SYMBOL(BN_swap)
#endif

#ifndef CRYPTO_THREADID_get_callback
#define CRYPTO_THREADID_get_callback __NS_SYMBOL(CRYPTO_THREADID_get_callback)
#endif

#ifndef ESS_CERT_ID_free
#define ESS_CERT_ID_free __NS_SYMBOL(ESS_CERT_ID_free)
#endif

#ifndef EVP_PKEY_CTX_ctrl
#define EVP_PKEY_CTX_ctrl __NS_SYMBOL(EVP_PKEY_CTX_ctrl)
#endif

#ifndef EVP_PKEY_free
#define EVP_PKEY_free __NS_SYMBOL(EVP_PKEY_free)
#endif

#ifndef ISSUING_DIST_POINT_new
#define ISSUING_DIST_POINT_new __NS_SYMBOL(ISSUING_DIST_POINT_new)
#endif

#ifndef OCSP_SERVICELOC_new
#define OCSP_SERVICELOC_new __NS_SYMBOL(OCSP_SERVICELOC_new)
#endif

#ifndef X509V3_EXT_i2d
#define X509V3_EXT_i2d __NS_SYMBOL(X509V3_EXT_i2d)
#endif

#ifndef X509_NAME_add_entry_by_txt
#define X509_NAME_add_entry_by_txt __NS_SYMBOL(X509_NAME_add_entry_by_txt)
#endif

#ifndef X509at_get0_data_by_OBJ
#define X509at_get0_data_by_OBJ __NS_SYMBOL(X509at_get0_data_by_OBJ)
#endif

#ifndef sk_shift
#define sk_shift __NS_SYMBOL(sk_shift)
#endif

#ifndef CMS_get0_eContentType
#define CMS_get0_eContentType __NS_SYMBOL(CMS_get0_eContentType)
#endif

#ifndef CRYPTO_THREADID_current
#define CRYPTO_THREADID_current __NS_SYMBOL(CRYPTO_THREADID_current)
#endif

#ifndef CRYPTO_ccm128_encrypt_ccm64
#define CRYPTO_ccm128_encrypt_ccm64 __NS_SYMBOL(CRYPTO_ccm128_encrypt_ccm64)
#endif

#ifndef MD4_Transform
#define MD4_Transform __NS_SYMBOL(MD4_Transform)
#endif

#ifndef OCSP_url_svcloc_new
#define OCSP_url_svcloc_new __NS_SYMBOL(OCSP_url_svcloc_new)
#endif

#ifndef TS_RESP_CTX_add_flags
#define TS_RESP_CTX_add_flags __NS_SYMBOL(TS_RESP_CTX_add_flags)
#endif

#ifndef d2i_ECPrivateKey_fp
#define d2i_ECPrivateKey_fp __NS_SYMBOL(d2i_ECPrivateKey_fp)
#endif

#ifndef gost2001_compute_public
#define gost2001_compute_public __NS_SYMBOL(gost2001_compute_public)
#endif

#ifndef ASN1_BMPSTRING_free
#define ASN1_BMPSTRING_free __NS_SYMBOL(ASN1_BMPSTRING_free)
#endif

#ifndef BN_asc2bn
#define BN_asc2bn __NS_SYMBOL(BN_asc2bn)
#endif

#ifndef CRYPTO_gcm128_encrypt
#define CRYPTO_gcm128_encrypt __NS_SYMBOL(CRYPTO_gcm128_encrypt)
#endif

#ifndef ESS_CERT_ID_dup
#define ESS_CERT_ID_dup __NS_SYMBOL(ESS_CERT_ID_dup)
#endif

#ifndef EVP_DecodeFinal
#define EVP_DecodeFinal __NS_SYMBOL(EVP_DecodeFinal)
#endif

#ifndef EVP_PKEY_asn1_set_public
#define EVP_PKEY_asn1_set_public __NS_SYMBOL(EVP_PKEY_asn1_set_public)
#endif

#ifndef ISSUING_DIST_POINT_free
#define ISSUING_DIST_POINT_free __NS_SYMBOL(ISSUING_DIST_POINT_free)
#endif

#ifndef MD4_Final
#define MD4_Final __NS_SYMBOL(MD4_Final)
#endif

#ifndef OCSP_SERVICELOC_free
#define OCSP_SERVICELOC_free __NS_SYMBOL(OCSP_SERVICELOC_free)
#endif

#ifndef PEM_write_bio_RSA_PUBKEY
#define PEM_write_bio_RSA_PUBKEY __NS_SYMBOL(PEM_write_bio_RSA_PUBKEY)
#endif

#ifndef TS_RESP_CTX_set_serial_cb
#define TS_RESP_CTX_set_serial_cb __NS_SYMBOL(TS_RESP_CTX_set_serial_cb)
#endif

#ifndef X509_PURPOSE_get_count
#define X509_PURPOSE_get_count __NS_SYMBOL(X509_PURPOSE_get_count)
#endif

#ifndef ec_GFp_simple_point_copy
#define ec_GFp_simple_point_copy __NS_SYMBOL(ec_GFp_simple_point_copy)
#endif

#ifndef gost94_compute_public
#define gost94_compute_public __NS_SYMBOL(gost94_compute_public)
#endif

#ifndef DSO_merge
#define DSO_merge __NS_SYMBOL(DSO_merge)
#endif

#ifndef PEM_read_bio_PKCS8
#define PEM_read_bio_PKCS8 __NS_SYMBOL(PEM_read_bio_PKCS8)
#endif

#ifndef TS_RESP_CTX_set_time_cb
#define TS_RESP_CTX_set_time_cb __NS_SYMBOL(TS_RESP_CTX_set_time_cb)
#endif

#ifndef TXT_DB_insert
#define TXT_DB_insert __NS_SYMBOL(TXT_DB_insert)
#endif

#ifndef BF_cbc_encrypt
#define BF_cbc_encrypt __NS_SYMBOL(BF_cbc_encrypt)
#endif

#ifndef TS_RESP_CTX_set_extension_cb
#define TS_RESP_CTX_set_extension_cb __NS_SYMBOL(TS_RESP_CTX_set_extension_cb)
#endif

#ifndef X509_PURPOSE_get_by_sname
#define X509_PURPOSE_get_by_sname __NS_SYMBOL(X509_PURPOSE_get_by_sname)
#endif

#ifndef X509_find_by_issuer_and_serial
#define X509_find_by_issuer_and_serial __NS_SYMBOL(X509_find_by_issuer_and_serial)
#endif

#ifndef d2i_ASN1_TYPE
#define d2i_ASN1_TYPE __NS_SYMBOL(d2i_ASN1_TYPE)
#endif

#ifndef d2i_ESS_SIGNING_CERT
#define d2i_ESS_SIGNING_CERT __NS_SYMBOL(d2i_ESS_SIGNING_CERT)
#endif

#ifndef i2d_ECPrivateKey_fp
#define i2d_ECPrivateKey_fp __NS_SYMBOL(i2d_ECPrivateKey_fp)
#endif

#ifndef ASN1_STRING_free
#define ASN1_STRING_free __NS_SYMBOL(ASN1_STRING_free)
#endif

#ifndef BN_GF2m_mod_mul_arr
#define BN_GF2m_mod_mul_arr __NS_SYMBOL(BN_GF2m_mod_mul_arr)
#endif

#ifndef BN_nist_mod_256
#define BN_nist_mod_256 __NS_SYMBOL(BN_nist_mod_256)
#endif

#ifndef EVP_PKEY_asn1_set_private
#define EVP_PKEY_asn1_set_private __NS_SYMBOL(EVP_PKEY_asn1_set_private)
#endif

#ifndef TS_RESP_CTX_set_status_info
#define TS_RESP_CTX_set_status_info __NS_SYMBOL(TS_RESP_CTX_set_status_info)
#endif

#ifndef BN_clear
#define BN_clear __NS_SYMBOL(BN_clear)
#endif

#ifndef EVP_PKEY_derive_init
#define EVP_PKEY_derive_init __NS_SYMBOL(EVP_PKEY_derive_init)
#endif

#ifndef PEM_read_PKCS8
#define PEM_read_PKCS8 __NS_SYMBOL(PEM_read_PKCS8)
#endif

#ifndef PKCS7_SIGNER_INFO_set
#define PKCS7_SIGNER_INFO_set __NS_SYMBOL(PKCS7_SIGNER_INFO_set)
#endif

#ifndef SRP_VBASE_get_by_user
#define SRP_VBASE_get_by_user __NS_SYMBOL(SRP_VBASE_get_by_user)
#endif

#ifndef X509_OBJECT_retrieve_by_subject
#define X509_OBJECT_retrieve_by_subject __NS_SYMBOL(X509_OBJECT_retrieve_by_subject)
#endif

#ifndef d2i_EC_PUBKEY_bio
#define d2i_EC_PUBKEY_bio __NS_SYMBOL(d2i_EC_PUBKEY_bio)
#endif

#ifndef i2d_ASN1_TYPE
#define i2d_ASN1_TYPE __NS_SYMBOL(i2d_ASN1_TYPE)
#endif

#ifndef i2d_EC_PUBKEY
#define i2d_EC_PUBKEY __NS_SYMBOL(i2d_EC_PUBKEY)
#endif

#ifndef i2d_ESS_SIGNING_CERT
#define i2d_ESS_SIGNING_CERT __NS_SYMBOL(i2d_ESS_SIGNING_CERT)
#endif

#ifndef sk_pop
#define sk_pop __NS_SYMBOL(sk_pop)
#endif

#ifndef EC_EX_DATA_set_data
#define EC_EX_DATA_set_data __NS_SYMBOL(EC_EX_DATA_set_data)
#endif

#ifndef EVP_PKEY_asn1_set_param
#define EVP_PKEY_asn1_set_param __NS_SYMBOL(EVP_PKEY_asn1_set_param)
#endif

#ifndef PEM_write_RSA_PUBKEY
#define PEM_write_RSA_PUBKEY __NS_SYMBOL(PEM_write_RSA_PUBKEY)
#endif

#ifndef ASN1_TYPE_new
#define ASN1_TYPE_new __NS_SYMBOL(ASN1_TYPE_new)
#endif

#ifndef CRYPTO_THREADID_cmp
#define CRYPTO_THREADID_cmp __NS_SYMBOL(CRYPTO_THREADID_cmp)
#endif

#ifndef ESS_SIGNING_CERT_new
#define ESS_SIGNING_CERT_new __NS_SYMBOL(ESS_SIGNING_CERT_new)
#endif

#ifndef RC2_decrypt
#define RC2_decrypt __NS_SYMBOL(RC2_decrypt)
#endif

#ifndef SRP_Calc_client_key
#define SRP_Calc_client_key __NS_SYMBOL(SRP_Calc_client_key)
#endif

#ifndef ec_GF2m_simple_point_get_affine_coordinates
#define ec_GF2m_simple_point_get_affine_coordinates __NS_SYMBOL(ec_GF2m_simple_point_get_affine_coordinates)
#endif

#ifndef lh_doall
#define lh_doall __NS_SYMBOL(lh_doall)
#endif

#ifndef ASN1_STRING_set0
#define ASN1_STRING_set0 __NS_SYMBOL(ASN1_STRING_set0)
#endif

#ifndef BN_print_fp
#define BN_print_fp __NS_SYMBOL(BN_print_fp)
#endif

#ifndef CONF_dump_bio
#define CONF_dump_bio __NS_SYMBOL(CONF_dump_bio)
#endif

#ifndef CRYPTO_THREADID_cpy
#define CRYPTO_THREADID_cpy __NS_SYMBOL(CRYPTO_THREADID_cpy)
#endif

#ifndef CRYPTO_dbg_malloc
#define CRYPTO_dbg_malloc __NS_SYMBOL(CRYPTO_dbg_malloc)
#endif

#ifndef DSO_convert_filename
#define DSO_convert_filename __NS_SYMBOL(DSO_convert_filename)
#endif

#ifndef PEM_write_bio_PKCS8
#define PEM_write_bio_PKCS8 __NS_SYMBOL(PEM_write_bio_PKCS8)
#endif

#ifndef ec_GFp_simple_point_set_to_infinity
#define ec_GFp_simple_point_set_to_infinity __NS_SYMBOL(ec_GFp_simple_point_set_to_infinity)
#endif

#ifndef fill_GOST94_params
#define fill_GOST94_params __NS_SYMBOL(fill_GOST94_params)
#endif

#ifndef i2d_EC_PUBKEY_bio
#define i2d_EC_PUBKEY_bio __NS_SYMBOL(i2d_EC_PUBKEY_bio)
#endif

#ifndef sk_zero
#define sk_zero __NS_SYMBOL(sk_zero)
#endif

#ifndef ASN1_TYPE_free
#define ASN1_TYPE_free __NS_SYMBOL(ASN1_TYPE_free)
#endif

#ifndef BN_get_word
#define BN_get_word __NS_SYMBOL(BN_get_word)
#endif

#ifndef ESS_SIGNING_CERT_free
#define ESS_SIGNING_CERT_free __NS_SYMBOL(ESS_SIGNING_CERT_free)
#endif

#ifndef EVP_DecryptUpdate
#define EVP_DecryptUpdate __NS_SYMBOL(EVP_DecryptUpdate)
#endif

#ifndef EVP_MD_CTX_destroy
#define EVP_MD_CTX_destroy __NS_SYMBOL(EVP_MD_CTX_destroy)
#endif

#ifndef EVP_PKEY_asn1_set_free
#define EVP_PKEY_asn1_set_free __NS_SYMBOL(EVP_PKEY_asn1_set_free)
#endif

#ifndef EVP_PKEY_print_public
#define EVP_PKEY_print_public __NS_SYMBOL(EVP_PKEY_print_public)
#endif

#ifndef CRYPTO_THREADID_hash
#define CRYPTO_THREADID_hash __NS_SYMBOL(CRYPTO_THREADID_hash)
#endif

#ifndef EVP_PKEY_asn1_set_ctrl
#define EVP_PKEY_asn1_set_ctrl __NS_SYMBOL(EVP_PKEY_asn1_set_ctrl)
#endif

#ifndef d2i_ASN1_OBJECT
#define d2i_ASN1_OBJECT __NS_SYMBOL(d2i_ASN1_OBJECT)
#endif

#ifndef d2i_ECPrivateKey_bio
#define d2i_ECPrivateKey_bio __NS_SYMBOL(d2i_ECPrivateKey_bio)
#endif

#ifndef ec_GFp_simple_set_Jprojective_coordinates_GFp
#define ec_GFp_simple_set_Jprojective_coordinates_GFp __NS_SYMBOL(ec_GFp_simple_set_Jprojective_coordinates_GFp)
#endif

#ifndef CMAC_resume
#define CMAC_resume __NS_SYMBOL(CMAC_resume)
#endif

#ifndef CONF_modules_finish
#define CONF_modules_finish __NS_SYMBOL(CONF_modules_finish)
#endif

#ifndef CRYPTO_get_id_callback
#define CRYPTO_get_id_callback __NS_SYMBOL(CRYPTO_get_id_callback)
#endif

#ifndef ESS_SIGNING_CERT_dup
#define ESS_SIGNING_CERT_dup __NS_SYMBOL(ESS_SIGNING_CERT_dup)
#endif

#ifndef PEM_read_bio_DSAPrivateKey
#define PEM_read_bio_DSAPrivateKey __NS_SYMBOL(PEM_read_bio_DSAPrivateKey)
#endif

#ifndef UI_add_input_boolean
#define UI_add_input_boolean __NS_SYMBOL(UI_add_input_boolean)
#endif

#ifndef d2i_ASN1_PRINTABLE
#define d2i_ASN1_PRINTABLE __NS_SYMBOL(d2i_ASN1_PRINTABLE)
#endif

#ifndef ASN1_INTEGER_get
#define ASN1_INTEGER_get __NS_SYMBOL(ASN1_INTEGER_get)
#endif

#ifndef ASN1_STRING_type_new
#define ASN1_STRING_type_new __NS_SYMBOL(ASN1_STRING_type_new)
#endif

#ifndef BN_set_word
#define BN_set_word __NS_SYMBOL(BN_set_word)
#endif

#ifndef CMS_set1_eContentType
#define CMS_set1_eContentType __NS_SYMBOL(CMS_set1_eContentType)
#endif

#ifndef CRYPTO_set_id_callback
#define CRYPTO_set_id_callback __NS_SYMBOL(CRYPTO_set_id_callback)
#endif

#ifndef PKCS7_dataDecode
#define PKCS7_dataDecode __NS_SYMBOL(PKCS7_dataDecode)
#endif

#ifndef TS_CONF_set_digests
#define TS_CONF_set_digests __NS_SYMBOL(TS_CONF_set_digests)
#endif

#ifndef X509_NAME_ENTRY_create_by_txt
#define X509_NAME_ENTRY_create_by_txt __NS_SYMBOL(X509_NAME_ENTRY_create_by_txt)
#endif

#ifndef X509_PURPOSE_add
#define X509_PURPOSE_add __NS_SYMBOL(X509_PURPOSE_add)
#endif

#ifndef sk_pop_free
#define sk_pop_free __NS_SYMBOL(sk_pop_free)
#endif

#ifndef BIO_ctrl
#define BIO_ctrl __NS_SYMBOL(BIO_ctrl)
#endif

#ifndef CRYPTO_free
#define CRYPTO_free __NS_SYMBOL(CRYPTO_free)
#endif

#ifndef CRYPTO_thread_id
#define CRYPTO_thread_id __NS_SYMBOL(CRYPTO_thread_id)
#endif

#ifndef ENGINE_up_ref
#define ENGINE_up_ref __NS_SYMBOL(ENGINE_up_ref)
#endif

#ifndef EVP_PKEY_CTX_ctrl_str
#define EVP_PKEY_CTX_ctrl_str __NS_SYMBOL(EVP_PKEY_CTX_ctrl_str)
#endif

#ifndef EVP_PKEY_derive_set_peer
#define EVP_PKEY_derive_set_peer __NS_SYMBOL(EVP_PKEY_derive_set_peer)
#endif

#ifndef PEM_write_PKCS8
#define PEM_write_PKCS8 __NS_SYMBOL(PEM_write_PKCS8)
#endif

#ifndef PKCS7_to_TS_TST_INFO
#define PKCS7_to_TS_TST_INFO __NS_SYMBOL(PKCS7_to_TS_TST_INFO)
#endif

#ifndef i2d_ASN1_PRINTABLE
#define i2d_ASN1_PRINTABLE __NS_SYMBOL(i2d_ASN1_PRINTABLE)
#endif

#ifndef i2d_ECPrivateKey_bio
#define i2d_ECPrivateKey_bio __NS_SYMBOL(i2d_ECPrivateKey_bio)
#endif

#ifndef lh_doall_arg
#define lh_doall_arg __NS_SYMBOL(lh_doall_arg)
#endif

#ifndef BN_print
#define BN_print __NS_SYMBOL(BN_print)
#endif

#ifndef CMS_RecipientInfo_kekri_get0_id
#define CMS_RecipientInfo_kekri_get0_id __NS_SYMBOL(CMS_RecipientInfo_kekri_get0_id)
#endif

#ifndef NCONF_dump_bio
#define NCONF_dump_bio __NS_SYMBOL(NCONF_dump_bio)
#endif

#ifndef ASN1_PRINTABLE_new
#define ASN1_PRINTABLE_new __NS_SYMBOL(ASN1_PRINTABLE_new)
#endif

#ifndef CRYPTO_cts128_decrypt
#define CRYPTO_cts128_decrypt __NS_SYMBOL(CRYPTO_cts128_decrypt)
#endif

#ifndef OpenSSLDie
#define OpenSSLDie __NS_SYMBOL(OpenSSLDie)
#endif

#ifndef X509_pubkey_digest
#define X509_pubkey_digest __NS_SYMBOL(X509_pubkey_digest)
#endif

#ifndef cms_encode_Receipt
#define cms_encode_Receipt __NS_SYMBOL(cms_encode_Receipt)
#endif

#ifndef ERR_clear_error
#define ERR_clear_error __NS_SYMBOL(ERR_clear_error)
#endif

#ifndef EVP_PKEY_print_private
#define EVP_PKEY_print_private __NS_SYMBOL(EVP_PKEY_print_private)
#endif

#ifndef MD4_Init
#define MD4_Init __NS_SYMBOL(MD4_Init)
#endif

#ifndef X509_find_by_subject
#define X509_find_by_subject __NS_SYMBOL(X509_find_by_subject)
#endif

#ifndef ec_GFp_simple_oct2point
#define ec_GFp_simple_oct2point __NS_SYMBOL(ec_GFp_simple_oct2point)
#endif

#ifndef gostdecrypt
#define gostdecrypt __NS_SYMBOL(gostdecrypt)
#endif

#ifndef ASN1_PRINTABLE_free
#define ASN1_PRINTABLE_free __NS_SYMBOL(ASN1_PRINTABLE_free)
#endif

#ifndef BN_MONT_CTX_copy
#define BN_MONT_CTX_copy __NS_SYMBOL(BN_MONT_CTX_copy)
#endif

#ifndef CRYPTO_add_lock
#define CRYPTO_add_lock __NS_SYMBOL(CRYPTO_add_lock)
#endif

#ifndef PEM_write_bio_DSAPrivateKey
#define PEM_write_bio_DSAPrivateKey __NS_SYMBOL(PEM_write_bio_DSAPrivateKey)
#endif

#ifndef X509_OBJECT_up_ref_count
#define X509_OBJECT_up_ref_count __NS_SYMBOL(X509_OBJECT_up_ref_count)
#endif

#ifndef X509_PUBKEY_set0_param
#define X509_PUBKEY_set0_param __NS_SYMBOL(X509_PUBKEY_set0_param)
#endif

#ifndef CRYPTO_remalloc
#define CRYPTO_remalloc __NS_SYMBOL(CRYPTO_remalloc)
#endif

#ifndef NCONF_new
#define NCONF_new __NS_SYMBOL(NCONF_new)
#endif

#ifndef PEM_read_bio_PKCS8_PRIV_KEY_INFO
#define PEM_read_bio_PKCS8_PRIV_KEY_INFO __NS_SYMBOL(PEM_read_bio_PKCS8_PRIV_KEY_INFO)
#endif

#ifndef gost2001_keygen
#define gost2001_keygen __NS_SYMBOL(gost2001_keygen)
#endif

#ifndef ASN1_STRING_cmp
#define ASN1_STRING_cmp __NS_SYMBOL(ASN1_STRING_cmp)
#endif

#ifndef CMS_add_standard_smimecap
#define CMS_add_standard_smimecap __NS_SYMBOL(CMS_add_standard_smimecap)
#endif

#ifndef EC_KEY_set_public_key_affine_coordinates
#define EC_KEY_set_public_key_affine_coordinates __NS_SYMBOL(EC_KEY_set_public_key_affine_coordinates)
#endif

#ifndef EC_POINT_new
#define EC_POINT_new __NS_SYMBOL(EC_POINT_new)
#endif

#ifndef TS_RESP_CTX_set_status_info_cond
#define TS_RESP_CTX_set_status_info_cond __NS_SYMBOL(TS_RESP_CTX_set_status_info_cond)
#endif

#ifndef TXT_DB_free
#define TXT_DB_free __NS_SYMBOL(TXT_DB_free)
#endif

#ifndef d2i_DISPLAYTEXT
#define d2i_DISPLAYTEXT __NS_SYMBOL(d2i_DISPLAYTEXT)
#endif

#ifndef sk_num
#define sk_num __NS_SYMBOL(sk_num)
#endif

#ifndef ASN1_TIME_print
#define ASN1_TIME_print __NS_SYMBOL(ASN1_TIME_print)
#endif

#ifndef BN_bin2bn
#define BN_bin2bn __NS_SYMBOL(BN_bin2bn)
#endif

#ifndef BN_to_ASN1_INTEGER
#define BN_to_ASN1_INTEGER __NS_SYMBOL(BN_to_ASN1_INTEGER)
#endif

#ifndef CONF_module_add
#define CONF_module_add __NS_SYMBOL(CONF_module_add)
#endif

#ifndef X509_digest
#define X509_digest __NS_SYMBOL(X509_digest)
#endif

#ifndef c2i_ASN1_OBJECT
#define c2i_ASN1_OBJECT __NS_SYMBOL(c2i_ASN1_OBJECT)
#endif

#ifndef lh_num_items
#define lh_num_items __NS_SYMBOL(lh_num_items)
#endif

#ifndef PEM_read_PKCS8_PRIV_KEY_INFO
#define PEM_read_PKCS8_PRIV_KEY_INFO __NS_SYMBOL(PEM_read_PKCS8_PRIV_KEY_INFO)
#endif

#ifndef X509V3_EXT_add_nconf_sk
#define X509V3_EXT_add_nconf_sk __NS_SYMBOL(X509V3_EXT_add_nconf_sk)
#endif

#ifndef ec_GF2m_simple_add
#define ec_GF2m_simple_add __NS_SYMBOL(ec_GF2m_simple_add)
#endif

#ifndef i2d_DISPLAYTEXT
#define i2d_DISPLAYTEXT __NS_SYMBOL(i2d_DISPLAYTEXT)
#endif

#ifndef sk_value
#define sk_value __NS_SYMBOL(sk_value)
#endif

#ifndef v2i_GENERAL_NAMES
#define v2i_GENERAL_NAMES __NS_SYMBOL(v2i_GENERAL_NAMES)
#endif

#ifndef NCONF_free
#define NCONF_free __NS_SYMBOL(NCONF_free)
#endif

#ifndef PEM_write_DSAPrivateKey
#define PEM_write_DSAPrivateKey __NS_SYMBOL(PEM_write_DSAPrivateKey)
#endif

#ifndef X509_CRL_digest
#define X509_CRL_digest __NS_SYMBOL(X509_CRL_digest)
#endif

#ifndef X509_NAME_ENTRY_set_object
#define X509_NAME_ENTRY_set_object __NS_SYMBOL(X509_NAME_ENTRY_set_object)
#endif

#ifndef gost_sign_keygen
#define gost_sign_keygen __NS_SYMBOL(gost_sign_keygen)
#endif

#ifndef DISPLAYTEXT_new
#define DISPLAYTEXT_new __NS_SYMBOL(DISPLAYTEXT_new)
#endif

#ifndef EVP_PKEY_print_params
#define EVP_PKEY_print_params __NS_SYMBOL(EVP_PKEY_print_params)
#endif

#ifndef X509_STORE_add_cert
#define X509_STORE_add_cert __NS_SYMBOL(X509_STORE_add_cert)
#endif

#ifndef asn1_add_error
#define asn1_add_error __NS_SYMBOL(asn1_add_error)
#endif

#ifndef CMS_RecipientInfo_set0_key
#define CMS_RecipientInfo_set0_key __NS_SYMBOL(CMS_RecipientInfo_set0_key)
#endif

#ifndef DSO_get_loaded_filename
#define DSO_get_loaded_filename __NS_SYMBOL(DSO_get_loaded_filename)
#endif

#ifndef NCONF_load
#define NCONF_load __NS_SYMBOL(NCONF_load)
#endif

#ifndef PEM_write_bio_PKCS8_PRIV_KEY_INFO
#define PEM_write_bio_PKCS8_PRIV_KEY_INFO __NS_SYMBOL(PEM_write_bio_PKCS8_PRIV_KEY_INFO)
#endif

#ifndef X509_PUBKEY_get0_param
#define X509_PUBKEY_get0_param __NS_SYMBOL(X509_PUBKEY_get0_param)
#endif

#ifndef X509_REQ_digest
#define X509_REQ_digest __NS_SYMBOL(X509_REQ_digest)
#endif

#ifndef X509_ocspid_print
#define X509_ocspid_print __NS_SYMBOL(X509_ocspid_print)
#endif

#ifndef sk_set
#define sk_set __NS_SYMBOL(sk_set)
#endif

#ifndef BN_MONT_CTX_set_locked
#define BN_MONT_CTX_set_locked __NS_SYMBOL(BN_MONT_CTX_set_locked)
#endif

#ifndef DISPLAYTEXT_free
#define DISPLAYTEXT_free __NS_SYMBOL(DISPLAYTEXT_free)
#endif

#ifndef TS_RESP_CTX_add_failure_info
#define TS_RESP_CTX_add_failure_info __NS_SYMBOL(TS_RESP_CTX_add_failure_info)
#endif

#ifndef CRYPTO_get_lock_name
#define CRYPTO_get_lock_name __NS_SYMBOL(CRYPTO_get_lock_name)
#endif

#ifndef ERR_get_error
#define ERR_get_error __NS_SYMBOL(ERR_get_error)
#endif

#ifndef X509_NAME_digest
#define X509_NAME_digest __NS_SYMBOL(X509_NAME_digest)
#endif

#ifndef CMS_is_detached
#define CMS_is_detached __NS_SYMBOL(CMS_is_detached)
#endif

#ifndef PEM_read_bio_DSA_PUBKEY
#define PEM_read_bio_DSA_PUBKEY __NS_SYMBOL(PEM_read_bio_DSA_PUBKEY)
#endif

#ifndef PKCS7_add_signature
#define PKCS7_add_signature __NS_SYMBOL(PKCS7_add_signature)
#endif

#ifndef d2i_DIRECTORYSTRING
#define d2i_DIRECTORYSTRING __NS_SYMBOL(d2i_DIRECTORYSTRING)
#endif

#ifndef sk_sort
#define sk_sort __NS_SYMBOL(sk_sort)
#endif

#ifndef DSO_pathbyaddr
#define DSO_pathbyaddr __NS_SYMBOL(DSO_pathbyaddr)
#endif

#ifndef EVP_PKEY_CTX_get_operation
#define EVP_PKEY_CTX_get_operation __NS_SYMBOL(EVP_PKEY_CTX_get_operation)
#endif

#ifndef NCONF_load_fp
#define NCONF_load_fp __NS_SYMBOL(NCONF_load_fp)
#endif

#ifndef PKCS7_ISSUER_AND_SERIAL_digest
#define PKCS7_ISSUER_AND_SERIAL_digest __NS_SYMBOL(PKCS7_ISSUER_AND_SERIAL_digest)
#endif

#ifndef X509_NAME_ENTRY_set_data
#define X509_NAME_ENTRY_set_data __NS_SYMBOL(X509_NAME_ENTRY_set_data)
#endif

#ifndef gcm_init_clmul
#define gcm_init_clmul __NS_SYMBOL(gcm_init_clmul)
#endif

#ifndef i2b_PVK_bio
#define i2b_PVK_bio __NS_SYMBOL(i2b_PVK_bio)
#endif

#ifndef BIO_ptr_ctrl
#define BIO_ptr_ctrl __NS_SYMBOL(BIO_ptr_ctrl)
#endif

#ifndef BN_options
#define BN_options __NS_SYMBOL(BN_options)
#endif

#ifndef CMS_RecipientInfo_decrypt
#define CMS_RecipientInfo_decrypt __NS_SYMBOL(CMS_RecipientInfo_decrypt)
#endif

#ifndef EVP_PKEY_CTX_set0_keygen_info
#define EVP_PKEY_CTX_set0_keygen_info __NS_SYMBOL(EVP_PKEY_CTX_set0_keygen_info)
#endif

#ifndef PEM_write_PKCS8_PRIV_KEY_INFO
#define PEM_write_PKCS8_PRIV_KEY_INFO __NS_SYMBOL(PEM_write_PKCS8_PRIV_KEY_INFO)
#endif

#ifndef X509_get_pubkey
#define X509_get_pubkey __NS_SYMBOL(X509_get_pubkey)
#endif

#ifndef i2d_DIRECTORYSTRING
#define i2d_DIRECTORYSTRING __NS_SYMBOL(i2d_DIRECTORYSTRING)
#endif

#ifndef CRYPTO_set_mem_debug_options
#define CRYPTO_set_mem_debug_options __NS_SYMBOL(CRYPTO_set_mem_debug_options)
#endif

#ifndef EVP_PKEY_CTX_set_data
#define EVP_PKEY_CTX_set_data __NS_SYMBOL(EVP_PKEY_CTX_set_data)
#endif

#ifndef EVP_PKEY_get_default_digest_nid
#define EVP_PKEY_get_default_digest_nid __NS_SYMBOL(EVP_PKEY_get_default_digest_nid)
#endif

#ifndef OCSP_sendreq_bio
#define OCSP_sendreq_bio __NS_SYMBOL(OCSP_sendreq_bio)
#endif

#ifndef PEM_read_DSA_PUBKEY
#define PEM_read_DSA_PUBKEY __NS_SYMBOL(PEM_read_DSA_PUBKEY)
#endif

#ifndef d2i_PKCS8_fp
#define d2i_PKCS8_fp __NS_SYMBOL(d2i_PKCS8_fp)
#endif

#ifndef unpack_cp_signature
#define unpack_cp_signature __NS_SYMBOL(unpack_cp_signature)
#endif

#ifndef CONF_modules_free
#define CONF_modules_free __NS_SYMBOL(CONF_modules_free)
#endif

#ifndef DIRECTORYSTRING_new
#define DIRECTORYSTRING_new __NS_SYMBOL(DIRECTORYSTRING_new)
#endif

#ifndef EVP_PKEY_CTX_get_data
#define EVP_PKEY_CTX_get_data __NS_SYMBOL(EVP_PKEY_CTX_get_data)
#endif

#ifndef TS_CONF_set_accuracy
#define TS_CONF_set_accuracy __NS_SYMBOL(TS_CONF_set_accuracy)
#endif

#ifndef X509_get0_pubkey_bitstr
#define X509_get0_pubkey_bitstr __NS_SYMBOL(X509_get0_pubkey_bitstr)
#endif

#ifndef sk_is_sorted
#define sk_is_sorted __NS_SYMBOL(sk_is_sorted)
#endif

#ifndef CRYPTO_get_mem_debug_options
#define CRYPTO_get_mem_debug_options __NS_SYMBOL(CRYPTO_get_mem_debug_options)
#endif

#ifndef EC_POINT_copy
#define EC_POINT_copy __NS_SYMBOL(EC_POINT_copy)
#endif

#ifndef EVP_PKEY_CTX_get0_pkey
#define EVP_PKEY_CTX_get0_pkey __NS_SYMBOL(EVP_PKEY_CTX_get0_pkey)
#endif

#ifndef OPENSSL_ia32cap_loc
#define OPENSSL_ia32cap_loc __NS_SYMBOL(OPENSSL_ia32cap_loc)
#endif

#ifndef ASN1_STRING_length
#define ASN1_STRING_length __NS_SYMBOL(ASN1_STRING_length)
#endif

#ifndef CONF_imodule_get_name
#define CONF_imodule_get_name __NS_SYMBOL(CONF_imodule_get_name)
#endif

#ifndef DIRECTORYSTRING_free
#define DIRECTORYSTRING_free __NS_SYMBOL(DIRECTORYSTRING_free)
#endif

#ifndef EVP_PKEY_CTX_get0_peerkey
#define EVP_PKEY_CTX_get0_peerkey __NS_SYMBOL(EVP_PKEY_CTX_get0_peerkey)
#endif

#ifndef OPENSSL_cpuid_setup
#define OPENSSL_cpuid_setup __NS_SYMBOL(OPENSSL_cpuid_setup)
#endif

#ifndef PEM_write_bio_DSA_PUBKEY
#define PEM_write_bio_DSA_PUBKEY __NS_SYMBOL(PEM_write_bio_DSA_PUBKEY)
#endif

#ifndef TS_RESP_CTX_get_request
#define TS_RESP_CTX_get_request __NS_SYMBOL(TS_RESP_CTX_get_request)
#endif

#ifndef X509_ATTRIBUTE_count
#define X509_ATTRIBUTE_count __NS_SYMBOL(X509_ATTRIBUTE_count)
#endif

#ifndef X509_check_private_key
#define X509_check_private_key __NS_SYMBOL(X509_check_private_key)
#endif

#ifndef i2d_PKCS8_fp
#define i2d_PKCS8_fp __NS_SYMBOL(i2d_PKCS8_fp)
#endif

#ifndef ASN1_STRING_length_set
#define ASN1_STRING_length_set __NS_SYMBOL(ASN1_STRING_length_set)
#endif

#ifndef CONF_imodule_get_value
#define CONF_imodule_get_value __NS_SYMBOL(CONF_imodule_get_value)
#endif

#ifndef CRYPTO_ccm128_decrypt_ccm64
#define CRYPTO_ccm128_decrypt_ccm64 __NS_SYMBOL(CRYPTO_ccm128_decrypt_ccm64)
#endif

#ifndef CRYPTO_nistcts128_decrypt
#define CRYPTO_nistcts128_decrypt __NS_SYMBOL(CRYPTO_nistcts128_decrypt)
#endif

#ifndef EVP_CipherFinal_ex
#define EVP_CipherFinal_ex __NS_SYMBOL(EVP_CipherFinal_ex)
#endif

#ifndef EVP_PKEY_CTX_set_app_data
#define EVP_PKEY_CTX_set_app_data __NS_SYMBOL(EVP_PKEY_CTX_set_app_data)
#endif

#ifndef TS_RESP_CTX_get_tst_info
#define TS_RESP_CTX_get_tst_info __NS_SYMBOL(TS_RESP_CTX_get_tst_info)
#endif

#ifndef v2i_GENERAL_NAME
#define v2i_GENERAL_NAME __NS_SYMBOL(v2i_GENERAL_NAME)
#endif

#ifndef ASN1_STRING_type
#define ASN1_STRING_type __NS_SYMBOL(ASN1_STRING_type)
#endif

#ifndef CONF_imodule_get_usr_data
#define CONF_imodule_get_usr_data __NS_SYMBOL(CONF_imodule_get_usr_data)
#endif

#ifndef EVP_PKEY_CTX_get_app_data
#define EVP_PKEY_CTX_get_app_data __NS_SYMBOL(EVP_PKEY_CTX_get_app_data)
#endif

#ifndef TS_RESP_CTX_set_clock_precision_digits
#define TS_RESP_CTX_set_clock_precision_digits __NS_SYMBOL(TS_RESP_CTX_set_clock_precision_digits)
#endif

#ifndef d2i_ASN1_SEQUENCE_ANY
#define d2i_ASN1_SEQUENCE_ANY __NS_SYMBOL(d2i_ASN1_SEQUENCE_ANY)
#endif

#ifndef d2i_PKCS8_bio
#define d2i_PKCS8_bio __NS_SYMBOL(d2i_PKCS8_bio)
#endif

#ifndef ASN1_STRING_data
#define ASN1_STRING_data __NS_SYMBOL(ASN1_STRING_data)
#endif

#ifndef CONF_imodule_set_usr_data
#define CONF_imodule_set_usr_data __NS_SYMBOL(CONF_imodule_set_usr_data)
#endif

#ifndef DSO_global_lookup
#define DSO_global_lookup __NS_SYMBOL(DSO_global_lookup)
#endif

#ifndef EVP_EncryptFinal_ex
#define EVP_EncryptFinal_ex __NS_SYMBOL(EVP_EncryptFinal_ex)
#endif

#ifndef EVP_PKEY_meth_set_init
#define EVP_PKEY_meth_set_init __NS_SYMBOL(EVP_PKEY_meth_set_init)
#endif

#ifndef X509_ATTRIBUTE_get0_data
#define X509_ATTRIBUTE_get0_data __NS_SYMBOL(X509_ATTRIBUTE_get0_data)
#endif

#ifndef bn_scatter5
#define bn_scatter5 __NS_SYMBOL(bn_scatter5)
#endif

#ifndef ASN1_INTEGER_to_BN
#define ASN1_INTEGER_to_BN __NS_SYMBOL(ASN1_INTEGER_to_BN)
#endif

#ifndef CONF_imodule_get_module
#define CONF_imodule_get_module __NS_SYMBOL(CONF_imodule_get_module)
#endif

#ifndef EVP_PKEY_meth_set_copy
#define EVP_PKEY_meth_set_copy __NS_SYMBOL(EVP_PKEY_meth_set_copy)
#endif

#ifndef TS_RESP_create_response
#define TS_RESP_create_response __NS_SYMBOL(TS_RESP_create_response)
#endif

#ifndef X509V3_EXT_add_nconf
#define X509V3_EXT_add_nconf __NS_SYMBOL(X509V3_EXT_add_nconf)
#endif

#ifndef i2d_ASN1_SEQUENCE_ANY
#define i2d_ASN1_SEQUENCE_ANY __NS_SYMBOL(i2d_ASN1_SEQUENCE_ANY)
#endif

#ifndef v2i_GENERAL_NAME_ex
#define v2i_GENERAL_NAME_ex __NS_SYMBOL(v2i_GENERAL_NAME_ex)
#endif

#ifndef CONF_imodule_get_flags
#define CONF_imodule_get_flags __NS_SYMBOL(CONF_imodule_get_flags)
#endif

#ifndef EVP_PKEY_meth_set_cleanup
#define EVP_PKEY_meth_set_cleanup __NS_SYMBOL(EVP_PKEY_meth_set_cleanup)
#endif

#ifndef NCONF_dump_fp
#define NCONF_dump_fp __NS_SYMBOL(NCONF_dump_fp)
#endif

#ifndef PEM_write_DSA_PUBKEY
#define PEM_write_DSA_PUBKEY __NS_SYMBOL(PEM_write_DSA_PUBKEY)
#endif

#ifndef i2d_PKCS8_bio
#define i2d_PKCS8_bio __NS_SYMBOL(i2d_PKCS8_bio)
#endif

#ifndef CONF_imodule_set_flags
#define CONF_imodule_set_flags __NS_SYMBOL(CONF_imodule_set_flags)
#endif

#ifndef EC_GROUP_dup
#define EC_GROUP_dup __NS_SYMBOL(EC_GROUP_dup)
#endif

#ifndef EVP_PKEY_meth_set_paramgen
#define EVP_PKEY_meth_set_paramgen __NS_SYMBOL(EVP_PKEY_meth_set_paramgen)
#endif

#ifndef PKCS7_set_digest
#define PKCS7_set_digest __NS_SYMBOL(PKCS7_set_digest)
#endif

#ifndef X509V3_EXT_CRL_add_nconf
#define X509V3_EXT_CRL_add_nconf __NS_SYMBOL(X509V3_EXT_CRL_add_nconf)
#endif

#ifndef bn_gather5
#define bn_gather5 __NS_SYMBOL(bn_gather5)
#endif

#ifndef d2i_ASN1_SET_ANY
#define d2i_ASN1_SET_ANY __NS_SYMBOL(d2i_ASN1_SET_ANY)
#endif

#ifndef BN_GF2m_mod_sqr_arr
#define BN_GF2m_mod_sqr_arr __NS_SYMBOL(BN_GF2m_mod_sqr_arr)
#endif

#ifndef CONF_module_get_usr_data
#define CONF_module_get_usr_data __NS_SYMBOL(CONF_module_get_usr_data)
#endif

#ifndef EVP_PKEY_meth_set_keygen
#define EVP_PKEY_meth_set_keygen __NS_SYMBOL(EVP_PKEY_meth_set_keygen)
#endif

#ifndef asn1_template_print_ctx
#define asn1_template_print_ctx __NS_SYMBOL(asn1_template_print_ctx)
#endif

#ifndef d2i_PKCS8_PRIV_KEY_INFO_fp
#define d2i_PKCS8_PRIV_KEY_INFO_fp __NS_SYMBOL(d2i_PKCS8_PRIV_KEY_INFO_fp)
#endif

#ifndef CONF_module_set_usr_data
#define CONF_module_set_usr_data __NS_SYMBOL(CONF_module_set_usr_data)
#endif

#ifndef EVP_PKEY_meth_set_sign
#define EVP_PKEY_meth_set_sign __NS_SYMBOL(EVP_PKEY_meth_set_sign)
#endif

#ifndef X509V3_EXT_REQ_add_nconf
#define X509V3_EXT_REQ_add_nconf __NS_SYMBOL(X509V3_EXT_REQ_add_nconf)
#endif

#ifndef cms_DigestAlgorithm_set
#define cms_DigestAlgorithm_set __NS_SYMBOL(cms_DigestAlgorithm_set)
#endif

#ifndef ec_GFp_simple_get_Jprojective_coordinates_GFp
#define ec_GFp_simple_get_Jprojective_coordinates_GFp __NS_SYMBOL(ec_GFp_simple_get_Jprojective_coordinates_GFp)
#endif

#ifndef i2d_ASN1_SET_ANY
#define i2d_ASN1_SET_ANY __NS_SYMBOL(i2d_ASN1_SET_ANY)
#endif

#ifndef AES_decrypt
#define AES_decrypt __NS_SYMBOL(AES_decrypt)
#endif

#ifndef CONF_parse_list
#define CONF_parse_list __NS_SYMBOL(CONF_parse_list)
#endif

#ifndef EVP_PKEY_meth_set_verify
#define EVP_PKEY_meth_set_verify __NS_SYMBOL(EVP_PKEY_meth_set_verify)
#endif

#ifndef SRP_create_verifier
#define SRP_create_verifier __NS_SYMBOL(SRP_create_verifier)
#endif

#ifndef X509_NAME_ENTRY_get_object
#define X509_NAME_ENTRY_get_object __NS_SYMBOL(X509_NAME_ENTRY_get_object)
#endif

#ifndef asm_AES_decrypt
#define asm_AES_decrypt __NS_SYMBOL(asm_AES_decrypt)
#endif

#ifndef bn_mul_comba4
#define bn_mul_comba4 __NS_SYMBOL(bn_mul_comba4)
#endif

#ifndef EVP_PKEY_meth_set_verify_recover
#define EVP_PKEY_meth_set_verify_recover __NS_SYMBOL(EVP_PKEY_meth_set_verify_recover)
#endif

#ifndef PEM_read_DSAPrivateKey
#define PEM_read_DSAPrivateKey __NS_SYMBOL(PEM_read_DSAPrivateKey)
#endif

#ifndef gcm_gmult_clmul
#define gcm_gmult_clmul __NS_SYMBOL(gcm_gmult_clmul)
#endif

#ifndef i2d_PKCS8_PRIV_KEY_INFO_fp
#define i2d_PKCS8_PRIV_KEY_INFO_fp __NS_SYMBOL(i2d_PKCS8_PRIV_KEY_INFO_fp)
#endif

#ifndef BIO_callback_ctrl
#define BIO_callback_ctrl __NS_SYMBOL(BIO_callback_ctrl)
#endif

#ifndef EC_GROUP_method_of
#define EC_GROUP_method_of __NS_SYMBOL(EC_GROUP_method_of)
#endif

#ifndef EVP_PKEY_meth_set_signctx
#define EVP_PKEY_meth_set_signctx __NS_SYMBOL(EVP_PKEY_meth_set_signctx)
#endif

#ifndef SRP_Verify_B_mod_N
#define SRP_Verify_B_mod_N __NS_SYMBOL(SRP_Verify_B_mod_N)
#endif

#ifndef ASN1_STRING_print_ex_fp
#define ASN1_STRING_print_ex_fp __NS_SYMBOL(ASN1_STRING_print_ex_fp)
#endif

#ifndef EC_METHOD_get_field_type
#define EC_METHOD_get_field_type __NS_SYMBOL(EC_METHOD_get_field_type)
#endif

#ifndef EVP_PKEY_derive
#define EVP_PKEY_derive __NS_SYMBOL(EVP_PKEY_derive)
#endif

#ifndef EVP_PKEY_meth_set_verifyctx
#define EVP_PKEY_meth_set_verifyctx __NS_SYMBOL(EVP_PKEY_meth_set_verifyctx)
#endif

#ifndef OPENSSL_showfatal
#define OPENSSL_showfatal __NS_SYMBOL(OPENSSL_showfatal)
#endif

#ifndef cms_DigestAlgorithm_init_bio
#define cms_DigestAlgorithm_init_bio __NS_SYMBOL(cms_DigestAlgorithm_init_bio)
#endif

#ifndef i2d_PKCS8PrivateKeyInfo_fp
#define i2d_PKCS8PrivateKeyInfo_fp __NS_SYMBOL(i2d_PKCS8PrivateKeyInfo_fp)
#endif

#ifndef EC_GROUP_set_generator
#define EC_GROUP_set_generator __NS_SYMBOL(EC_GROUP_set_generator)
#endif

#ifndef SMIME_read_ASN1
#define SMIME_read_ASN1 __NS_SYMBOL(SMIME_read_ASN1)
#endif

#ifndef X509_get_pubkey_parameters
#define X509_get_pubkey_parameters __NS_SYMBOL(X509_get_pubkey_parameters)
#endif

#ifndef ASN1_STRING_to_UTF8
#define ASN1_STRING_to_UTF8 __NS_SYMBOL(ASN1_STRING_to_UTF8)
#endif

#ifndef EVP_PKEY_meth_set_encrypt
#define EVP_PKEY_meth_set_encrypt __NS_SYMBOL(EVP_PKEY_meth_set_encrypt)
#endif

#ifndef X509V3_get_string
#define X509V3_get_string __NS_SYMBOL(X509V3_get_string)
#endif

#ifndef X509_ATTRIBUTE_set1_object
#define X509_ATTRIBUTE_set1_object __NS_SYMBOL(X509_ATTRIBUTE_set1_object)
#endif

#ifndef X509_OBJECT_retrieve_match
#define X509_OBJECT_retrieve_match __NS_SYMBOL(X509_OBJECT_retrieve_match)
#endif

#ifndef X509_PURPOSE_cleanup
#define X509_PURPOSE_cleanup __NS_SYMBOL(X509_PURPOSE_cleanup)
#endif

#ifndef getbnfrombuf
#define getbnfrombuf __NS_SYMBOL(getbnfrombuf)
#endif

#ifndef UI_dup_input_boolean
#define UI_dup_input_boolean __NS_SYMBOL(UI_dup_input_boolean)
#endif

#ifndef EVP_PKEY_meth_set_decrypt
#define EVP_PKEY_meth_set_decrypt __NS_SYMBOL(EVP_PKEY_meth_set_decrypt)
#endif

#ifndef PEM_read_bio_DSAparams
#define PEM_read_bio_DSAparams __NS_SYMBOL(PEM_read_bio_DSAparams)
#endif

#ifndef BN_bn2bin
#define BN_bn2bin __NS_SYMBOL(BN_bn2bin)
#endif

#ifndef PKCS7_get_signer_info
#define PKCS7_get_signer_info __NS_SYMBOL(PKCS7_get_signer_info)
#endif

#ifndef i2d_PrivateKey_fp
#define i2d_PrivateKey_fp __NS_SYMBOL(i2d_PrivateKey_fp)
#endif

#ifndef CMS_add_smimecap
#define CMS_add_smimecap __NS_SYMBOL(CMS_add_smimecap)
#endif

#ifndef EC_KEY_set_public_key
#define EC_KEY_set_public_key __NS_SYMBOL(EC_KEY_set_public_key)
#endif

#ifndef EVP_PKEY_meth_set_derive
#define EVP_PKEY_meth_set_derive __NS_SYMBOL(EVP_PKEY_meth_set_derive)
#endif

#ifndef X509_ATTRIBUTE_set1_data
#define X509_ATTRIBUTE_set1_data __NS_SYMBOL(X509_ATTRIBUTE_set1_data)
#endif

#ifndef PEM_read_DSAparams
#define PEM_read_DSAparams __NS_SYMBOL(PEM_read_DSAparams)
#endif

#ifndef X509V3_get_section
#define X509V3_get_section __NS_SYMBOL(X509V3_get_section)
#endif

#ifndef X509_signature_dump
#define X509_signature_dump __NS_SYMBOL(X509_signature_dump)
#endif

#ifndef d2i_PrivateKey_fp
#define d2i_PrivateKey_fp __NS_SYMBOL(d2i_PrivateKey_fp)
#endif

#ifndef CRYPTO_dbg_free
#define CRYPTO_dbg_free __NS_SYMBOL(CRYPTO_dbg_free)
#endif

#ifndef EVP_DecryptFinal_ex
#define EVP_DecryptFinal_ex __NS_SYMBOL(EVP_DecryptFinal_ex)
#endif

#ifndef EVP_PKEY_meth_set_ctrl
#define EVP_PKEY_meth_set_ctrl __NS_SYMBOL(EVP_PKEY_meth_set_ctrl)
#endif

#ifndef SRP_Verify_A_mod_N
#define SRP_Verify_A_mod_N __NS_SYMBOL(SRP_Verify_A_mod_N)
#endif

#ifndef OBJ_sn2nid
#define OBJ_sn2nid __NS_SYMBOL(OBJ_sn2nid)
#endif

#ifndef PKCS7_SIGNER_INFO_get0_algs
#define PKCS7_SIGNER_INFO_get0_algs __NS_SYMBOL(PKCS7_SIGNER_INFO_get0_algs)
#endif

#ifndef private_AES_set_encrypt_key
#define private_AES_set_encrypt_key __NS_SYMBOL(private_AES_set_encrypt_key)
#endif

#ifndef EC_KEY_get0_group
#define EC_KEY_get0_group __NS_SYMBOL(EC_KEY_get0_group)
#endif

#ifndef PEM_write_bio_DSAparams
#define PEM_write_bio_DSAparams __NS_SYMBOL(PEM_write_bio_DSAparams)
#endif

#ifndef gcm_ghash_clmul
#define gcm_ghash_clmul __NS_SYMBOL(gcm_ghash_clmul)
#endif

#ifndef i2d_PUBKEY_fp
#define i2d_PUBKEY_fp __NS_SYMBOL(i2d_PUBKEY_fp)
#endif

#ifndef BIO_ctrl_pending
#define BIO_ctrl_pending __NS_SYMBOL(BIO_ctrl_pending)
#endif

#ifndef EC_KEY_set_group
#define EC_KEY_set_group __NS_SYMBOL(EC_KEY_set_group)
#endif

#ifndef CMS_SignerInfo_sign
#define CMS_SignerInfo_sign __NS_SYMBOL(CMS_SignerInfo_sign)
#endif

#ifndef OPENSSL_isservice
#define OPENSSL_isservice __NS_SYMBOL(OPENSSL_isservice)
#endif

#ifndef PKCS7_RECIP_INFO_get0_alg
#define PKCS7_RECIP_INFO_get0_alg __NS_SYMBOL(PKCS7_RECIP_INFO_get0_alg)
#endif

#ifndef X509V3_string_free
#define X509V3_string_free __NS_SYMBOL(X509V3_string_free)
#endif

#ifndef d2i_PUBKEY_fp
#define d2i_PUBKEY_fp __NS_SYMBOL(d2i_PUBKEY_fp)
#endif

#ifndef OPENSSL_stderr
#define OPENSSL_stderr __NS_SYMBOL(OPENSSL_stderr)
#endif

#ifndef bn_mul_normal
#define bn_mul_normal __NS_SYMBOL(bn_mul_normal)
#endif

#ifndef ASN1_template_d2i
#define ASN1_template_d2i __NS_SYMBOL(ASN1_template_d2i)
#endif

#ifndef CRYPTO_memcmp
#define CRYPTO_memcmp __NS_SYMBOL(CRYPTO_memcmp)
#endif

#ifndef PKCS7_add_recipient
#define PKCS7_add_recipient __NS_SYMBOL(PKCS7_add_recipient)
#endif

#ifndef X509V3_section_free
#define X509V3_section_free __NS_SYMBOL(X509V3_section_free)
#endif

#ifndef d2i_CERTIFICATEPOLICIES
#define d2i_CERTIFICATEPOLICIES __NS_SYMBOL(d2i_CERTIFICATEPOLICIES)
#endif

#ifndef ASN1_template_i2d
#define ASN1_template_i2d __NS_SYMBOL(ASN1_template_i2d)
#endif

#ifndef BN_ucmp
#define BN_ucmp __NS_SYMBOL(BN_ucmp)
#endif

#ifndef EC_KEY_get0_private_key
#define EC_KEY_get0_private_key __NS_SYMBOL(EC_KEY_get0_private_key)
#endif

#ifndef EC_KEY_print_fp
#define EC_KEY_print_fp __NS_SYMBOL(EC_KEY_print_fp)
#endif

#ifndef PEM_write_DSAparams
#define PEM_write_DSAparams __NS_SYMBOL(PEM_write_DSAparams)
#endif

#ifndef X509_PURPOSE_get_id
#define X509_PURPOSE_get_id __NS_SYMBOL(X509_PURPOSE_get_id)
#endif

#ifndef a2i_GENERAL_NAME
#define a2i_GENERAL_NAME __NS_SYMBOL(a2i_GENERAL_NAME)
#endif

#ifndef cms_DigestAlgorithm_find_ctx
#define cms_DigestAlgorithm_find_ctx __NS_SYMBOL(cms_DigestAlgorithm_find_ctx)
#endif

#ifndef d2i_PKCS8_PRIV_KEY_INFO_bio
#define d2i_PKCS8_PRIV_KEY_INFO_bio __NS_SYMBOL(d2i_PKCS8_PRIV_KEY_INFO_bio)
#endif

#ifndef EC_KEY_set_private_key
#define EC_KEY_set_private_key __NS_SYMBOL(EC_KEY_set_private_key)
#endif

#ifndef TS_CONF_set_clock_precision_digits
#define TS_CONF_set_clock_precision_digits __NS_SYMBOL(TS_CONF_set_clock_precision_digits)
#endif

#ifndef X509V3_set_nconf
#define X509V3_set_nconf __NS_SYMBOL(X509V3_set_nconf)
#endif

#ifndef X509_PURPOSE_get0_name
#define X509_PURPOSE_get0_name __NS_SYMBOL(X509_PURPOSE_get0_name)
#endif

#ifndef i2d_CERTIFICATEPOLICIES
#define i2d_CERTIFICATEPOLICIES __NS_SYMBOL(i2d_CERTIFICATEPOLICIES)
#endif

#ifndef SRP_check_known_gN_param
#define SRP_check_known_gN_param __NS_SYMBOL(SRP_check_known_gN_param)
#endif

#ifndef X509_PURPOSE_get0_sname
#define X509_PURPOSE_get0_sname __NS_SYMBOL(X509_PURPOSE_get0_sname)
#endif

#ifndef aesni_ccm64_encrypt_blocks
#define aesni_ccm64_encrypt_blocks __NS_SYMBOL(aesni_ccm64_encrypt_blocks)
#endif

#ifndef asn1_ex_i2c
#define asn1_ex_i2c __NS_SYMBOL(asn1_ex_i2c)
#endif

#ifndef CERTIFICATEPOLICIES_new
#define CERTIFICATEPOLICIES_new __NS_SYMBOL(CERTIFICATEPOLICIES_new)
#endif

#ifndef CRYPTO_ccm128_tag
#define CRYPTO_ccm128_tag __NS_SYMBOL(CRYPTO_ccm128_tag)
#endif

#ifndef ERR_get_error_line
#define ERR_get_error_line __NS_SYMBOL(ERR_get_error_line)
#endif

#ifndef X509V3_set_ctx
#define X509V3_set_ctx __NS_SYMBOL(X509V3_set_ctx)
#endif

#ifndef X509_PURPOSE_get_trust
#define X509_PURPOSE_get_trust __NS_SYMBOL(X509_PURPOSE_get_trust)
#endif

#ifndef i2d_PKCS8_PRIV_KEY_INFO_bio
#define i2d_PKCS8_PRIV_KEY_INFO_bio __NS_SYMBOL(i2d_PKCS8_PRIV_KEY_INFO_bio)
#endif

#ifndef X509_supported_extension
#define X509_supported_extension __NS_SYMBOL(X509_supported_extension)
#endif

#ifndef ec_GFp_simple_point_set_affine_coordinates
#define ec_GFp_simple_point_set_affine_coordinates __NS_SYMBOL(ec_GFp_simple_point_set_affine_coordinates)
#endif

#ifndef ASN1_OBJECT_new
#define ASN1_OBJECT_new __NS_SYMBOL(ASN1_OBJECT_new)
#endif

#ifndef CERTIFICATEPOLICIES_free
#define CERTIFICATEPOLICIES_free __NS_SYMBOL(CERTIFICATEPOLICIES_free)
#endif

#ifndef EC_GROUP_get0_generator
#define EC_GROUP_get0_generator __NS_SYMBOL(EC_GROUP_get0_generator)
#endif

#ifndef EC_KEY_get0_public_key
#define EC_KEY_get0_public_key __NS_SYMBOL(EC_KEY_get0_public_key)
#endif

#ifndef PEM_read_bio_ECPrivateKey
#define PEM_read_bio_ECPrivateKey __NS_SYMBOL(PEM_read_bio_ECPrivateKey)
#endif

#ifndef X509V3_EXT_conf
#define X509V3_EXT_conf __NS_SYMBOL(X509V3_EXT_conf)
#endif

#ifndef X509_OBJECT_free_contents
#define X509_OBJECT_free_contents __NS_SYMBOL(X509_OBJECT_free_contents)
#endif

#ifndef i2d_PKCS8PrivateKeyInfo_bio
#define i2d_PKCS8PrivateKeyInfo_bio __NS_SYMBOL(i2d_PKCS8PrivateKeyInfo_bio)
#endif

#ifndef BN_cmp
#define BN_cmp __NS_SYMBOL(BN_cmp)
#endif

#ifndef EC_GROUP_get_order
#define EC_GROUP_get_order __NS_SYMBOL(EC_GROUP_get_order)
#endif

#ifndef EC_KEY_get_enc_flags
#define EC_KEY_get_enc_flags __NS_SYMBOL(EC_KEY_get_enc_flags)
#endif

#ifndef BN_nist_mod_384
#define BN_nist_mod_384 __NS_SYMBOL(BN_nist_mod_384)
#endif

#ifndef EC_KEY_set_enc_flags
#define EC_KEY_set_enc_flags __NS_SYMBOL(EC_KEY_set_enc_flags)
#endif

#ifndef d2i_POLICYINFO
#define d2i_POLICYINFO __NS_SYMBOL(d2i_POLICYINFO)
#endif

#ifndef ASN1_STRING_print
#define ASN1_STRING_print __NS_SYMBOL(ASN1_STRING_print)
#endif

#ifndef CRYPTO_gcm128_decrypt
#define CRYPTO_gcm128_decrypt __NS_SYMBOL(CRYPTO_gcm128_decrypt)
#endif

#ifndef DIST_POINT_set_dpname
#define DIST_POINT_set_dpname __NS_SYMBOL(DIST_POINT_set_dpname)
#endif

#ifndef EC_KEY_get_conv_form
#define EC_KEY_get_conv_form __NS_SYMBOL(EC_KEY_get_conv_form)
#endif

#ifndef X509_STORE_add_crl
#define X509_STORE_add_crl __NS_SYMBOL(X509_STORE_add_crl)
#endif

#ifndef bn_sqr_comba8
#define bn_sqr_comba8 __NS_SYMBOL(bn_sqr_comba8)
#endif

#ifndef BIO_ctrl_wpending
#define BIO_ctrl_wpending __NS_SYMBOL(BIO_ctrl_wpending)
#endif

#ifndef EC_GROUP_get_cofactor
#define EC_GROUP_get_cofactor __NS_SYMBOL(EC_GROUP_get_cofactor)
#endif

#ifndef EC_KEY_set_conv_form
#define EC_KEY_set_conv_form __NS_SYMBOL(EC_KEY_set_conv_form)
#endif

#ifndef OBJ_ln2nid
#define OBJ_ln2nid __NS_SYMBOL(OBJ_ln2nid)
#endif

#ifndef PKCS7_RECIP_INFO_set
#define PKCS7_RECIP_INFO_set __NS_SYMBOL(PKCS7_RECIP_INFO_set)
#endif

#ifndef X509_check_ca
#define X509_check_ca __NS_SYMBOL(X509_check_ca)
#endif

#ifndef i2d_POLICYINFO
#define i2d_POLICYINFO __NS_SYMBOL(i2d_POLICYINFO)
#endif

#ifndef TS_CONF_set_ordering
#define TS_CONF_set_ordering __NS_SYMBOL(TS_CONF_set_ordering)
#endif

#ifndef X509V3_EXT_conf_nid
#define X509V3_EXT_conf_nid __NS_SYMBOL(X509V3_EXT_conf_nid)
#endif

#ifndef i2d_PrivateKey_bio
#define i2d_PrivateKey_bio __NS_SYMBOL(i2d_PrivateKey_bio)
#endif

#ifndef EC_KEY_get_key_method_data
#define EC_KEY_get_key_method_data __NS_SYMBOL(EC_KEY_get_key_method_data)
#endif

#ifndef PEM_read_bio_ECPKParameters
#define PEM_read_bio_ECPKParameters __NS_SYMBOL(PEM_read_bio_ECPKParameters)
#endif

#ifndef POLICYINFO_new
#define POLICYINFO_new __NS_SYMBOL(POLICYINFO_new)
#endif

#ifndef SRP_get_default_gN
#define SRP_get_default_gN __NS_SYMBOL(SRP_get_default_gN)
#endif

#ifndef ec_GF2m_precompute_mult
#define ec_GF2m_precompute_mult __NS_SYMBOL(ec_GF2m_precompute_mult)
#endif

#ifndef ASN1_OBJECT_free
#define ASN1_OBJECT_free __NS_SYMBOL(ASN1_OBJECT_free)
#endif

#ifndef EC_KEY_print
#define EC_KEY_print __NS_SYMBOL(EC_KEY_print)
#endif

#ifndef d2i_PrivateKey_bio
#define d2i_PrivateKey_bio __NS_SYMBOL(d2i_PrivateKey_bio)
#endif

#ifndef ec_GF2m_have_precompute_mult
#define ec_GF2m_have_precompute_mult __NS_SYMBOL(ec_GF2m_have_precompute_mult)
#endif

#ifndef EC_GROUP_set_curve_name
#define EC_GROUP_set_curve_name __NS_SYMBOL(EC_GROUP_set_curve_name)
#endif

#ifndef POLICYINFO_free
#define POLICYINFO_free __NS_SYMBOL(POLICYINFO_free)
#endif

#ifndef UI_add_info_string
#define UI_add_info_string __NS_SYMBOL(UI_add_info_string)
#endif

#ifndef ec_GFp_simple_point_get_affine_coordinates
#define ec_GFp_simple_point_get_affine_coordinates __NS_SYMBOL(ec_GFp_simple_point_get_affine_coordinates)
#endif

#ifndef EC_GROUP_get_curve_name
#define EC_GROUP_get_curve_name __NS_SYMBOL(EC_GROUP_get_curve_name)
#endif

#ifndef PEM_read_ECPKParameters
#define PEM_read_ECPKParameters __NS_SYMBOL(PEM_read_ECPKParameters)
#endif

#ifndef EC_GROUP_set_asn1_flag
#define EC_GROUP_set_asn1_flag __NS_SYMBOL(EC_GROUP_set_asn1_flag)
#endif

#ifndef X509V3_set_conf_lhash
#define X509V3_set_conf_lhash __NS_SYMBOL(X509V3_set_conf_lhash)
#endif

#ifndef aesni_ccm64_decrypt_blocks
#define aesni_ccm64_decrypt_blocks __NS_SYMBOL(aesni_ccm64_decrypt_blocks)
#endif

#ifndef d2i_POLICYQUALINFO
#define d2i_POLICYQUALINFO __NS_SYMBOL(d2i_POLICYQUALINFO)
#endif

#ifndef i2d_PUBKEY_bio
#define i2d_PUBKEY_bio __NS_SYMBOL(i2d_PUBKEY_bio)
#endif

#ifndef BN_set_bit
#define BN_set_bit __NS_SYMBOL(BN_set_bit)
#endif

#ifndef CMS_add0_CertificateChoices
#define CMS_add0_CertificateChoices __NS_SYMBOL(CMS_add0_CertificateChoices)
#endif

#ifndef EC_GROUP_get_asn1_flag
#define EC_GROUP_get_asn1_flag __NS_SYMBOL(EC_GROUP_get_asn1_flag)
#endif

#ifndef TS_RESP_verify_token
#define TS_RESP_verify_token __NS_SYMBOL(TS_RESP_verify_token)
#endif

#ifndef EC_GROUP_set_point_conversion_form
#define EC_GROUP_set_point_conversion_form __NS_SYMBOL(EC_GROUP_set_point_conversion_form)
#endif

#ifndef ERR_get_error_line_data
#define ERR_get_error_line_data __NS_SYMBOL(ERR_get_error_line_data)
#endif

#ifndef PEM_write_bio_ECPKParameters
#define PEM_write_bio_ECPKParameters __NS_SYMBOL(PEM_write_bio_ECPKParameters)
#endif

#ifndef X509V3_EXT_add_conf
#define X509V3_EXT_add_conf __NS_SYMBOL(X509V3_EXT_add_conf)
#endif

#ifndef X509_ATTRIBUTE_get0_object
#define X509_ATTRIBUTE_get0_object __NS_SYMBOL(X509_ATTRIBUTE_get0_object)
#endif

#ifndef d2i_PUBKEY_bio
#define d2i_PUBKEY_bio __NS_SYMBOL(d2i_PUBKEY_bio)
#endif

#ifndef hex_to_string
#define hex_to_string __NS_SYMBOL(hex_to_string)
#endif

#ifndef i2d_POLICYQUALINFO
#define i2d_POLICYQUALINFO __NS_SYMBOL(i2d_POLICYQUALINFO)
#endif

#ifndef ECParameters_print_fp
#define ECParameters_print_fp __NS_SYMBOL(ECParameters_print_fp)
#endif

#ifndef EC_GROUP_get_point_conversion_form
#define EC_GROUP_get_point_conversion_form __NS_SYMBOL(EC_GROUP_get_point_conversion_form)
#endif

#ifndef X509_ATTRIBUTE_get0_type
#define X509_ATTRIBUTE_get0_type __NS_SYMBOL(X509_ATTRIBUTE_get0_type)
#endif

#ifndef BIO_accept
#define BIO_accept __NS_SYMBOL(BIO_accept)
#endif

#ifndef BN_GF2m_mod_mul
#define BN_GF2m_mod_mul __NS_SYMBOL(BN_GF2m_mod_mul)
#endif

#ifndef EC_GROUP_set_seed
#define EC_GROUP_set_seed __NS_SYMBOL(EC_GROUP_set_seed)
#endif

#ifndef EC_KEY_insert_key_method_data
#define EC_KEY_insert_key_method_data __NS_SYMBOL(EC_KEY_insert_key_method_data)
#endif

#ifndef ERR_peek_error
#define ERR_peek_error __NS_SYMBOL(ERR_peek_error)
#endif

#ifndef POLICYQUALINFO_new
#define POLICYQUALINFO_new __NS_SYMBOL(POLICYQUALINFO_new)
#endif

#ifndef ASN1_OBJECT_create
#define ASN1_OBJECT_create __NS_SYMBOL(ASN1_OBJECT_create)
#endif

#ifndef CRYPTO_dbg_realloc
#define CRYPTO_dbg_realloc __NS_SYMBOL(CRYPTO_dbg_realloc)
#endif

#ifndef PKCS7_get0_signers
#define PKCS7_get0_signers __NS_SYMBOL(PKCS7_get0_signers)
#endif

#ifndef TS_CONF_set_tsa_name
#define TS_CONF_set_tsa_name __NS_SYMBOL(TS_CONF_set_tsa_name)
#endif

#ifndef X509_check_issued
#define X509_check_issued __NS_SYMBOL(X509_check_issued)
#endif

#ifndef bn_mul_part_recursive
#define bn_mul_part_recursive __NS_SYMBOL(bn_mul_part_recursive)
#endif

#ifndef POLICYQUALINFO_free
#define POLICYQUALINFO_free __NS_SYMBOL(POLICYQUALINFO_free)
#endif

#ifndef BIO_push
#define BIO_push __NS_SYMBOL(BIO_push)
#endif

#ifndef PEM_write_ECPKParameters
#define PEM_write_ECPKParameters __NS_SYMBOL(PEM_write_ECPKParameters)
#endif

#ifndef X509V3_EXT_CRL_add_conf
#define X509V3_EXT_CRL_add_conf __NS_SYMBOL(X509V3_EXT_CRL_add_conf)
#endif

#ifndef ASN1_parse_dump
#define ASN1_parse_dump __NS_SYMBOL(ASN1_parse_dump)
#endif

#ifndef ERR_peek_error_line
#define ERR_peek_error_line __NS_SYMBOL(ERR_peek_error_line)
#endif

#ifndef d2i_USERNOTICE
#define d2i_USERNOTICE __NS_SYMBOL(d2i_USERNOTICE)
#endif

#ifndef ASN1_UTCTIME_print
#define ASN1_UTCTIME_print __NS_SYMBOL(ASN1_UTCTIME_print)
#endif

#ifndef OBJ_obj2txt
#define OBJ_obj2txt __NS_SYMBOL(OBJ_obj2txt)
#endif

#ifndef BN_mod_exp_recp
#define BN_mod_exp_recp __NS_SYMBOL(BN_mod_exp_recp)
#endif

#ifndef i2d_USERNOTICE
#define i2d_USERNOTICE __NS_SYMBOL(i2d_USERNOTICE)
#endif

#ifndef ASN1_tag2str
#define ASN1_tag2str __NS_SYMBOL(ASN1_tag2str)
#endif

#ifndef EVP_CipherFinal
#define EVP_CipherFinal __NS_SYMBOL(EVP_CipherFinal)
#endif

#ifndef ec_GF2m_simple_dbl
#define ec_GF2m_simple_dbl __NS_SYMBOL(ec_GF2m_simple_dbl)
#endif

#ifndef PEM_write_bio_ECPrivateKey
#define PEM_write_bio_ECPrivateKey __NS_SYMBOL(PEM_write_bio_ECPrivateKey)
#endif

#ifndef USERNOTICE_new
#define USERNOTICE_new __NS_SYMBOL(USERNOTICE_new)
#endif

#ifndef X509V3_EXT_REQ_add_conf
#define X509V3_EXT_REQ_add_conf __NS_SYMBOL(X509V3_EXT_REQ_add_conf)
#endif

#ifndef CMS_add0_cert
#define CMS_add0_cert __NS_SYMBOL(CMS_add0_cert)
#endif

#ifndef EC_GROUP_get0_seed
#define EC_GROUP_get0_seed __NS_SYMBOL(EC_GROUP_get0_seed)
#endif

#ifndef EVP_EncryptFinal
#define EVP_EncryptFinal __NS_SYMBOL(EVP_EncryptFinal)
#endif

#ifndef ec_GF2m_simple_invert
#define ec_GF2m_simple_invert __NS_SYMBOL(ec_GF2m_simple_invert)
#endif

#ifndef ECParameters_print
#define ECParameters_print __NS_SYMBOL(ECParameters_print)
#endif

#ifndef EC_GROUP_get_seed_len
#define EC_GROUP_get_seed_len __NS_SYMBOL(EC_GROUP_get_seed_len)
#endif

#ifndef EC_KEY_set_asn1_flag
#define EC_KEY_set_asn1_flag __NS_SYMBOL(EC_KEY_set_asn1_flag)
#endif

#ifndef EVP_DecryptFinal
#define EVP_DecryptFinal __NS_SYMBOL(EVP_DecryptFinal)
#endif

#ifndef USERNOTICE_free
#define USERNOTICE_free __NS_SYMBOL(USERNOTICE_free)
#endif

#ifndef string_to_hex
#define string_to_hex __NS_SYMBOL(string_to_hex)
#endif

#ifndef EC_GROUP_set_curve_GFp
#define EC_GROUP_set_curve_GFp __NS_SYMBOL(EC_GROUP_set_curve_GFp)
#endif

#ifndef EVP_EncryptInit
#define EVP_EncryptInit __NS_SYMBOL(EVP_EncryptInit)
#endif

#ifndef TS_CONF_set_ess_cert_id_chain
#define TS_CONF_set_ess_cert_id_chain __NS_SYMBOL(TS_CONF_set_ess_cert_id_chain)
#endif

#ifndef X509_check_akid
#define X509_check_akid __NS_SYMBOL(X509_check_akid)
#endif

#ifndef BN_clear_bit
#define BN_clear_bit __NS_SYMBOL(BN_clear_bit)
#endif

#ifndef EC_KEY_precompute_mult
#define EC_KEY_precompute_mult __NS_SYMBOL(EC_KEY_precompute_mult)
#endif

#ifndef ERR_peek_error_line_data
#define ERR_peek_error_line_data __NS_SYMBOL(ERR_peek_error_line_data)
#endif

#ifndef d2i_NOTICEREF
#define d2i_NOTICEREF __NS_SYMBOL(d2i_NOTICEREF)
#endif

#ifndef PEM_write_ECPrivateKey
#define PEM_write_ECPrivateKey __NS_SYMBOL(PEM_write_ECPrivateKey)
#endif

#ifndef PKCS7_add_recipient_info
#define PKCS7_add_recipient_info __NS_SYMBOL(PKCS7_add_recipient_info)
#endif

#ifndef UI_dup_info_string
#define UI_dup_info_string __NS_SYMBOL(UI_dup_info_string)
#endif

#ifndef X509_OBJECT_idx_by_subject
#define X509_OBJECT_idx_by_subject __NS_SYMBOL(X509_OBJECT_idx_by_subject)
#endif

#ifndef EC_KEY_get_flags
#define EC_KEY_get_flags __NS_SYMBOL(EC_KEY_get_flags)
#endif

#ifndef cms_EnvelopedData_init_bio
#define cms_EnvelopedData_init_bio __NS_SYMBOL(cms_EnvelopedData_init_bio)
#endif

#ifndef i2d_NOTICEREF
#define i2d_NOTICEREF __NS_SYMBOL(i2d_NOTICEREF)
#endif

#ifndef BN_is_prime_ex
#define BN_is_prime_ex __NS_SYMBOL(BN_is_prime_ex)
#endif

#ifndef CMS_get0_SignerInfos
#define CMS_get0_SignerInfos __NS_SYMBOL(CMS_get0_SignerInfos)
#endif

#ifndef EC_GROUP_get_curve_GFp
#define EC_GROUP_get_curve_GFp __NS_SYMBOL(EC_GROUP_get_curve_GFp)
#endif

#ifndef EC_KEY_set_flags
#define EC_KEY_set_flags __NS_SYMBOL(EC_KEY_set_flags)
#endif

#ifndef EC_KEY_clear_flags
#define EC_KEY_clear_flags __NS_SYMBOL(EC_KEY_clear_flags)
#endif

#ifndef EVP_EncryptInit_ex
#define EVP_EncryptInit_ex __NS_SYMBOL(EVP_EncryptInit_ex)
#endif

#ifndef NOTICEREF_new
#define NOTICEREF_new __NS_SYMBOL(NOTICEREF_new)
#endif

#ifndef aesni_ctr32_encrypt_blocks
#define aesni_ctr32_encrypt_blocks __NS_SYMBOL(aesni_ctr32_encrypt_blocks)
#endif

#ifndef ec_GF2m_simple_is_at_infinity
#define ec_GF2m_simple_is_at_infinity __NS_SYMBOL(ec_GF2m_simple_is_at_infinity)
#endif

#ifndef EVP_DecryptInit
#define EVP_DecryptInit __NS_SYMBOL(EVP_DecryptInit)
#endif

#ifndef ec_GF2m_simple_is_on_curve
#define ec_GF2m_simple_is_on_curve __NS_SYMBOL(ec_GF2m_simple_is_on_curve)
#endif

#ifndef BIO_pop
#define BIO_pop __NS_SYMBOL(BIO_pop)
#endif

#ifndef NOTICEREF_free
#define NOTICEREF_free __NS_SYMBOL(NOTICEREF_free)
#endif

#ifndef PEM_read_bio_EC_PUBKEY
#define PEM_read_bio_EC_PUBKEY __NS_SYMBOL(PEM_read_bio_EC_PUBKEY)
#endif

#ifndef finish_hash
#define finish_hash __NS_SYMBOL(finish_hash)
#endif

#ifndef i2d_ECPKParameters
#define i2d_ECPKParameters __NS_SYMBOL(i2d_ECPKParameters)
#endif

#ifndef EC_GROUP_set_curve_GF2m
#define EC_GROUP_set_curve_GF2m __NS_SYMBOL(EC_GROUP_set_curve_GF2m)
#endif

#ifndef BN_is_bit_set
#define BN_is_bit_set __NS_SYMBOL(BN_is_bit_set)
#endif

#ifndef PKCS7_cert_from_signer_info
#define PKCS7_cert_from_signer_info __NS_SYMBOL(PKCS7_cert_from_signer_info)
#endif

#ifndef X509_POLICY_NODE_print
#define X509_POLICY_NODE_print __NS_SYMBOL(X509_POLICY_NODE_print)
#endif

#ifndef private_AES_set_decrypt_key
#define private_AES_set_decrypt_key __NS_SYMBOL(private_AES_set_decrypt_key)
#endif

#ifndef BN_GF2m_mod_sqr
#define BN_GF2m_mod_sqr __NS_SYMBOL(BN_GF2m_mod_sqr)
#endif

#ifndef CMS_get0_signers
#define CMS_get0_signers __NS_SYMBOL(CMS_get0_signers)
#endif

#ifndef CMS_verify_receipt
#define CMS_verify_receipt __NS_SYMBOL(CMS_verify_receipt)
#endif

#ifndef PEM_read_EC_PUBKEY
#define PEM_read_EC_PUBKEY __NS_SYMBOL(PEM_read_EC_PUBKEY)
#endif

#ifndef EVP_DecryptInit_ex
#define EVP_DecryptInit_ex __NS_SYMBOL(EVP_DecryptInit_ex)
#endif

#ifndef EC_GROUP_get_curve_GF2m
#define EC_GROUP_get_curve_GF2m __NS_SYMBOL(EC_GROUP_get_curve_GF2m)
#endif

#ifndef EVP_CIPHER_CTX_free
#define EVP_CIPHER_CTX_free __NS_SYMBOL(EVP_CIPHER_CTX_free)
#endif

#ifndef BN_mask_bits
#define BN_mask_bits __NS_SYMBOL(BN_mask_bits)
#endif

#ifndef CMS_add1_cert
#define CMS_add1_cert __NS_SYMBOL(CMS_add1_cert)
#endif

#ifndef PEM_write_bio_EC_PUBKEY
#define PEM_write_bio_EC_PUBKEY __NS_SYMBOL(PEM_write_bio_EC_PUBKEY)
#endif

#ifndef PKCS7_set_cipher
#define PKCS7_set_cipher __NS_SYMBOL(PKCS7_set_cipher)
#endif

#ifndef ERR_peek_last_error
#define ERR_peek_last_error __NS_SYMBOL(ERR_peek_last_error)
#endif

#ifndef CMS_sign
#define CMS_sign __NS_SYMBOL(CMS_sign)
#endif

#ifndef CRYPTO_mem_leaks
#define CRYPTO_mem_leaks __NS_SYMBOL(CRYPTO_mem_leaks)
#endif

#ifndef EC_GROUP_get_degree
#define EC_GROUP_get_degree __NS_SYMBOL(EC_GROUP_get_degree)
#endif

#ifndef ASN1_GENERALIZEDTIME_print
#define ASN1_GENERALIZEDTIME_print __NS_SYMBOL(ASN1_GENERALIZEDTIME_print)
#endif

#ifndef ERR_peek_last_error_line
#define ERR_peek_last_error_line __NS_SYMBOL(ERR_peek_last_error_line)
#endif

#ifndef CMS_add0_RevocationInfoChoice
#define CMS_add0_RevocationInfoChoice __NS_SYMBOL(CMS_add0_RevocationInfoChoice)
#endif

#ifndef PEM_write_EC_PUBKEY
#define PEM_write_EC_PUBKEY __NS_SYMBOL(PEM_write_EC_PUBKEY)
#endif

#ifndef EC_GROUP_check_discriminant
#define EC_GROUP_check_discriminant __NS_SYMBOL(EC_GROUP_check_discriminant)
#endif

#ifndef EVP_CIPHER_CTX_set_key_length
#define EVP_CIPHER_CTX_set_key_length __NS_SYMBOL(EVP_CIPHER_CTX_set_key_length)
#endif

#ifndef BN_set_negative
#define BN_set_negative __NS_SYMBOL(BN_set_negative)
#endif

#ifndef BIO_get_retry_BIO
#define BIO_get_retry_BIO __NS_SYMBOL(BIO_get_retry_BIO)
#endif

#ifndef PEM_read_ECPrivateKey
#define PEM_read_ECPrivateKey __NS_SYMBOL(PEM_read_ECPrivateKey)
#endif

#ifndef PKCS7_stream
#define PKCS7_stream __NS_SYMBOL(PKCS7_stream)
#endif

#ifndef CMS_SignerInfo_set1_signer_cert
#define CMS_SignerInfo_set1_signer_cert __NS_SYMBOL(CMS_SignerInfo_set1_signer_cert)
#endif

#ifndef EC_GROUP_cmp
#define EC_GROUP_cmp __NS_SYMBOL(EC_GROUP_cmp)
#endif

#ifndef ERR_peek_last_error_line_data
#define ERR_peek_last_error_line_data __NS_SYMBOL(ERR_peek_last_error_line_data)
#endif

#ifndef UI_add_error_string
#define UI_add_error_string __NS_SYMBOL(UI_add_error_string)
#endif

#ifndef bn_cmp_words
#define bn_cmp_words __NS_SYMBOL(bn_cmp_words)
#endif

#ifndef BIO_get_retry_reason
#define BIO_get_retry_reason __NS_SYMBOL(BIO_get_retry_reason)
#endif

#ifndef BIO_find_type
#define BIO_find_type __NS_SYMBOL(BIO_find_type)
#endif

#ifndef CMS_add0_crl
#define CMS_add0_crl __NS_SYMBOL(CMS_add0_crl)
#endif

#ifndef PEM_read_bio_DHparams
#define PEM_read_bio_DHparams __NS_SYMBOL(PEM_read_bio_DHparams)
#endif

#ifndef PKCS7_encrypt
#define PKCS7_encrypt __NS_SYMBOL(PKCS7_encrypt)
#endif

#ifndef bn_cmp_part_words
#define bn_cmp_part_words __NS_SYMBOL(bn_cmp_part_words)
#endif

#ifndef BN_GF2m_mod_inv
#define BN_GF2m_mod_inv __NS_SYMBOL(BN_GF2m_mod_inv)
#endif

#ifndef CMS_SignerInfo_get0_signer_id
#define CMS_SignerInfo_get0_signer_id __NS_SYMBOL(CMS_SignerInfo_get0_signer_id)
#endif

#ifndef ec_GF2m_simple_cmp
#define ec_GF2m_simple_cmp __NS_SYMBOL(ec_GF2m_simple_cmp)
#endif

#ifndef ec_GFp_simple_add
#define ec_GFp_simple_add __NS_SYMBOL(ec_GFp_simple_add)
#endif

#ifndef CMS_add1_crl
#define CMS_add1_crl __NS_SYMBOL(CMS_add1_crl)
#endif

#ifndef PEM_read_DHparams
#define PEM_read_DHparams __NS_SYMBOL(PEM_read_DHparams)
#endif

#ifndef name_cmp
#define name_cmp __NS_SYMBOL(name_cmp)
#endif

#ifndef X509_STORE_get1_certs
#define X509_STORE_get1_certs __NS_SYMBOL(X509_STORE_get1_certs)
#endif

#ifndef EVP_CIPHER_CTX_set_padding
#define EVP_CIPHER_CTX_set_padding __NS_SYMBOL(EVP_CIPHER_CTX_set_padding)
#endif

#ifndef BIO_next
#define BIO_next __NS_SYMBOL(BIO_next)
#endif

#ifndef PEM_write_bio_DHparams
#define PEM_write_bio_DHparams __NS_SYMBOL(PEM_write_bio_DHparams)
#endif

#ifndef ERR_error_string_n
#define ERR_error_string_n __NS_SYMBOL(ERR_error_string_n)
#endif

#ifndef BIO_free_all
#define BIO_free_all __NS_SYMBOL(BIO_free_all)
#endif

#ifndef CMS_SignerInfo_cert_cmp
#define CMS_SignerInfo_cert_cmp __NS_SYMBOL(CMS_SignerInfo_cert_cmp)
#endif

#ifndef EVP_CIPHER_CTX_rand_key
#define EVP_CIPHER_CTX_rand_key __NS_SYMBOL(EVP_CIPHER_CTX_rand_key)
#endif

#ifndef X509_get1_email
#define X509_get1_email __NS_SYMBOL(X509_get1_email)
#endif

#ifndef BIO_set_tcp_ndelay
#define BIO_set_tcp_ndelay __NS_SYMBOL(BIO_set_tcp_ndelay)
#endif

#ifndef CMS_get1_certs
#define CMS_get1_certs __NS_SYMBOL(CMS_get1_certs)
#endif

#ifndef CMS_set1_signers_certs
#define CMS_set1_signers_certs __NS_SYMBOL(CMS_set1_signers_certs)
#endif

#ifndef PEM_get_EVP_CIPHER_INFO
#define PEM_get_EVP_CIPHER_INFO __NS_SYMBOL(PEM_get_EVP_CIPHER_INFO)
#endif

#ifndef BIO_socket_nbio
#define BIO_socket_nbio __NS_SYMBOL(BIO_socket_nbio)
#endif

#ifndef CMS_sign_receipt
#define CMS_sign_receipt __NS_SYMBOL(CMS_sign_receipt)
#endif

#ifndef PEM_write_DHparams
#define PEM_write_DHparams __NS_SYMBOL(PEM_write_DHparams)
#endif

#ifndef BN_consttime_swap
#define BN_consttime_swap __NS_SYMBOL(BN_consttime_swap)
#endif

#ifndef X509_cmp_current_time
#define X509_cmp_current_time __NS_SYMBOL(X509_cmp_current_time)
#endif

#ifndef AES_cbc_encrypt
#define AES_cbc_encrypt __NS_SYMBOL(AES_cbc_encrypt)
#endif

#ifndef UI_dup_error_string
#define UI_dup_error_string __NS_SYMBOL(UI_dup_error_string)
#endif

#ifndef X509_cmp_time
#define X509_cmp_time __NS_SYMBOL(X509_cmp_time)
#endif

#ifndef asm_AES_cbc_encrypt
#define asm_AES_cbc_encrypt __NS_SYMBOL(asm_AES_cbc_encrypt)
#endif

#ifndef CRYPTO_gcm128_encrypt_ctr32
#define CRYPTO_gcm128_encrypt_ctr32 __NS_SYMBOL(CRYPTO_gcm128_encrypt_ctr32)
#endif

#ifndef PEM_read_bio_PUBKEY
#define PEM_read_bio_PUBKEY __NS_SYMBOL(PEM_read_bio_PUBKEY)
#endif

#ifndef EVP_CIPHER_CTX_copy
#define EVP_CIPHER_CTX_copy __NS_SYMBOL(EVP_CIPHER_CTX_copy)
#endif

#ifndef PEM_read_PUBKEY
#define PEM_read_PUBKEY __NS_SYMBOL(PEM_read_PUBKEY)
#endif

#ifndef BIO_dup_chain
#define BIO_dup_chain __NS_SYMBOL(BIO_dup_chain)
#endif

#ifndef PKCS7_decrypt
#define PKCS7_decrypt __NS_SYMBOL(PKCS7_decrypt)
#endif

#ifndef SEED_encrypt
#define SEED_encrypt __NS_SYMBOL(SEED_encrypt)
#endif

#ifndef PEM_write_bio_PUBKEY
#define PEM_write_bio_PUBKEY __NS_SYMBOL(PEM_write_bio_PUBKEY)
#endif

#ifndef X509_NAME_print
#define X509_NAME_print __NS_SYMBOL(X509_NAME_print)
#endif

#ifndef BN_nist_mod_521
#define BN_nist_mod_521 __NS_SYMBOL(BN_nist_mod_521)
#endif

#ifndef X509_get1_ocsp
#define X509_get1_ocsp __NS_SYMBOL(X509_get1_ocsp)
#endif

#ifndef CMS_get1_crls
#define CMS_get1_crls __NS_SYMBOL(CMS_get1_crls)
#endif

#ifndef PEM_write_PUBKEY
#define PEM_write_PUBKEY __NS_SYMBOL(PEM_write_PUBKEY)
#endif

#ifndef ec_GF2m_simple_make_affine
#define ec_GF2m_simple_make_affine __NS_SYMBOL(ec_GF2m_simple_make_affine)
#endif

#ifndef SRP_create_verifier_BN
#define SRP_create_verifier_BN __NS_SYMBOL(SRP_create_verifier_BN)
#endif

#ifndef bn_sqr_comba4
#define bn_sqr_comba4 __NS_SYMBOL(bn_sqr_comba4)
#endif

#ifndef gost_enc
#define gost_enc __NS_SYMBOL(gost_enc)
#endif

#ifndef CMS_encrypt
#define CMS_encrypt __NS_SYMBOL(CMS_encrypt)
#endif

#ifndef X509_STORE_get1_crls
#define X509_STORE_get1_crls __NS_SYMBOL(X509_STORE_get1_crls)
#endif

#ifndef UI_construct_prompt
#define UI_construct_prompt __NS_SYMBOL(UI_construct_prompt)
#endif

#ifndef gost_dec
#define gost_dec __NS_SYMBOL(gost_dec)
#endif

#ifndef mod_exp_512
#define mod_exp_512 __NS_SYMBOL(mod_exp_512)
#endif

#ifndef aesni_xts_encrypt
#define aesni_xts_encrypt __NS_SYMBOL(aesni_xts_encrypt)
#endif

#ifndef EC_POINT_cmp
#define EC_POINT_cmp __NS_SYMBOL(EC_POINT_cmp)
#endif

#ifndef bn_mul_low_recursive
#define bn_mul_low_recursive __NS_SYMBOL(bn_mul_low_recursive)
#endif

#ifndef gost_enc_cfb
#define gost_enc_cfb __NS_SYMBOL(gost_enc_cfb)
#endif

#ifndef PKCS7_dataFinal
#define PKCS7_dataFinal __NS_SYMBOL(PKCS7_dataFinal)
#endif

#ifndef BN_mod_exp_mont_consttime
#define BN_mod_exp_mont_consttime __NS_SYMBOL(BN_mod_exp_mont_consttime)
#endif

#ifndef get_encryption_params
#define get_encryption_params __NS_SYMBOL(get_encryption_params)
#endif

#ifndef EC_EX_DATA_get_data
#define EC_EX_DATA_get_data __NS_SYMBOL(EC_EX_DATA_get_data)
#endif

#ifndef CMS_SignerInfo_get0_algs
#define CMS_SignerInfo_get0_algs __NS_SYMBOL(CMS_SignerInfo_get0_algs)
#endif

#ifndef ec_GF2m_simple_points_make_affine
#define ec_GF2m_simple_points_make_affine __NS_SYMBOL(ec_GF2m_simple_points_make_affine)
#endif

#ifndef X509_REQ_get1_email
#define X509_REQ_get1_email __NS_SYMBOL(X509_REQ_get1_email)
#endif

#ifndef ec_wNAF_precompute_mult
#define ec_wNAF_precompute_mult __NS_SYMBOL(ec_wNAF_precompute_mult)
#endif

#ifndef EC_EX_DATA_free_data
#define EC_EX_DATA_free_data __NS_SYMBOL(EC_EX_DATA_free_data)
#endif

#ifndef PEM_do_header
#define PEM_do_header __NS_SYMBOL(PEM_do_header)
#endif

#ifndef CMS_decrypt_set1_pkey
#define CMS_decrypt_set1_pkey __NS_SYMBOL(CMS_decrypt_set1_pkey)
#endif

#ifndef cms_SignedData_final
#define cms_SignedData_final __NS_SYMBOL(cms_SignedData_final)
#endif

#ifndef SHA_Transform
#define SHA_Transform __NS_SYMBOL(SHA_Transform)
#endif

#ifndef UI_add_user_data
#define UI_add_user_data __NS_SYMBOL(UI_add_user_data)
#endif

#ifndef SHA_Final
#define SHA_Final __NS_SYMBOL(SHA_Final)
#endif

#ifndef UI_get0_user_data
#define UI_get0_user_data __NS_SYMBOL(UI_get0_user_data)
#endif

#ifndef UI_get0_result
#define UI_get0_result __NS_SYMBOL(UI_get0_result)
#endif

#ifndef ec_GF2m_simple_field_mul
#define ec_GF2m_simple_field_mul __NS_SYMBOL(ec_GF2m_simple_field_mul)
#endif

#ifndef X509_email_free
#define X509_email_free __NS_SYMBOL(X509_email_free)
#endif

#ifndef EC_EX_DATA_clear_free_data
#define EC_EX_DATA_clear_free_data __NS_SYMBOL(EC_EX_DATA_clear_free_data)
#endif

#ifndef X509_time_adj
#define X509_time_adj __NS_SYMBOL(X509_time_adj)
#endif

#ifndef ec_GF2m_simple_field_sqr
#define ec_GF2m_simple_field_sqr __NS_SYMBOL(ec_GF2m_simple_field_sqr)
#endif

#ifndef gost_dec_cfb
#define gost_dec_cfb __NS_SYMBOL(gost_dec_cfb)
#endif

#ifndef CRYPTO_mem_leaks_fp
#define CRYPTO_mem_leaks_fp __NS_SYMBOL(CRYPTO_mem_leaks_fp)
#endif

#ifndef bn_mul_low_normal
#define bn_mul_low_normal __NS_SYMBOL(bn_mul_low_normal)
#endif

#ifndef BIO_copy_next_retry
#define BIO_copy_next_retry __NS_SYMBOL(BIO_copy_next_retry)
#endif

#ifndef DES_encrypt2
#define DES_encrypt2 __NS_SYMBOL(DES_encrypt2)
#endif

#ifndef a2i_IPADDRESS
#define a2i_IPADDRESS __NS_SYMBOL(a2i_IPADDRESS)
#endif

#ifndef ec_GF2m_simple_field_div
#define ec_GF2m_simple_field_div __NS_SYMBOL(ec_GF2m_simple_field_div)
#endif

#ifndef BIO_get_ex_new_index
#define BIO_get_ex_new_index __NS_SYMBOL(BIO_get_ex_new_index)
#endif

#ifndef OBJ_txt2nid
#define OBJ_txt2nid __NS_SYMBOL(OBJ_txt2nid)
#endif

#ifndef BIO_set_ex_data
#define BIO_set_ex_data __NS_SYMBOL(BIO_set_ex_data)
#endif

#ifndef EC_POINT_dup
#define EC_POINT_dup __NS_SYMBOL(EC_POINT_dup)
#endif

#ifndef BIO_get_ex_data
#define BIO_get_ex_data __NS_SYMBOL(BIO_get_ex_data)
#endif

#ifndef UI_get0_result_string
#define UI_get0_result_string __NS_SYMBOL(UI_get0_result_string)
#endif

#ifndef BIO_number_read
#define BIO_number_read __NS_SYMBOL(BIO_number_read)
#endif

#ifndef OBJ_bsearch_
#define OBJ_bsearch_ __NS_SYMBOL(OBJ_bsearch_)
#endif

#ifndef X509_STORE_CTX_get1_issuer
#define X509_STORE_CTX_get1_issuer __NS_SYMBOL(X509_STORE_CTX_get1_issuer)
#endif

#ifndef X509_gmtime_adj
#define X509_gmtime_adj __NS_SYMBOL(X509_gmtime_adj)
#endif

#ifndef CRYPTO_gcm128_decrypt_ctr32
#define CRYPTO_gcm128_decrypt_ctr32 __NS_SYMBOL(CRYPTO_gcm128_decrypt_ctr32)
#endif

#ifndef UI_process
#define UI_process __NS_SYMBOL(UI_process)
#endif

#ifndef BIO_number_written
#define BIO_number_written __NS_SYMBOL(BIO_number_written)
#endif

#ifndef ERR_lib_error_string
#define ERR_lib_error_string __NS_SYMBOL(ERR_lib_error_string)
#endif

#ifndef a2i_ipadd
#define a2i_ipadd __NS_SYMBOL(a2i_ipadd)
#endif

#ifndef bsaes_cbc_encrypt
#define bsaes_cbc_encrypt __NS_SYMBOL(bsaes_cbc_encrypt)
#endif

#ifndef bn_mul_high
#define bn_mul_high __NS_SYMBOL(bn_mul_high)
#endif

#ifndef SHA_Init
#define SHA_Init __NS_SYMBOL(SHA_Init)
#endif

#ifndef BIO_snprintf
#define BIO_snprintf __NS_SYMBOL(BIO_snprintf)
#endif

#ifndef CRYPTO_mem_leaks_cb
#define CRYPTO_mem_leaks_cb __NS_SYMBOL(CRYPTO_mem_leaks_cb)
#endif

#ifndef gost_enc_with_key
#define gost_enc_with_key __NS_SYMBOL(gost_enc_with_key)
#endif

#ifndef X509_time_adj_ex
#define X509_time_adj_ex __NS_SYMBOL(X509_time_adj_ex)
#endif

#ifndef EC_POINT_method_of
#define EC_POINT_method_of __NS_SYMBOL(EC_POINT_method_of)
#endif

#ifndef OBJ_bsearch_ex_
#define OBJ_bsearch_ex_ __NS_SYMBOL(OBJ_bsearch_ex_)
#endif

#ifndef EC_POINT_set_to_infinity
#define EC_POINT_set_to_infinity __NS_SYMBOL(EC_POINT_set_to_infinity)
#endif

#ifndef ERR_func_error_string
#define ERR_func_error_string __NS_SYMBOL(ERR_func_error_string)
#endif

#ifndef gost_key
#define gost_key __NS_SYMBOL(gost_key)
#endif

#ifndef EC_POINT_set_Jprojective_coordinates_GFp
#define EC_POINT_set_Jprojective_coordinates_GFp __NS_SYMBOL(EC_POINT_set_Jprojective_coordinates_GFp)
#endif

#ifndef X509_STORE_CTX_get_ex_new_index
#define X509_STORE_CTX_get_ex_new_index __NS_SYMBOL(X509_STORE_CTX_get_ex_new_index)
#endif

#ifndef gost_get_key
#define gost_get_key __NS_SYMBOL(gost_get_key)
#endif

#ifndef PEM_ASN1_write
#define PEM_ASN1_write __NS_SYMBOL(PEM_ASN1_write)
#endif

#ifndef X509_STORE_CTX_set_ex_data
#define X509_STORE_CTX_set_ex_data __NS_SYMBOL(X509_STORE_CTX_set_ex_data)
#endif

#ifndef gost_init
#define gost_init __NS_SYMBOL(gost_init)
#endif

#ifndef BIO_vsnprintf
#define BIO_vsnprintf __NS_SYMBOL(BIO_vsnprintf)
#endif

#ifndef ERR_reason_error_string
#define ERR_reason_error_string __NS_SYMBOL(ERR_reason_error_string)
#endif

#ifndef X509_STORE_CTX_get_ex_data
#define X509_STORE_CTX_get_ex_data __NS_SYMBOL(X509_STORE_CTX_get_ex_data)
#endif

#ifndef CMS_decrypt_set1_key
#define CMS_decrypt_set1_key __NS_SYMBOL(CMS_decrypt_set1_key)
#endif

#ifndef EC_POINT_get_Jprojective_coordinates_GFp
#define EC_POINT_get_Jprojective_coordinates_GFp __NS_SYMBOL(EC_POINT_get_Jprojective_coordinates_GFp)
#endif

#ifndef X509_STORE_CTX_get_error
#define X509_STORE_CTX_get_error __NS_SYMBOL(X509_STORE_CTX_get_error)
#endif

#ifndef X509_STORE_CTX_set_error
#define X509_STORE_CTX_set_error __NS_SYMBOL(X509_STORE_CTX_set_error)
#endif

#ifndef X509_STORE_CTX_get_error_depth
#define X509_STORE_CTX_get_error_depth __NS_SYMBOL(X509_STORE_CTX_get_error_depth)
#endif

#ifndef UI_ctrl
#define UI_ctrl __NS_SYMBOL(UI_ctrl)
#endif

#ifndef X509_STORE_CTX_get_current_cert
#define X509_STORE_CTX_get_current_cert __NS_SYMBOL(X509_STORE_CTX_get_current_cert)
#endif

#ifndef OBJ_create_objects
#define OBJ_create_objects __NS_SYMBOL(OBJ_create_objects)
#endif

#ifndef X509_STORE_CTX_get_chain
#define X509_STORE_CTX_get_chain __NS_SYMBOL(X509_STORE_CTX_get_chain)
#endif

#ifndef EC_POINT_set_affine_coordinates_GFp
#define EC_POINT_set_affine_coordinates_GFp __NS_SYMBOL(EC_POINT_set_affine_coordinates_GFp)
#endif

#ifndef X509_STORE_CTX_get1_chain
#define X509_STORE_CTX_get1_chain __NS_SYMBOL(X509_STORE_CTX_get1_chain)
#endif

#ifndef asn1_ex_c2i
#define asn1_ex_c2i __NS_SYMBOL(asn1_ex_c2i)
#endif

#ifndef PEM_ASN1_write_bio
#define PEM_ASN1_write_bio __NS_SYMBOL(PEM_ASN1_write_bio)
#endif

#ifndef gost_destroy
#define gost_destroy __NS_SYMBOL(gost_destroy)
#endif

#ifndef BN_GF2m_mod_inv_arr
#define BN_GF2m_mod_inv_arr __NS_SYMBOL(BN_GF2m_mod_inv_arr)
#endif

#ifndef ERR_error_string
#define ERR_error_string __NS_SYMBOL(ERR_error_string)
#endif

#ifndef a2i_IPADDRESS_NC
#define a2i_IPADDRESS_NC __NS_SYMBOL(a2i_IPADDRESS_NC)
#endif

#ifndef EC_POINT_set_affine_coordinates_GF2m
#define EC_POINT_set_affine_coordinates_GF2m __NS_SYMBOL(EC_POINT_set_affine_coordinates_GF2m)
#endif

#ifndef mac_block
#define mac_block __NS_SYMBOL(mac_block)
#endif

#ifndef UI_get_ex_new_index
#define UI_get_ex_new_index __NS_SYMBOL(UI_get_ex_new_index)
#endif

#ifndef CMS_SignerInfo_verify
#define CMS_SignerInfo_verify __NS_SYMBOL(CMS_SignerInfo_verify)
#endif

#ifndef ERR_get_string_table
#define ERR_get_string_table __NS_SYMBOL(ERR_get_string_table)
#endif

#ifndef UI_set_ex_data
#define UI_set_ex_data __NS_SYMBOL(UI_set_ex_data)
#endif

#ifndef X509_STORE_CTX_get0_current_issuer
#define X509_STORE_CTX_get0_current_issuer __NS_SYMBOL(X509_STORE_CTX_get0_current_issuer)
#endif

#ifndef UI_get_ex_data
#define UI_get_ex_data __NS_SYMBOL(UI_get_ex_data)
#endif

#ifndef X509_STORE_CTX_get0_current_crl
#define X509_STORE_CTX_get0_current_crl __NS_SYMBOL(X509_STORE_CTX_get0_current_crl)
#endif

#ifndef CMS_decrypt_set1_password
#define CMS_decrypt_set1_password __NS_SYMBOL(CMS_decrypt_set1_password)
#endif

#ifndef EC_POINT_get_affine_coordinates_GFp
#define EC_POINT_get_affine_coordinates_GFp __NS_SYMBOL(EC_POINT_get_affine_coordinates_GFp)
#endif

#ifndef UI_set_default_method
#define UI_set_default_method __NS_SYMBOL(UI_set_default_method)
#endif

#ifndef X509_STORE_CTX_get0_parent_ctx
#define X509_STORE_CTX_get0_parent_ctx __NS_SYMBOL(X509_STORE_CTX_get0_parent_ctx)
#endif

#ifndef UI_get_method
#define UI_get_method __NS_SYMBOL(UI_get_method)
#endif

#ifndef X509_STORE_CTX_set_cert
#define X509_STORE_CTX_set_cert __NS_SYMBOL(X509_STORE_CTX_set_cert)
#endif

#ifndef BN_GF2m_arr2poly
#define BN_GF2m_arr2poly __NS_SYMBOL(BN_GF2m_arr2poly)
#endif

#ifndef UI_set_method
#define UI_set_method __NS_SYMBOL(UI_set_method)
#endif

#ifndef X509_STORE_CTX_set_chain
#define X509_STORE_CTX_set_chain __NS_SYMBOL(X509_STORE_CTX_set_chain)
#endif

#ifndef ERR_get_err_state_table
#define ERR_get_err_state_table __NS_SYMBOL(ERR_get_err_state_table)
#endif

#ifndef UI_create_method
#define UI_create_method __NS_SYMBOL(UI_create_method)
#endif

#ifndef X509_STORE_CTX_set0_crls
#define X509_STORE_CTX_set0_crls __NS_SYMBOL(X509_STORE_CTX_set0_crls)
#endif

#ifndef X509_STORE_CTX_set_purpose
#define X509_STORE_CTX_set_purpose __NS_SYMBOL(X509_STORE_CTX_set_purpose)
#endif

#ifndef ec_GFp_simple_dbl
#define ec_GFp_simple_dbl __NS_SYMBOL(ec_GFp_simple_dbl)
#endif

#ifndef X509_STORE_set_flags
#define X509_STORE_set_flags __NS_SYMBOL(X509_STORE_set_flags)
#endif

#ifndef EC_POINT_get_affine_coordinates_GF2m
#define EC_POINT_get_affine_coordinates_GF2m __NS_SYMBOL(EC_POINT_get_affine_coordinates_GF2m)
#endif

#ifndef X509_STORE_CTX_purpose_inherit
#define X509_STORE_CTX_purpose_inherit __NS_SYMBOL(X509_STORE_CTX_purpose_inherit)
#endif

#ifndef X509_STORE_set_depth
#define X509_STORE_set_depth __NS_SYMBOL(X509_STORE_set_depth)
#endif

#ifndef BN_GF2m_mod_div
#define BN_GF2m_mod_div __NS_SYMBOL(BN_GF2m_mod_div)
#endif

#ifndef CRYPTO_gcm128_finish
#define CRYPTO_gcm128_finish __NS_SYMBOL(CRYPTO_gcm128_finish)
#endif

#ifndef X509V3_NAME_from_section
#define X509V3_NAME_from_section __NS_SYMBOL(X509V3_NAME_from_section)
#endif

#ifndef X509_STORE_set_purpose
#define X509_STORE_set_purpose __NS_SYMBOL(X509_STORE_set_purpose)
#endif

#ifndef X509_STORE_set_trust
#define X509_STORE_set_trust __NS_SYMBOL(X509_STORE_set_trust)
#endif

#ifndef ERR_release_err_state_table
#define ERR_release_err_state_table __NS_SYMBOL(ERR_release_err_state_table)
#endif

#ifndef X509_STORE_set1_param
#define X509_STORE_set1_param __NS_SYMBOL(X509_STORE_set1_param)
#endif

#ifndef UI_destroy_method
#define UI_destroy_method __NS_SYMBOL(UI_destroy_method)
#endif

#ifndef X509_STORE_set_verify_cb
#define X509_STORE_set_verify_cb __NS_SYMBOL(X509_STORE_set_verify_cb)
#endif

#ifndef EC_POINT_add
#define EC_POINT_add __NS_SYMBOL(EC_POINT_add)
#endif

#ifndef SMIME_text
#define SMIME_text __NS_SYMBOL(SMIME_text)
#endif

#ifndef CMS_decrypt
#define CMS_decrypt __NS_SYMBOL(CMS_decrypt)
#endif

#ifndef UI_method_set_opener
#define UI_method_set_opener __NS_SYMBOL(UI_method_set_opener)
#endif

#ifndef cms_SignedData_init_bio
#define cms_SignedData_init_bio __NS_SYMBOL(cms_SignedData_init_bio)
#endif

#ifndef UI_method_set_writer
#define UI_method_set_writer __NS_SYMBOL(UI_method_set_writer)
#endif

#ifndef BN_GF2m_mod_div_arr
#define BN_GF2m_mod_div_arr __NS_SYMBOL(BN_GF2m_mod_div_arr)
#endif

#ifndef ERR_remove_thread_state
#define ERR_remove_thread_state __NS_SYMBOL(ERR_remove_thread_state)
#endif

#ifndef UI_method_set_flusher
#define UI_method_set_flusher __NS_SYMBOL(UI_method_set_flusher)
#endif

#ifndef EC_POINT_dbl
#define EC_POINT_dbl __NS_SYMBOL(EC_POINT_dbl)
#endif

#ifndef RIPEMD160_Transform
#define RIPEMD160_Transform __NS_SYMBOL(RIPEMD160_Transform)
#endif

#ifndef RIPEMD160_Final
#define RIPEMD160_Final __NS_SYMBOL(RIPEMD160_Final)
#endif

#ifndef UI_method_set_reader
#define UI_method_set_reader __NS_SYMBOL(UI_method_set_reader)
#endif

#ifndef CRYPTO_gcm128_tag
#define CRYPTO_gcm128_tag __NS_SYMBOL(CRYPTO_gcm128_tag)
#endif

#ifndef UI_method_set_closer
#define UI_method_set_closer __NS_SYMBOL(UI_method_set_closer)
#endif

#ifndef X509_STORE_CTX_set_trust
#define X509_STORE_CTX_set_trust __NS_SYMBOL(X509_STORE_CTX_set_trust)
#endif

#ifndef UI_method_set_prompt_constructor
#define UI_method_set_prompt_constructor __NS_SYMBOL(UI_method_set_prompt_constructor)
#endif

#ifndef X509_STORE_CTX_new
#define X509_STORE_CTX_new __NS_SYMBOL(X509_STORE_CTX_new)
#endif

#ifndef EC_POINT_invert
#define EC_POINT_invert __NS_SYMBOL(EC_POINT_invert)
#endif

#ifndef OBJ_create
#define OBJ_create __NS_SYMBOL(OBJ_create)
#endif

#ifndef UI_method_get_opener
#define UI_method_get_opener __NS_SYMBOL(UI_method_get_opener)
#endif

#ifndef ERR_remove_state
#define ERR_remove_state __NS_SYMBOL(ERR_remove_state)
#endif

#ifndef UI_method_get_writer
#define UI_method_get_writer __NS_SYMBOL(UI_method_get_writer)
#endif

#ifndef UI_method_get_flusher
#define UI_method_get_flusher __NS_SYMBOL(UI_method_get_flusher)
#endif

#ifndef EC_POINT_is_at_infinity
#define EC_POINT_is_at_infinity __NS_SYMBOL(EC_POINT_is_at_infinity)
#endif

#ifndef UI_method_get_reader
#define UI_method_get_reader __NS_SYMBOL(UI_method_get_reader)
#endif

#ifndef X509_STORE_CTX_free
#define X509_STORE_CTX_free __NS_SYMBOL(X509_STORE_CTX_free)
#endif

#ifndef aesni_xts_decrypt
#define aesni_xts_decrypt __NS_SYMBOL(aesni_xts_decrypt)
#endif

#ifndef BN_GF2m_mod_exp_arr
#define BN_GF2m_mod_exp_arr __NS_SYMBOL(BN_GF2m_mod_exp_arr)
#endif

#ifndef CRYPTO_gcm128_new
#define CRYPTO_gcm128_new __NS_SYMBOL(CRYPTO_gcm128_new)
#endif

#ifndef UI_method_get_closer
#define UI_method_get_closer __NS_SYMBOL(UI_method_get_closer)
#endif

#ifndef X509_STORE_CTX_cleanup
#define X509_STORE_CTX_cleanup __NS_SYMBOL(X509_STORE_CTX_cleanup)
#endif

#ifndef CMS_uncompress
#define CMS_uncompress __NS_SYMBOL(CMS_uncompress)
#endif

#ifndef RIPEMD160_Init
#define RIPEMD160_Init __NS_SYMBOL(RIPEMD160_Init)
#endif

#ifndef UI_method_get_prompt_constructor
#define UI_method_get_prompt_constructor __NS_SYMBOL(UI_method_get_prompt_constructor)
#endif

#ifndef bsaes_ctr32_encrypt_blocks
#define bsaes_ctr32_encrypt_blocks __NS_SYMBOL(bsaes_ctr32_encrypt_blocks)
#endif

#ifndef ERR_get_next_error_library
#define ERR_get_next_error_library __NS_SYMBOL(ERR_get_next_error_library)
#endif

#ifndef CMS_compress
#define CMS_compress __NS_SYMBOL(CMS_compress)
#endif

#ifndef CRYPTO_gcm128_release
#define CRYPTO_gcm128_release __NS_SYMBOL(CRYPTO_gcm128_release)
#endif

#ifndef EC_POINT_is_on_curve
#define EC_POINT_is_on_curve __NS_SYMBOL(EC_POINT_is_on_curve)
#endif

#ifndef UI_get_string_type
#define UI_get_string_type __NS_SYMBOL(UI_get_string_type)
#endif

#ifndef UI_get_input_flags
#define UI_get_input_flags __NS_SYMBOL(UI_get_input_flags)
#endif

#ifndef UI_get0_output_string
#define UI_get0_output_string __NS_SYMBOL(UI_get0_output_string)
#endif

#ifndef UI_get0_action_string
#define UI_get0_action_string __NS_SYMBOL(UI_get0_action_string)
#endif

#ifndef EC_POINT_make_affine
#define EC_POINT_make_affine __NS_SYMBOL(EC_POINT_make_affine)
#endif

#ifndef ERR_set_error_data
#define ERR_set_error_data __NS_SYMBOL(ERR_set_error_data)
#endif

#ifndef UI_get0_test_string
#define UI_get0_test_string __NS_SYMBOL(UI_get0_test_string)
#endif

#ifndef X509_STORE_CTX_init
#define X509_STORE_CTX_init __NS_SYMBOL(X509_STORE_CTX_init)
#endif

#ifndef UI_get_result_minsize
#define UI_get_result_minsize __NS_SYMBOL(UI_get_result_minsize)
#endif

#ifndef ec_wNAF_have_precompute_mult
#define ec_wNAF_have_precompute_mult __NS_SYMBOL(ec_wNAF_have_precompute_mult)
#endif

#ifndef UI_get_result_maxsize
#define UI_get_result_maxsize __NS_SYMBOL(UI_get_result_maxsize)
#endif

#ifndef BN_mul
#define BN_mul __NS_SYMBOL(BN_mul)
#endif

#ifndef EC_POINTs_make_affine
#define EC_POINTs_make_affine __NS_SYMBOL(EC_POINTs_make_affine)
#endif

#ifndef UI_set_result
#define UI_set_result __NS_SYMBOL(UI_set_result)
#endif

#ifndef CMS_SignerInfo_verify_content
#define CMS_SignerInfo_verify_content __NS_SYMBOL(CMS_SignerInfo_verify_content)
#endif

#ifndef ERR_add_error_data
#define ERR_add_error_data __NS_SYMBOL(ERR_add_error_data)
#endif

#ifndef BN_GF2m_mod_exp
#define BN_GF2m_mod_exp __NS_SYMBOL(BN_GF2m_mod_exp)
#endif

#ifndef EC_POINTs_mul
#define EC_POINTs_mul __NS_SYMBOL(EC_POINTs_mul)
#endif

#ifndef PKCS7_SIGNER_INFO_sign
#define PKCS7_SIGNER_INFO_sign __NS_SYMBOL(PKCS7_SIGNER_INFO_sign)
#endif

#ifndef EC_POINT_mul
#define EC_POINT_mul __NS_SYMBOL(EC_POINT_mul)
#endif

#ifndef ERR_add_error_vdata
#define ERR_add_error_vdata __NS_SYMBOL(ERR_add_error_vdata)
#endif

#ifndef PEM_write_bio
#define PEM_write_bio __NS_SYMBOL(PEM_write_bio)
#endif

#ifndef EC_GROUP_precompute_mult
#define EC_GROUP_precompute_mult __NS_SYMBOL(EC_GROUP_precompute_mult)
#endif

#ifndef EC_GROUP_have_precompute_mult
#define EC_GROUP_have_precompute_mult __NS_SYMBOL(EC_GROUP_have_precompute_mult)
#endif

#ifndef get_mac
#define get_mac __NS_SYMBOL(get_mac)
#endif

#ifndef BN_GF2m_mod_sqrt_arr
#define BN_GF2m_mod_sqrt_arr __NS_SYMBOL(BN_GF2m_mod_sqrt_arr)
#endif

#ifndef CMS_add_simple_smimecap
#define CMS_add_simple_smimecap __NS_SYMBOL(CMS_add_simple_smimecap)
#endif

#ifndef BN_GF2m_mod_sqrt
#define BN_GF2m_mod_sqrt __NS_SYMBOL(BN_GF2m_mod_sqrt)
#endif

#ifndef gost_mac
#define gost_mac __NS_SYMBOL(gost_mac)
#endif

#ifndef PKCS7_dataVerify
#define PKCS7_dataVerify __NS_SYMBOL(PKCS7_dataVerify)
#endif

#ifndef ERR_set_mark
#define ERR_set_mark __NS_SYMBOL(ERR_set_mark)
#endif

#ifndef bsaes_xts_encrypt
#define bsaes_xts_encrypt __NS_SYMBOL(bsaes_xts_encrypt)
#endif

#ifndef ec_GFp_simple_invert
#define ec_GFp_simple_invert __NS_SYMBOL(ec_GFp_simple_invert)
#endif

#ifndef ERR_pop_to_mark
#define ERR_pop_to_mark __NS_SYMBOL(ERR_pop_to_mark)
#endif

#ifndef d2i_ECPrivateKey
#define d2i_ECPrivateKey __NS_SYMBOL(d2i_ECPrivateKey)
#endif

#ifndef ec_GFp_simple_is_at_infinity
#define ec_GFp_simple_is_at_infinity __NS_SYMBOL(ec_GFp_simple_is_at_infinity)
#endif

#ifndef ec_GFp_simple_is_on_curve
#define ec_GFp_simple_is_on_curve __NS_SYMBOL(ec_GFp_simple_is_on_curve)
#endif

#ifndef SEED_decrypt
#define SEED_decrypt __NS_SYMBOL(SEED_decrypt)
#endif

#ifndef gost_mac_iv
#define gost_mac_iv __NS_SYMBOL(gost_mac_iv)
#endif

#ifndef BN_GF2m_mod_solve_quad_arr
#define BN_GF2m_mod_solve_quad_arr __NS_SYMBOL(BN_GF2m_mod_solve_quad_arr)
#endif

#ifndef PEM_write
#define PEM_write __NS_SYMBOL(PEM_write)
#endif

#ifndef PKCS7_signatureVerify
#define PKCS7_signatureVerify __NS_SYMBOL(PKCS7_signatureVerify)
#endif

#ifndef cryptopro_key_meshing
#define cryptopro_key_meshing __NS_SYMBOL(cryptopro_key_meshing)
#endif

#ifndef PEM_read
#define PEM_read __NS_SYMBOL(PEM_read)
#endif

#ifndef pem_check_suffix
#define pem_check_suffix __NS_SYMBOL(pem_check_suffix)
#endif

#ifndef i2d_ECPrivateKey
#define i2d_ECPrivateKey __NS_SYMBOL(i2d_ECPrivateKey)
#endif

#ifndef aesni_cbc_encrypt
#define aesni_cbc_encrypt __NS_SYMBOL(aesni_cbc_encrypt)
#endif

#ifndef ec_GFp_simple_cmp
#define ec_GFp_simple_cmp __NS_SYMBOL(ec_GFp_simple_cmp)
#endif

#ifndef Camellia_cbc_encrypt
#define Camellia_cbc_encrypt __NS_SYMBOL(Camellia_cbc_encrypt)
#endif

#ifndef PKCS7_digest_from_attributes
#define PKCS7_digest_from_attributes __NS_SYMBOL(PKCS7_digest_from_attributes)
#endif

#ifndef BN_GF2m_mod_solve_quad
#define BN_GF2m_mod_solve_quad __NS_SYMBOL(BN_GF2m_mod_solve_quad)
#endif

#ifndef PKCS7_get_issuer_and_serial
#define PKCS7_get_issuer_and_serial __NS_SYMBOL(PKCS7_get_issuer_and_serial)
#endif

#ifndef PKCS7_get_signed_attribute
#define PKCS7_get_signed_attribute __NS_SYMBOL(PKCS7_get_signed_attribute)
#endif

#ifndef PKCS7_get_attribute
#define PKCS7_get_attribute __NS_SYMBOL(PKCS7_get_attribute)
#endif

#ifndef ec_GFp_simple_make_affine
#define ec_GFp_simple_make_affine __NS_SYMBOL(ec_GFp_simple_make_affine)
#endif

#ifndef PKCS7_set_signed_attributes
#define PKCS7_set_signed_attributes __NS_SYMBOL(PKCS7_set_signed_attributes)
#endif

#ifndef i2d_ECParameters
#define i2d_ECParameters __NS_SYMBOL(i2d_ECParameters)
#endif

#ifndef d2i_ECParameters
#define d2i_ECParameters __NS_SYMBOL(d2i_ECParameters)
#endif

#ifndef PKCS7_set_attributes
#define PKCS7_set_attributes __NS_SYMBOL(PKCS7_set_attributes)
#endif

#ifndef BN_mod_exp_simple
#define BN_mod_exp_simple __NS_SYMBOL(BN_mod_exp_simple)
#endif

#ifndef ec_GFp_simple_points_make_affine
#define ec_GFp_simple_points_make_affine __NS_SYMBOL(ec_GFp_simple_points_make_affine)
#endif

#ifndef o2i_ECPublicKey
#define o2i_ECPublicKey __NS_SYMBOL(o2i_ECPublicKey)
#endif

#ifndef PKCS7_add_signed_attribute
#define PKCS7_add_signed_attribute __NS_SYMBOL(PKCS7_add_signed_attribute)
#endif

#ifndef aesni_set_decrypt_key
#define aesni_set_decrypt_key __NS_SYMBOL(aesni_set_decrypt_key)
#endif

#ifndef bsaes_xts_decrypt
#define bsaes_xts_decrypt __NS_SYMBOL(bsaes_xts_decrypt)
#endif

#ifndef aesni_set_encrypt_key
#define aesni_set_encrypt_key __NS_SYMBOL(aesni_set_encrypt_key)
#endif

#ifndef i2o_ECPublicKey
#define i2o_ECPublicKey __NS_SYMBOL(i2o_ECPublicKey)
#endif

#ifndef PKCS7_add_attribute
#define PKCS7_add_attribute __NS_SYMBOL(PKCS7_add_attribute)
#endif

#ifndef DES_encrypt3
#define DES_encrypt3 __NS_SYMBOL(DES_encrypt3)
#endif

#ifndef X509_STORE_CTX_trusted_stack
#define X509_STORE_CTX_trusted_stack __NS_SYMBOL(X509_STORE_CTX_trusted_stack)
#endif

#ifndef DES_decrypt3
#define DES_decrypt3 __NS_SYMBOL(DES_decrypt3)
#endif

#ifndef X509_STORE_CTX_set_depth
#define X509_STORE_CTX_set_depth __NS_SYMBOL(X509_STORE_CTX_set_depth)
#endif

#ifndef X509_STORE_CTX_set_flags
#define X509_STORE_CTX_set_flags __NS_SYMBOL(X509_STORE_CTX_set_flags)
#endif

#ifndef X509_STORE_CTX_set_time
#define X509_STORE_CTX_set_time __NS_SYMBOL(X509_STORE_CTX_set_time)
#endif

#ifndef X509_STORE_CTX_set_verify_cb
#define X509_STORE_CTX_set_verify_cb __NS_SYMBOL(X509_STORE_CTX_set_verify_cb)
#endif

#ifndef X509_STORE_CTX_get0_policy_tree
#define X509_STORE_CTX_get0_policy_tree __NS_SYMBOL(X509_STORE_CTX_get0_policy_tree)
#endif

#ifndef X509_STORE_CTX_get_explicit_policy
#define X509_STORE_CTX_get_explicit_policy __NS_SYMBOL(X509_STORE_CTX_get_explicit_policy)
#endif

#ifndef X509_STORE_CTX_set_default
#define X509_STORE_CTX_set_default __NS_SYMBOL(X509_STORE_CTX_set_default)
#endif

#ifndef DES_ncbc_encrypt
#define DES_ncbc_encrypt __NS_SYMBOL(DES_ncbc_encrypt)
#endif

#ifndef X509_STORE_CTX_get0_param
#define X509_STORE_CTX_get0_param __NS_SYMBOL(X509_STORE_CTX_get0_param)
#endif

#ifndef X509_STORE_CTX_set0_param
#define X509_STORE_CTX_set0_param __NS_SYMBOL(X509_STORE_CTX_set0_param)
#endif

#ifndef ec_GFp_simple_field_mul
#define ec_GFp_simple_field_mul __NS_SYMBOL(ec_GFp_simple_field_mul)
#endif

#ifndef ec_GFp_simple_field_sqr
#define ec_GFp_simple_field_sqr __NS_SYMBOL(ec_GFp_simple_field_sqr)
#endif

#ifndef DES_ede3_cbc_encrypt
#define DES_ede3_cbc_encrypt __NS_SYMBOL(DES_ede3_cbc_encrypt)
#endif

// Externs
#ifndef digest_gost
#define digest_gost __NS_SYMBOL(digest_gost)
#endif

#ifndef _shadow_DES_rw_mode
#define _shadow_DES_rw_mode __NS_SYMBOL(_shadow_DES_rw_mode)
#endif

#ifndef x509_file_lookup
#define x509_file_lookup __NS_SYMBOL(x509_file_lookup)
#endif

#ifndef x509_dir_lookup
#define x509_dir_lookup __NS_SYMBOL(x509_dir_lookup)
#endif

#ifndef rand_ssleay_meth
#define rand_ssleay_meth __NS_SYMBOL(rand_ssleay_meth)
#endif

#ifndef default_pctx
#define default_pctx __NS_SYMBOL(default_pctx)
#endif

#ifndef cipher_gost
#define cipher_gost __NS_SYMBOL(cipher_gost)
#endif

#ifndef cipher_gost_cpacnt
#define cipher_gost_cpacnt __NS_SYMBOL(cipher_gost_cpacnt)
#endif

#ifndef imit_gost_cpa
#define imit_gost_cpa __NS_SYMBOL(imit_gost_cpa)
#endif

#ifndef gost_cipher_list
#define gost_cipher_list __NS_SYMBOL(gost_cipher_list)
#endif

#ifndef R3410_paramset
#define R3410_paramset __NS_SYMBOL(R3410_paramset)
#endif

#ifndef R3410_2001_paramset
#define R3410_2001_paramset __NS_SYMBOL(R3410_2001_paramset)
#endif

#ifndef GostR3411_94_TestParamSet
#define GostR3411_94_TestParamSet __NS_SYMBOL(GostR3411_94_TestParamSet)
#endif

#ifndef GostR3411_94_CryptoProParamSet
#define GostR3411_94_CryptoProParamSet __NS_SYMBOL(GostR3411_94_CryptoProParamSet)
#endif

#ifndef Gost28147_TestParamSet
#define Gost28147_TestParamSet __NS_SYMBOL(Gost28147_TestParamSet)
#endif

#ifndef Gost28147_CryptoProParamSetA
#define Gost28147_CryptoProParamSetA __NS_SYMBOL(Gost28147_CryptoProParamSetA)
#endif

#ifndef Gost28147_CryptoProParamSetB
#define Gost28147_CryptoProParamSetB __NS_SYMBOL(Gost28147_CryptoProParamSetB)
#endif

#ifndef Gost28147_CryptoProParamSetC
#define Gost28147_CryptoProParamSetC __NS_SYMBOL(Gost28147_CryptoProParamSetC)
#endif

#ifndef Gost28147_CryptoProParamSetD
#define Gost28147_CryptoProParamSetD __NS_SYMBOL(Gost28147_CryptoProParamSetD)
#endif

#ifndef v3_crl_num
#define v3_crl_num __NS_SYMBOL(v3_crl_num)
#endif

#ifndef AES_version
#define AES_version __NS_SYMBOL(AES_version)
#endif

#ifndef cmac_asn1_meth
#define cmac_asn1_meth __NS_SYMBOL(cmac_asn1_meth)
#endif

#ifndef v3_delta_crl
#define v3_delta_crl __NS_SYMBOL(v3_delta_crl)
#endif

#ifndef CAMELLIA_version
#define CAMELLIA_version __NS_SYMBOL(CAMELLIA_version)
#endif

#ifndef CAST_version
#define CAST_version __NS_SYMBOL(CAST_version)
#endif

#ifndef BF_version
#define BF_version __NS_SYMBOL(BF_version)
#endif

#ifndef ECDSA_SIG_it
#define ECDSA_SIG_it __NS_SYMBOL(ECDSA_SIG_it)
#endif

#ifndef NETSCAPE_X509_it
#define NETSCAPE_X509_it __NS_SYMBOL(NETSCAPE_X509_it)
#endif

#ifndef X509_SIG_it
#define X509_SIG_it __NS_SYMBOL(X509_SIG_it)
#endif

#ifndef X509_VAL_it
#define X509_VAL_it __NS_SYMBOL(X509_VAL_it)
#endif

#ifndef v3_inhibit_anyp
#define v3_inhibit_anyp __NS_SYMBOL(v3_inhibit_anyp)
#endif

#ifndef RC2_version
#define RC2_version __NS_SYMBOL(RC2_version)
#endif

#ifndef AUTHORITY_KEYID_it
#define AUTHORITY_KEYID_it __NS_SYMBOL(AUTHORITY_KEYID_it)
#endif

#ifndef IDEA_version
#define IDEA_version __NS_SYMBOL(IDEA_version)
#endif

#ifndef NETSCAPE_CERT_SEQUENCE_it
#define NETSCAPE_CERT_SEQUENCE_it __NS_SYMBOL(NETSCAPE_CERT_SEQUENCE_it)
#endif

#ifndef v3_ns_ia5_list
#define v3_ns_ia5_list __NS_SYMBOL(v3_ns_ia5_list)
#endif

#ifndef OSSL_libdes_version
#define OSSL_libdes_version __NS_SYMBOL(OSSL_libdes_version)
#endif

#ifndef DHparams_it
#define DHparams_it __NS_SYMBOL(DHparams_it)
#endif

#ifndef PKEY_USAGE_PERIOD_it
#define PKEY_USAGE_PERIOD_it __NS_SYMBOL(PKEY_USAGE_PERIOD_it)
#endif

#ifndef NETSCAPE_SPKAC_it
#define NETSCAPE_SPKAC_it __NS_SYMBOL(NETSCAPE_SPKAC_it)
#endif

#ifndef OSSL_DES_version
#define OSSL_DES_version __NS_SYMBOL(OSSL_DES_version)
#endif

#ifndef PROXY_POLICY_it
#define PROXY_POLICY_it __NS_SYMBOL(PROXY_POLICY_it)
#endif

#ifndef X509_EXTENSION_it
#define X509_EXTENSION_it __NS_SYMBOL(X509_EXTENSION_it)
#endif

#ifndef v3_crl_reason
#define v3_crl_reason __NS_SYMBOL(v3_crl_reason)
#endif

#ifndef gost_cmds
#define gost_cmds __NS_SYMBOL(gost_cmds)
#endif

#ifndef hmac_asn1_meth
#define hmac_asn1_meth __NS_SYMBOL(hmac_asn1_meth)
#endif

#ifndef v3_pkey_usage_period
#define v3_pkey_usage_period __NS_SYMBOL(v3_pkey_usage_period)
#endif

#ifndef CMS_IssuerAndSerialNumber_it
#define CMS_IssuerAndSerialNumber_it __NS_SYMBOL(CMS_IssuerAndSerialNumber_it)
#endif

#ifndef BIGNUM_it
#define BIGNUM_it __NS_SYMBOL(BIGNUM_it)
#endif

#ifndef X509_ATTRIBUTE_SET_it
#define X509_ATTRIBUTE_SET_it __NS_SYMBOL(X509_ATTRIBUTE_SET_it)
#endif

#ifndef X509_EXTENSIONS_it
#define X509_EXTENSIONS_it __NS_SYMBOL(X509_EXTENSIONS_it)
#endif

#ifndef CBIGNUM_it
#define CBIGNUM_it __NS_SYMBOL(CBIGNUM_it)
#endif

#ifndef PROXY_CERT_INFO_EXTENSION_it
#define PROXY_CERT_INFO_EXTENSION_it __NS_SYMBOL(PROXY_CERT_INFO_EXTENSION_it)
#endif

#ifndef X509_REQ_INFO_it
#define X509_REQ_INFO_it __NS_SYMBOL(X509_REQ_INFO_it)
#endif

#ifndef LONG_it
#define LONG_it __NS_SYMBOL(LONG_it)
#endif

#ifndef NETSCAPE_SPKI_it
#define NETSCAPE_SPKI_it __NS_SYMBOL(NETSCAPE_SPKI_it)
#endif

#ifndef CMS_OtherCertificateFormat_it
#define CMS_OtherCertificateFormat_it __NS_SYMBOL(CMS_OtherCertificateFormat_it)
#endif

#ifndef BASIC_CONSTRAINTS_it
#define BASIC_CONSTRAINTS_it __NS_SYMBOL(BASIC_CONSTRAINTS_it)
#endif

#ifndef POLICY_CONSTRAINTS_it
#define POLICY_CONSTRAINTS_it __NS_SYMBOL(POLICY_CONSTRAINTS_it)
#endif

#ifndef X509_ATTRIBUTE_it
#define X509_ATTRIBUTE_it __NS_SYMBOL(X509_ATTRIBUTE_it)
#endif

#ifndef ZLONG_it
#define ZLONG_it __NS_SYMBOL(ZLONG_it)
#endif

#ifndef EXTENDED_KEY_USAGE_it
#define EXTENDED_KEY_USAGE_it __NS_SYMBOL(EXTENDED_KEY_USAGE_it)
#endif

#ifndef v3_bcons
#define v3_bcons __NS_SYMBOL(v3_bcons)
#endif

#ifndef v3_policy_constraints
#define v3_policy_constraints __NS_SYMBOL(v3_policy_constraints)
#endif

#ifndef v3_skey_id
#define v3_skey_id __NS_SYMBOL(v3_skey_id)
#endif

#ifndef PKCS12_it
#define PKCS12_it __NS_SYMBOL(PKCS12_it)
#endif

#ifndef PKCS8_PRIV_KEY_INFO_it
#define PKCS8_PRIV_KEY_INFO_it __NS_SYMBOL(PKCS8_PRIV_KEY_INFO_it)
#endif

#ifndef RC4_version
#define RC4_version __NS_SYMBOL(RC4_version)
#endif

#ifndef v3_ext_ku
#define v3_ext_ku __NS_SYMBOL(v3_ext_ku)
#endif

#ifndef X509_REQ_it
#define X509_REQ_it __NS_SYMBOL(X509_REQ_it)
#endif

#ifndef X509_ALGOR_it
#define X509_ALGOR_it __NS_SYMBOL(X509_ALGOR_it)
#endif

#ifndef MD5_version
#define MD5_version __NS_SYMBOL(MD5_version)
#endif

#ifndef POLICY_MAPPINGS_it
#define POLICY_MAPPINGS_it __NS_SYMBOL(POLICY_MAPPINGS_it)
#endif

#ifndef RSAPrivateKey_it
#define RSAPrivateKey_it __NS_SYMBOL(RSAPrivateKey_it)
#endif

#ifndef v3_ocsp_accresp
#define v3_ocsp_accresp __NS_SYMBOL(v3_ocsp_accresp)
#endif

#ifndef PBEPARAM_it
#define PBEPARAM_it __NS_SYMBOL(PBEPARAM_it)
#endif

#ifndef cmac_pkey_meth
#define cmac_pkey_meth __NS_SYMBOL(cmac_pkey_meth)
#endif

#ifndef ECDH_version
#define ECDH_version __NS_SYMBOL(ECDH_version)
#endif

#ifndef SHA1_version
#define SHA1_version __NS_SYMBOL(SHA1_version)
#endif

#ifndef X509_ALGORS_it
#define X509_ALGORS_it __NS_SYMBOL(X509_ALGORS_it)
#endif

#ifndef CMS_CertificateChoices_it
#define CMS_CertificateChoices_it __NS_SYMBOL(CMS_CertificateChoices_it)
#endif

#ifndef PKCS12_MAC_DATA_it
#define PKCS12_MAC_DATA_it __NS_SYMBOL(PKCS12_MAC_DATA_it)
#endif

#ifndef v3_policy_mappings
#define v3_policy_mappings __NS_SYMBOL(v3_policy_mappings)
#endif

#ifndef DSA_SIG_it
#define DSA_SIG_it __NS_SYMBOL(DSA_SIG_it)
#endif

#ifndef GOST_KEY_TRANSPORT_it
#define GOST_KEY_TRANSPORT_it __NS_SYMBOL(GOST_KEY_TRANSPORT_it)
#endif

#ifndef ASN1_TIME_it
#define ASN1_TIME_it __NS_SYMBOL(ASN1_TIME_it)
#endif

#ifndef dh_pkey_meth
#define dh_pkey_meth __NS_SYMBOL(dh_pkey_meth)
#endif

#ifndef RSAPublicKey_it
#define RSAPublicKey_it __NS_SYMBOL(RSAPublicKey_it)
#endif

#ifndef CMS_SignerIdentifier_it
#define CMS_SignerIdentifier_it __NS_SYMBOL(CMS_SignerIdentifier_it)
#endif

#ifndef PKCS12_BAGS_it
#define PKCS12_BAGS_it __NS_SYMBOL(PKCS12_BAGS_it)
#endif

#ifndef ECDSA_version
#define ECDSA_version __NS_SYMBOL(ECDSA_version)
#endif

#ifndef v3_akey_id
#define v3_akey_id __NS_SYMBOL(v3_akey_id)
#endif

#ifndef GOST_KEY_INFO_it
#define GOST_KEY_INFO_it __NS_SYMBOL(GOST_KEY_INFO_it)
#endif

#ifndef POLICY_MAPPING_it
#define POLICY_MAPPING_it __NS_SYMBOL(POLICY_MAPPING_it)
#endif

#ifndef v3_nscert
#define v3_nscert __NS_SYMBOL(v3_nscert)
#endif

#ifndef DH_version
#define DH_version __NS_SYMBOL(DH_version)
#endif

#ifndef hmac_pkey_meth
#define hmac_pkey_meth __NS_SYMBOL(hmac_pkey_meth)
#endif

#ifndef CMS_EncapsulatedContentInfo_it
#define CMS_EncapsulatedContentInfo_it __NS_SYMBOL(CMS_EncapsulatedContentInfo_it)
#endif

#ifndef v3_key_usage
#define v3_key_usage __NS_SYMBOL(v3_key_usage)
#endif

#ifndef RSA_PSS_PARAMS_it
#define RSA_PSS_PARAMS_it __NS_SYMBOL(RSA_PSS_PARAMS_it)
#endif

#ifndef v3_ocsp_crlid
#define v3_ocsp_crlid __NS_SYMBOL(v3_ocsp_crlid)
#endif

#ifndef PKCS12_SAFEBAG_it
#define PKCS12_SAFEBAG_it __NS_SYMBOL(PKCS12_SAFEBAG_it)
#endif

#ifndef DSAPrivateKey_it
#define DSAPrivateKey_it __NS_SYMBOL(DSAPrivateKey_it)
#endif

#ifndef GOST_KEY_AGREEMENT_INFO_it
#define GOST_KEY_AGREEMENT_INFO_it __NS_SYMBOL(GOST_KEY_AGREEMENT_INFO_it)
#endif

#ifndef PKCS12_SAFEBAGS_it
#define PKCS12_SAFEBAGS_it __NS_SYMBOL(PKCS12_SAFEBAGS_it)
#endif

#ifndef v3_ocsp_acutoff
#define v3_ocsp_acutoff __NS_SYMBOL(v3_ocsp_acutoff)
#endif

#ifndef OTHERNAME_it
#define OTHERNAME_it __NS_SYMBOL(OTHERNAME_it)
#endif

#ifndef X509_CINF_it
#define X509_CINF_it __NS_SYMBOL(X509_CINF_it)
#endif

#ifndef DSA_version
#define DSA_version __NS_SYMBOL(DSA_version)
#endif

#ifndef AUTHORITY_INFO_ACCESS_it
#define AUTHORITY_INFO_ACCESS_it __NS_SYMBOL(AUTHORITY_INFO_ACCESS_it)
#endif

#ifndef DSAparams_it
#define DSAparams_it __NS_SYMBOL(DSAparams_it)
#endif

#ifndef PKCS12_AUTHSAFES_it
#define PKCS12_AUTHSAFES_it __NS_SYMBOL(PKCS12_AUTHSAFES_it)
#endif

#ifndef v3_crl_invdate
#define v3_crl_invdate __NS_SYMBOL(v3_crl_invdate)
#endif

#ifndef GOST_KEY_PARAMS_it
#define GOST_KEY_PARAMS_it __NS_SYMBOL(GOST_KEY_PARAMS_it)
#endif

#ifndef X509_CERT_AUX_it
#define X509_CERT_AUX_it __NS_SYMBOL(X509_CERT_AUX_it)
#endif

#ifndef v3_info
#define v3_info __NS_SYMBOL(v3_info)
#endif

#ifndef EDIPARTYNAME_it
#define EDIPARTYNAME_it __NS_SYMBOL(EDIPARTYNAME_it)
#endif

#ifndef CMS_SignerInfo_it
#define CMS_SignerInfo_it __NS_SYMBOL(CMS_SignerInfo_it)
#endif

#ifndef X509_it
#define X509_it __NS_SYMBOL(X509_it)
#endif

#ifndef v3_crl_hold
#define v3_crl_hold __NS_SYMBOL(v3_crl_hold)
#endif

#ifndef ec_pkey_meth
#define ec_pkey_meth __NS_SYMBOL(ec_pkey_meth)
#endif

#ifndef v3_sinfo
#define v3_sinfo __NS_SYMBOL(v3_sinfo)
#endif

#ifndef GOST_CIPHER_PARAMS_it
#define GOST_CIPHER_PARAMS_it __NS_SYMBOL(GOST_CIPHER_PARAMS_it)
#endif

#ifndef X509_CERT_PAIR_it
#define X509_CERT_PAIR_it __NS_SYMBOL(X509_CERT_PAIR_it)
#endif

#ifndef KRB5_ENCDATA_it
#define KRB5_ENCDATA_it __NS_SYMBOL(KRB5_ENCDATA_it)
#endif

#ifndef dsa_pkey_meth
#define dsa_pkey_meth __NS_SYMBOL(dsa_pkey_meth)
#endif

#ifndef RSA_version
#define RSA_version __NS_SYMBOL(RSA_version)
#endif

#ifndef dsa_pub_internal_it
#define dsa_pub_internal_it __NS_SYMBOL(dsa_pub_internal_it)
#endif

#ifndef v3_ocsp_nonce
#define v3_ocsp_nonce __NS_SYMBOL(v3_ocsp_nonce)
#endif

#ifndef CMS_OtherRevocationInfoFormat_it
#define CMS_OtherRevocationInfoFormat_it __NS_SYMBOL(CMS_OtherRevocationInfoFormat_it)
#endif

#ifndef GOST_CLIENT_KEY_EXCHANGE_PARAMS_it
#define GOST_CLIENT_KEY_EXCHANGE_PARAMS_it __NS_SYMBOL(GOST_CLIENT_KEY_EXCHANGE_PARAMS_it)
#endif

#ifndef SHA256_version
#define SHA256_version __NS_SYMBOL(SHA256_version)
#endif

#ifndef v3_ocsp_nocheck
#define v3_ocsp_nocheck __NS_SYMBOL(v3_ocsp_nocheck)
#endif

#ifndef ACCESS_DESCRIPTION_it
#define ACCESS_DESCRIPTION_it __NS_SYMBOL(ACCESS_DESCRIPTION_it)
#endif

#ifndef KRB5_PRINCNAME_it
#define KRB5_PRINCNAME_it __NS_SYMBOL(KRB5_PRINCNAME_it)
#endif

#ifndef PKCS7_it
#define PKCS7_it __NS_SYMBOL(PKCS7_it)
#endif

#ifndef DSAPublicKey_it
#define DSAPublicKey_it __NS_SYMBOL(DSAPublicKey_it)
#endif

#ifndef CMS_RevocationInfoChoice_it
#define CMS_RevocationInfoChoice_it __NS_SYMBOL(CMS_RevocationInfoChoice_it)
#endif

#ifndef v3_ocsp_serviceloc
#define v3_ocsp_serviceloc __NS_SYMBOL(v3_ocsp_serviceloc)
#endif

#ifndef PBE2PARAM_it
#define PBE2PARAM_it __NS_SYMBOL(PBE2PARAM_it)
#endif

#ifndef GENERAL_NAME_it
#define GENERAL_NAME_it __NS_SYMBOL(GENERAL_NAME_it)
#endif

#ifndef KRB5_TKTBODY_it
#define KRB5_TKTBODY_it __NS_SYMBOL(KRB5_TKTBODY_it)
#endif

#ifndef GENERAL_NAMES_it
#define GENERAL_NAMES_it __NS_SYMBOL(GENERAL_NAMES_it)
#endif

#ifndef PKCS7_SIGNED_it
#define PKCS7_SIGNED_it __NS_SYMBOL(PKCS7_SIGNED_it)
#endif

#ifndef KRB5_TICKET_it
#define KRB5_TICKET_it __NS_SYMBOL(KRB5_TICKET_it)
#endif

#ifndef PBKDF2PARAM_it
#define PBKDF2PARAM_it __NS_SYMBOL(PBKDF2PARAM_it)
#endif

#ifndef CMS_SignedData_it
#define CMS_SignedData_it __NS_SYMBOL(CMS_SignedData_it)
#endif

#ifndef OCSP_SIGNATURE_it
#define OCSP_SIGNATURE_it __NS_SYMBOL(OCSP_SIGNATURE_it)
#endif

#ifndef SXNET_it
#define SXNET_it __NS_SYMBOL(SXNET_it)
#endif

#ifndef SHA512_version
#define SHA512_version __NS_SYMBOL(SHA512_version)
#endif

#ifndef v3_sxnet
#define v3_sxnet __NS_SYMBOL(v3_sxnet)
#endif

#ifndef CMS_OriginatorInfo_it
#define CMS_OriginatorInfo_it __NS_SYMBOL(CMS_OriginatorInfo_it)
#endif

#ifndef lh_version
#define lh_version __NS_SYMBOL(lh_version)
#endif

#ifndef KRB5_APREQBODY_it
#define KRB5_APREQBODY_it __NS_SYMBOL(KRB5_APREQBODY_it)
#endif

#ifndef OCSP_CERTID_it
#define OCSP_CERTID_it __NS_SYMBOL(OCSP_CERTID_it)
#endif

#ifndef MD4_version
#define MD4_version __NS_SYMBOL(MD4_version)
#endif

#ifndef SXNETID_it
#define SXNETID_it __NS_SYMBOL(SXNETID_it)
#endif

#ifndef PKCS7_SIGNER_INFO_it
#define PKCS7_SIGNER_INFO_it __NS_SYMBOL(PKCS7_SIGNER_INFO_it)
#endif

#ifndef CMS_EncryptedContentInfo_it
#define CMS_EncryptedContentInfo_it __NS_SYMBOL(CMS_EncryptedContentInfo_it)
#endif

#ifndef KRB5_APREQ_it
#define KRB5_APREQ_it __NS_SYMBOL(KRB5_APREQ_it)
#endif

#ifndef OCSP_ONEREQ_it
#define OCSP_ONEREQ_it __NS_SYMBOL(OCSP_ONEREQ_it)
#endif

#ifndef STACK_version
#define STACK_version __NS_SYMBOL(STACK_version)
#endif

#ifndef X509_PUBKEY_it
#define X509_PUBKEY_it __NS_SYMBOL(X509_PUBKEY_it)
#endif

#ifndef PKCS7_ISSUER_AND_SERIAL_it
#define PKCS7_ISSUER_AND_SERIAL_it __NS_SYMBOL(PKCS7_ISSUER_AND_SERIAL_it)
#endif

#ifndef ASN1_version
#define ASN1_version __NS_SYMBOL(ASN1_version)
#endif

#ifndef KRB5_CHECKSUM_it
#define KRB5_CHECKSUM_it __NS_SYMBOL(KRB5_CHECKSUM_it)
#endif

#ifndef NAME_CONSTRAINTS_it
#define NAME_CONSTRAINTS_it __NS_SYMBOL(NAME_CONSTRAINTS_it)
#endif

#ifndef v3_name_constraints
#define v3_name_constraints __NS_SYMBOL(v3_name_constraints)
#endif

#ifndef TXT_DB_version
#define TXT_DB_version __NS_SYMBOL(TXT_DB_version)
#endif

#ifndef CMS_KeyTransRecipientInfo_it
#define CMS_KeyTransRecipientInfo_it __NS_SYMBOL(CMS_KeyTransRecipientInfo_it)
#endif

#ifndef v3_pci
#define v3_pci __NS_SYMBOL(v3_pci)
#endif

#ifndef KRB5_ENCKEY_it
#define KRB5_ENCKEY_it __NS_SYMBOL(KRB5_ENCKEY_it)
#endif

#ifndef OCSP_REQINFO_it
#define OCSP_REQINFO_it __NS_SYMBOL(OCSP_REQINFO_it)
#endif

#ifndef PKCS7_ENVELOPE_it
#define PKCS7_ENVELOPE_it __NS_SYMBOL(PKCS7_ENVELOPE_it)
#endif

#ifndef CONF_version
#define CONF_version __NS_SYMBOL(CONF_version)
#endif

#ifndef NETSCAPE_ENCRYPTED_PKEY_it
#define NETSCAPE_ENCRYPTED_PKEY_it __NS_SYMBOL(NETSCAPE_ENCRYPTED_PKEY_it)
#endif

#ifndef TS_MSG_IMPRINT_it
#define TS_MSG_IMPRINT_it __NS_SYMBOL(TS_MSG_IMPRINT_it)
#endif

#ifndef CMS_OtherKeyAttribute_it
#define CMS_OtherKeyAttribute_it __NS_SYMBOL(CMS_OtherKeyAttribute_it)
#endif

#ifndef GENERAL_SUBTREE_it
#define GENERAL_SUBTREE_it __NS_SYMBOL(GENERAL_SUBTREE_it)
#endif

#ifndef KRB5_AUTHDATA_it
#define KRB5_AUTHDATA_it __NS_SYMBOL(KRB5_AUTHDATA_it)
#endif

#ifndef OCSP_REQUEST_it
#define OCSP_REQUEST_it __NS_SYMBOL(OCSP_REQUEST_it)
#endif

#ifndef X509_REVOKED_it
#define X509_REVOKED_it __NS_SYMBOL(X509_REVOKED_it)
#endif

#ifndef PKCS7_RECIP_INFO_it
#define PKCS7_RECIP_INFO_it __NS_SYMBOL(PKCS7_RECIP_INFO_it)
#endif

#ifndef NETSCAPE_PKEY_it
#define NETSCAPE_PKEY_it __NS_SYMBOL(NETSCAPE_PKEY_it)
#endif

#ifndef dh_asn1_meth
#define dh_asn1_meth __NS_SYMBOL(dh_asn1_meth)
#endif

#ifndef CMS_RecipientKeyIdentifier_it
#define CMS_RecipientKeyIdentifier_it __NS_SYMBOL(CMS_RecipientKeyIdentifier_it)
#endif

#ifndef OCSP_RESPBYTES_it
#define OCSP_RESPBYTES_it __NS_SYMBOL(OCSP_RESPBYTES_it)
#endif

#ifndef RAND_version
#define RAND_version __NS_SYMBOL(RAND_version)
#endif

#ifndef ASN1_INTEGER_it
#define ASN1_INTEGER_it __NS_SYMBOL(ASN1_INTEGER_it)
#endif

#ifndef TS_REQ_it
#define TS_REQ_it __NS_SYMBOL(TS_REQ_it)
#endif

#ifndef ASN1_ENUMERATED_it
#define ASN1_ENUMERATED_it __NS_SYMBOL(ASN1_ENUMERATED_it)
#endif

#ifndef CMS_KeyAgreeRecipientIdentifier_it
#define CMS_KeyAgreeRecipientIdentifier_it __NS_SYMBOL(CMS_KeyAgreeRecipientIdentifier_it)
#endif

#ifndef PKCS7_ENC_CONTENT_it
#define PKCS7_ENC_CONTENT_it __NS_SYMBOL(PKCS7_ENC_CONTENT_it)
#endif

#ifndef X509_NAME_ENTRY_it
#define X509_NAME_ENTRY_it __NS_SYMBOL(X509_NAME_ENTRY_it)
#endif

#ifndef OCSP_RESPONSE_it
#define OCSP_RESPONSE_it __NS_SYMBOL(OCSP_RESPONSE_it)
#endif

#ifndef ASN1_BIT_STRING_it
#define ASN1_BIT_STRING_it __NS_SYMBOL(ASN1_BIT_STRING_it)
#endif

#ifndef ASN1_OCTET_STRING_it
#define ASN1_OCTET_STRING_it __NS_SYMBOL(ASN1_OCTET_STRING_it)
#endif

#ifndef X509_NAME_ENTRIES_it
#define X509_NAME_ENTRIES_it __NS_SYMBOL(X509_NAME_ENTRIES_it)
#endif

#ifndef TS_ACCURACY_it
#define TS_ACCURACY_it __NS_SYMBOL(TS_ACCURACY_it)
#endif

#ifndef CMS_RecipientEncryptedKey_it
#define CMS_RecipientEncryptedKey_it __NS_SYMBOL(CMS_RecipientEncryptedKey_it)
#endif

#ifndef X509_CRL_INFO_it
#define X509_CRL_INFO_it __NS_SYMBOL(X509_CRL_INFO_it)
#endif

#ifndef ASN1_NULL_it
#define ASN1_NULL_it __NS_SYMBOL(ASN1_NULL_it)
#endif

#ifndef KRB5_AUTHENTBODY_it
#define KRB5_AUTHENTBODY_it __NS_SYMBOL(KRB5_AUTHENTBODY_it)
#endif

#ifndef OCSP_RESPID_it
#define OCSP_RESPID_it __NS_SYMBOL(OCSP_RESPID_it)
#endif

#ifndef X509_NAME_INTERNAL_it
#define X509_NAME_INTERNAL_it __NS_SYMBOL(X509_NAME_INTERNAL_it)
#endif

#ifndef ASN1_OBJECT_it
#define ASN1_OBJECT_it __NS_SYMBOL(ASN1_OBJECT_it)
#endif

#ifndef KRB5_AUTHENT_it
#define KRB5_AUTHENT_it __NS_SYMBOL(KRB5_AUTHENT_it)
#endif

#ifndef x509_name_ff
#define x509_name_ff __NS_SYMBOL(x509_name_ff)
#endif

#ifndef ASN1_UTF8STRING_it
#define ASN1_UTF8STRING_it __NS_SYMBOL(ASN1_UTF8STRING_it)
#endif

#ifndef CMS_OriginatorPublicKey_it
#define CMS_OriginatorPublicKey_it __NS_SYMBOL(CMS_OriginatorPublicKey_it)
#endif

#ifndef OCSP_REVOKEDINFO_it
#define OCSP_REVOKEDINFO_it __NS_SYMBOL(OCSP_REVOKEDINFO_it)
#endif

#ifndef X509_NAME_it
#define X509_NAME_it __NS_SYMBOL(X509_NAME_it)
#endif

#ifndef X509_CRL_it
#define X509_CRL_it __NS_SYMBOL(X509_CRL_it)
#endif

#ifndef ASN1_PRINTABLESTRING_it
#define ASN1_PRINTABLESTRING_it __NS_SYMBOL(ASN1_PRINTABLESTRING_it)
#endif

#ifndef PKCS7_SIGN_ENVELOPE_it
#define PKCS7_SIGN_ENVELOPE_it __NS_SYMBOL(PKCS7_SIGN_ENVELOPE_it)
#endif

#ifndef ASN1_T61STRING_it
#define ASN1_T61STRING_it __NS_SYMBOL(ASN1_T61STRING_it)
#endif

#ifndef ASN1_IA5STRING_it
#define ASN1_IA5STRING_it __NS_SYMBOL(ASN1_IA5STRING_it)
#endif

#ifndef CMS_OriginatorIdentifierOrKey_it
#define CMS_OriginatorIdentifierOrKey_it __NS_SYMBOL(CMS_OriginatorIdentifierOrKey_it)
#endif

#ifndef PKCS7_ENCRYPT_it
#define PKCS7_ENCRYPT_it __NS_SYMBOL(PKCS7_ENCRYPT_it)
#endif

#ifndef ASN1_GENERALSTRING_it
#define ASN1_GENERALSTRING_it __NS_SYMBOL(ASN1_GENERALSTRING_it)
#endif

#ifndef OCSP_CERTSTATUS_it
#define OCSP_CERTSTATUS_it __NS_SYMBOL(OCSP_CERTSTATUS_it)
#endif

#ifndef CAST_S_table0
#define CAST_S_table0 __NS_SYMBOL(CAST_S_table0)
#endif

#ifndef ASN1_UTCTIME_it
#define ASN1_UTCTIME_it __NS_SYMBOL(ASN1_UTCTIME_it)
#endif

#ifndef TS_TST_INFO_it
#define TS_TST_INFO_it __NS_SYMBOL(TS_TST_INFO_it)
#endif

#ifndef ASN1_GENERALIZEDTIME_it
#define ASN1_GENERALIZEDTIME_it __NS_SYMBOL(ASN1_GENERALIZEDTIME_it)
#endif

#ifndef ASN1_VISIBLESTRING_it
#define ASN1_VISIBLESTRING_it __NS_SYMBOL(ASN1_VISIBLESTRING_it)
#endif

#ifndef PKCS7_DIGEST_it
#define PKCS7_DIGEST_it __NS_SYMBOL(PKCS7_DIGEST_it)
#endif

#ifndef ASN1_UNIVERSALSTRING_it
#define ASN1_UNIVERSALSTRING_it __NS_SYMBOL(ASN1_UNIVERSALSTRING_it)
#endif

#ifndef CMS_KeyAgreeRecipientInfo_it
#define CMS_KeyAgreeRecipientInfo_it __NS_SYMBOL(CMS_KeyAgreeRecipientInfo_it)
#endif

#ifndef rsa_pkey_meth
#define rsa_pkey_meth __NS_SYMBOL(rsa_pkey_meth)
#endif

#ifndef OCSP_SINGLERESP_it
#define OCSP_SINGLERESP_it __NS_SYMBOL(OCSP_SINGLERESP_it)
#endif

#ifndef TS_STATUS_INFO_it
#define TS_STATUS_INFO_it __NS_SYMBOL(TS_STATUS_INFO_it)
#endif

#ifndef ASN1_BMPSTRING_it
#define ASN1_BMPSTRING_it __NS_SYMBOL(ASN1_BMPSTRING_it)
#endif

#ifndef PKCS7_ATTR_SIGN_it
#define PKCS7_ATTR_SIGN_it __NS_SYMBOL(PKCS7_ATTR_SIGN_it)
#endif

#ifndef ASN1_ANY_it
#define ASN1_ANY_it __NS_SYMBOL(ASN1_ANY_it)
#endif

#ifndef _shadow_DES_check_key
#define _shadow_DES_check_key __NS_SYMBOL(_shadow_DES_check_key)
#endif

#ifndef ASN1_SEQUENCE_it
#define ASN1_SEQUENCE_it __NS_SYMBOL(ASN1_SEQUENCE_it)
#endif

#ifndef PKCS7_ATTR_VERIFY_it
#define PKCS7_ATTR_VERIFY_it __NS_SYMBOL(PKCS7_ATTR_VERIFY_it)
#endif

#ifndef CMS_KEKIdentifier_it
#define CMS_KEKIdentifier_it __NS_SYMBOL(CMS_KEKIdentifier_it)
#endif

#ifndef TS_RESP_it
#define TS_RESP_it __NS_SYMBOL(TS_RESP_it)
#endif

#ifndef ASN1_PRINTABLE_it
#define ASN1_PRINTABLE_it __NS_SYMBOL(ASN1_PRINTABLE_it)
#endif

#ifndef eckey_asn1_meth
#define eckey_asn1_meth __NS_SYMBOL(eckey_asn1_meth)
#endif

#ifndef DISPLAYTEXT_it
#define DISPLAYTEXT_it __NS_SYMBOL(DISPLAYTEXT_it)
#endif

#ifndef OCSP_RESPDATA_it
#define OCSP_RESPDATA_it __NS_SYMBOL(OCSP_RESPDATA_it)
#endif

#ifndef ESS_ISSUER_SERIAL_it
#define ESS_ISSUER_SERIAL_it __NS_SYMBOL(ESS_ISSUER_SERIAL_it)
#endif

#ifndef DIRECTORYSTRING_it
#define DIRECTORYSTRING_it __NS_SYMBOL(DIRECTORYSTRING_it)
#endif

#ifndef ASN1_BOOLEAN_it
#define ASN1_BOOLEAN_it __NS_SYMBOL(ASN1_BOOLEAN_it)
#endif

#ifndef CMS_KEKRecipientInfo_it
#define CMS_KEKRecipientInfo_it __NS_SYMBOL(CMS_KEKRecipientInfo_it)
#endif

#ifndef dsa_asn1_meths
#define dsa_asn1_meths __NS_SYMBOL(dsa_asn1_meths)
#endif

#ifndef ASN1_TBOOLEAN_it
#define ASN1_TBOOLEAN_it __NS_SYMBOL(ASN1_TBOOLEAN_it)
#endif

#ifndef CERTIFICATEPOLICIES_it
#define CERTIFICATEPOLICIES_it __NS_SYMBOL(CERTIFICATEPOLICIES_it)
#endif

#ifndef ESS_CERT_ID_it
#define ESS_CERT_ID_it __NS_SYMBOL(ESS_CERT_ID_it)
#endif

#ifndef ASN1_FBOOLEAN_it
#define ASN1_FBOOLEAN_it __NS_SYMBOL(ASN1_FBOOLEAN_it)
#endif

#ifndef OCSP_BASICRESP_it
#define OCSP_BASICRESP_it __NS_SYMBOL(OCSP_BASICRESP_it)
#endif

#ifndef v3_cpols
#define v3_cpols __NS_SYMBOL(v3_cpols)
#endif

#ifndef ASN1_OCTET_STRING_NDEF_it
#define ASN1_OCTET_STRING_NDEF_it __NS_SYMBOL(ASN1_OCTET_STRING_NDEF_it)
#endif

#ifndef CRL_DIST_POINTS_it
#define CRL_DIST_POINTS_it __NS_SYMBOL(CRL_DIST_POINTS_it)
#endif

#ifndef v3_alt
#define v3_alt __NS_SYMBOL(v3_alt)
#endif

#ifndef app_pkey_methods
#define app_pkey_methods __NS_SYMBOL(app_pkey_methods)
#endif

#ifndef CMS_PasswordRecipientInfo_it
#define CMS_PasswordRecipientInfo_it __NS_SYMBOL(CMS_PasswordRecipientInfo_it)
#endif

#ifndef CONF_def_version
#define CONF_def_version __NS_SYMBOL(CONF_def_version)
#endif

#ifndef ESS_SIGNING_CERT_it
#define ESS_SIGNING_CERT_it __NS_SYMBOL(ESS_SIGNING_CERT_it)
#endif

#ifndef v3_crld
#define v3_crld __NS_SYMBOL(v3_crld)
#endif

#ifndef ASN1_SEQUENCE_ANY_it
#define ASN1_SEQUENCE_ANY_it __NS_SYMBOL(ASN1_SEQUENCE_ANY_it)
#endif

#ifndef OCSP_CRLID_it
#define OCSP_CRLID_it __NS_SYMBOL(OCSP_CRLID_it)
#endif

#ifndef EVP_version
#define EVP_version __NS_SYMBOL(EVP_version)
#endif

#ifndef v3_freshest_crl
#define v3_freshest_crl __NS_SYMBOL(v3_freshest_crl)
#endif

#ifndef ASN1_SET_ANY_it
#define ASN1_SET_ANY_it __NS_SYMBOL(ASN1_SET_ANY_it)
#endif

#ifndef CMS_OtherRecipientInfo_it
#define CMS_OtherRecipientInfo_it __NS_SYMBOL(CMS_OtherRecipientInfo_it)
#endif

#ifndef POLICYINFO_it
#define POLICYINFO_it __NS_SYMBOL(POLICYINFO_it)
#endif

#ifndef OCSP_SERVICELOC_it
#define OCSP_SERVICELOC_it __NS_SYMBOL(OCSP_SERVICELOC_it)
#endif

#ifndef CAST_S_table1
#define CAST_S_table1 __NS_SYMBOL(CAST_S_table1)
#endif

#ifndef POLICYQUALINFO_it
#define POLICYQUALINFO_it __NS_SYMBOL(POLICYQUALINFO_it)
#endif

#ifndef BN_version
#define BN_version __NS_SYMBOL(BN_version)
#endif

#ifndef DIST_POINT_NAME_it
#define DIST_POINT_NAME_it __NS_SYMBOL(DIST_POINT_NAME_it)
#endif

#ifndef CMS_RecipientInfo_it
#define CMS_RecipientInfo_it __NS_SYMBOL(CMS_RecipientInfo_it)
#endif

#ifndef USERNOTICE_it
#define USERNOTICE_it __NS_SYMBOL(USERNOTICE_it)
#endif

#ifndef rsa_asn1_meths
#define rsa_asn1_meths __NS_SYMBOL(rsa_asn1_meths)
#endif

#ifndef DIST_POINT_it
#define DIST_POINT_it __NS_SYMBOL(DIST_POINT_it)
#endif

#ifndef NOTICEREF_it
#define NOTICEREF_it __NS_SYMBOL(NOTICEREF_it)
#endif

#ifndef CMS_EnvelopedData_it
#define CMS_EnvelopedData_it __NS_SYMBOL(CMS_EnvelopedData_it)
#endif

#ifndef SHA_version
#define SHA_version __NS_SYMBOL(SHA_version)
#endif

#ifndef ISSUING_DIST_POINT_it
#define ISSUING_DIST_POINT_it __NS_SYMBOL(ISSUING_DIST_POINT_it)
#endif

#ifndef CMS_DigestedData_it
#define CMS_DigestedData_it __NS_SYMBOL(CMS_DigestedData_it)
#endif

#ifndef v3_idp
#define v3_idp __NS_SYMBOL(v3_idp)
#endif

#ifndef OPENSSL_NONPIC_relocated
#define OPENSSL_NONPIC_relocated __NS_SYMBOL(OPENSSL_NONPIC_relocated)
#endif

#ifndef CMS_EncryptedData_it
#define CMS_EncryptedData_it __NS_SYMBOL(CMS_EncryptedData_it)
#endif

#ifndef CAST_S_table2
#define CAST_S_table2 __NS_SYMBOL(CAST_S_table2)
#endif

#ifndef CMS_AuthenticatedData_it
#define CMS_AuthenticatedData_it __NS_SYMBOL(CMS_AuthenticatedData_it)
#endif

#ifndef CMS_CompressedData_it
#define CMS_CompressedData_it __NS_SYMBOL(CMS_CompressedData_it)
#endif

#ifndef CMS_ContentInfo_it
#define CMS_ContentInfo_it __NS_SYMBOL(CMS_ContentInfo_it)
#endif

#ifndef RMD160_version
#define RMD160_version __NS_SYMBOL(RMD160_version)
#endif

#ifndef CMS_Attributes_Sign_it
#define CMS_Attributes_Sign_it __NS_SYMBOL(CMS_Attributes_Sign_it)
#endif

#ifndef CMS_Attributes_Verify_it
#define CMS_Attributes_Verify_it __NS_SYMBOL(CMS_Attributes_Verify_it)
#endif

#ifndef CMS_ReceiptsFrom_it
#define CMS_ReceiptsFrom_it __NS_SYMBOL(CMS_ReceiptsFrom_it)
#endif

#ifndef CAST_S_table3
#define CAST_S_table3 __NS_SYMBOL(CAST_S_table3)
#endif

#ifndef CMS_ReceiptRequest_it
#define CMS_ReceiptRequest_it __NS_SYMBOL(CMS_ReceiptRequest_it)
#endif

#ifndef CMS_Receipt_it
#define CMS_Receipt_it __NS_SYMBOL(CMS_Receipt_it)
#endif

#ifndef PEM_version
#define PEM_version __NS_SYMBOL(PEM_version)
#endif

#ifndef CAST_S_table4
#define CAST_S_table4 __NS_SYMBOL(CAST_S_table4)
#endif

#ifndef CryptoProKeyMeshingKey
#define CryptoProKeyMeshingKey __NS_SYMBOL(CryptoProKeyMeshingKey)
#endif

#ifndef CAST_S_table5
#define CAST_S_table5 __NS_SYMBOL(CAST_S_table5)
#endif

#ifndef CAST_S_table6
#define CAST_S_table6 __NS_SYMBOL(CAST_S_table6)
#endif

#ifndef X9_62_PENTANOMIAL_it
#define X9_62_PENTANOMIAL_it __NS_SYMBOL(X9_62_PENTANOMIAL_it)
#endif

#ifndef X9_62_CHARACTERISTIC_TWO_it
#define X9_62_CHARACTERISTIC_TWO_it __NS_SYMBOL(X9_62_CHARACTERISTIC_TWO_it)
#endif

#ifndef X9_62_FIELDID_it
#define X9_62_FIELDID_it __NS_SYMBOL(X9_62_FIELDID_it)
#endif

#ifndef X9_62_CURVE_it
#define X9_62_CURVE_it __NS_SYMBOL(X9_62_CURVE_it)
#endif

#ifndef ECPARAMETERS_it
#define ECPARAMETERS_it __NS_SYMBOL(ECPARAMETERS_it)
#endif

#ifndef CAST_S_table7
#define CAST_S_table7 __NS_SYMBOL(CAST_S_table7)
#endif

#ifndef ECPKPARAMETERS_it
#define ECPKPARAMETERS_it __NS_SYMBOL(ECPKPARAMETERS_it)
#endif

#ifndef p_CSwift_AcquireAccContext
#define p_CSwift_AcquireAccContext __NS_SYMBOL(p_CSwift_AcquireAccContext)
#endif

#ifndef p_CSwift_AttachKeyParam
#define p_CSwift_AttachKeyParam __NS_SYMBOL(p_CSwift_AttachKeyParam)
#endif

#ifndef p_CSwift_SimpleRequest
#define p_CSwift_SimpleRequest __NS_SYMBOL(p_CSwift_SimpleRequest)
#endif

#ifndef p_CSwift_ReleaseAccContext
#define p_CSwift_ReleaseAccContext __NS_SYMBOL(p_CSwift_ReleaseAccContext)
#endif

#ifndef EC_PRIVATEKEY_it
#define EC_PRIVATEKEY_it __NS_SYMBOL(EC_PRIVATEKEY_it)
#endif

#ifndef X509_version
#define X509_version __NS_SYMBOL(X509_version)
#endif

#ifndef DES_SPtrans
#define DES_SPtrans __NS_SYMBOL(DES_SPtrans)
#endif

#ifndef obj_cleanup_defer
#define obj_cleanup_defer __NS_SYMBOL(obj_cleanup_defer)
#endif

