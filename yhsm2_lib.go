package yhsm2go

/*
#cgo CFLAGS: -I/usr/include -std=c99
#cgo LDFLAGS: -L/usr/lib  -lyubihsm -lyubihsm_usb -lyubihsm_http
#include <stdlib.h>
#include <stdio.h>
#include <yubihsm.h>

void yh_set_debug_output_bridge(yh_connector *connector, const char *fpath){
	FILE* fio = fopen(fpath, "w+b");
	yh_set_debug_output(connector, fio);
	return;
}
*/
import "C"

import (
	"unsafe"
)

/**
 * Return a string describing an error condition
 *
 * @param err #yh_rc error code
 *
 * @return String with descriptive error
 **/
func YH_strerror(err YH_rc) string {
	err_ch := C.yh_strerror(C.yh_rc(err))
	return C.GoString(err_ch)
}

/**
 * Set verbosity level when executing commands. Default verbosity is
 *#YH_VERB_QUIET
 *
 * This function may be called prior to global library initialization to set
 * the debug level
 *
 * @param connector If not NULL, the verbosity of the specific connector will
 * be set
 * @param verbosity The desired level of debug output
 *
 * @return #YHR_SUCCESS
 *
 * @see YH_VERB_QUIET, YH_VERB_INTERMEDIATE, YH_VERB_CRYPTO, YH_VERB_RAW,
 * YH_VERB_INFO, YH_VERB_ERR, YH_VERB_ALL
 **/
func YH_set_verbosity(connector *YH_connector, verbosity uint8) YH_rc {
	return YH_rc(C.yh_set_verbosity((*C.yh_connector)(unsafe.Pointer(connector)), C.uint8_t(verbosity)))
}

/**
 * Get verbosity level when executing commands
 *
 * @param verbosity The verbosity level
 *
 * @return #YHR_SUCCESS if seccessful.
 *         #YHR_INVALID_PARAMETERS if verbosity is NULL
 *
 * @see YH_VERB_QUIET, YH_VERB_INTERMEDIATE, YH_VERB_CRYPTO, YH_VERB_RAW,
 * YH_VERB_INFO, YH_VERB_ERR, YH_VERB_ALL
 **/
func YH_get_verbosity(verbosity *uint8) YH_rc {
	return YH_rc(C.yh_get_verbosity((*C.uint8_t)(unsafe.Pointer(verbosity))))
}

/**
 * Set file for debug output
 *
 * @param connector If not NULL, the debug messages will be written to the
 *specified output file
 * @param fpath The filepath for the destination of the debug messages
 *
 * @return void
 **/
func YH_set_debug_output(connector *YH_connector, fpath string) {
 dbg_fpath := C.CString(fpath)
 C.yh_set_debug_output_bridge((*C.yh_connector)(unsafe.Pointer(connector)), dbg_fpath)
 C.free(unsafe.Pointer(dbg_fpath))
 return
}

/**
 * Global library initialization
 *
 * @return #YHR_SUCCESS
 **/
func YH_init() YH_rc {
	return YH_rc(C.yh_init())
}

/**
 * Global library clean up
 *
 * @return #YHR_SUCCESS
 **/
func YH_exit() YH_rc {
	return YH_rc(C.yh_exit())
}

/**
 * Instantiate a new connector
 *
 * @param url URL associated with this connector
 * @param connector Connector to the device
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if either the URL or the connector are NULL.
 *         #YHR_GENERIC_ERROR if failed to load the backend.
 *         #YHR_MEMORY_ERROR if failed to allocate memory for the connector.
 *         #YHR_CONNECTION_ERROR if failed to create the connector
 */
func YH_init_connector(url string) (*YH_connector, YH_rc) {
	curl := C.CString(url)
	var connector *YH_connector
	rc := C.yh_init_connector(curl, (**C.yh_connector)(unsafe.Pointer(&connector)))
	C.free(unsafe.Pointer(curl))
	return connector, YH_rc(rc)
}

/**
 * Set connector options.
 *
 * Note that backend options are not supported with winhttp or USB connectors
 *
 * @param connector Connector to set an option on
 * @param opt Option to set. See #yh_connector_option
 * @param val Value of the option. Type of value is specific to the given
 *option
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if the connector or the value are NULL or if
 *the option is unknown. #YHR_CONNECTOR_ERROR if failed to set the option
 **/
func YH_set_connector_option(connector *YH_connector, opt YH_connector_option, value string) YH_rc {
	v := C.CString(value)
	rc := C.yh_set_connector_option(	(*C.yh_connector)(unsafe.Pointer(connector)),
																		(C.yh_connector_option)(opt),
                              			unsafe.Pointer(v))
	C.free(unsafe.Pointer(v))
	return YH_rc(rc)

}

/**
 * Connect to the device through the specified connector
 *
 * @param connector Connector to the device
 * @param timeout Connection timeout in seconds
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if the connector does not exist.
 *         See #yh_rc for other possible errors
 **/
func YH_connect(connector *YH_connector, timeout int) YH_rc {
	return YH_rc(C.yh_connect((*C.yh_connector)(unsafe.Pointer(connector)), C.int(timeout)))
}


/**
 * Disconnect from a connector
 *
 * @param connector Connector from which to disconnect
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if the connector is NULL
 **/
func YH_disconnect(connector *YH_connector) YH_rc {
	return YH_rc(C.yh_disconnect((*C.yh_connector)(unsafe.Pointer(connector))))
}

/**
 * Send a plain (unencrypted) message to the device through a connector
 *
 * @param connector Connector to the device
 * @param cmd Command to send. See #yh_cmd
 * @param data Data to send
 * @param data_len length of data to send
 * @param response_cmd Response command
 * @param response Response data
 * @param response_len Length of response data
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL.
 *         #YHR_BUFFER_TOO_SMALL if the actual response was longer than
 *response_len. See #yh_rc for other possible errors
 **/
func YH_send_plain_msg(connector *YH_connector, cmd YH_cmd, data []byte, data_len int, response_cmd *YH_cmd, response []byte, response_len *int) YH_rc {

	rc := C.yh_send_plain_msg((*C.yh_connector)(unsafe.Pointer(connector)), (C.yh_cmd)(cmd),
		                        (*C.uint8_t)(unsafe.Pointer(&data[0])), (C.size_t)(data_len),
		                        (*C.yh_cmd)(unsafe.Pointer(response_cmd)), (*C.uint8_t)(unsafe.Pointer(&response[0])),
		                        (*C.size_t)(unsafe.Pointer(response_len)))

  return YH_rc(rc)
}

/**
 * Send an encrypted message to the device over a session. The session has to be
 *authenticated
 *
 * @param session Session to send the message over
 * @param cmd Command to send
 * @param data Data to send
 * @param data_len length of data to send
 * @param response_cmd Response command
 * @param response Response data
 * @param response_buffer_len Length of response buffer
 *
 * @return #YHR_SUCCESS if successful. See #yh_rc for possible errors
 **/
func YH_send_secure_msg(session *YH_session, cmd YH_cmd, data []byte, data_len int, response_cmd *YH_cmd, response []byte, response_len *int) YH_rc {


 	rc := C.yh_send_secure_msg(	(*C.yh_session)(unsafe.Pointer(session)), (C.yh_cmd)(cmd),
															(*C.uint8_t)(unsafe.Pointer(&data[0])), (C.size_t)(data_len),
															(*C.yh_cmd)(unsafe.Pointer(response_cmd)), (*C.uint8_t)(unsafe.Pointer(&response[0])),
															(*C.size_t)(unsafe.Pointer(response_len)))

  return YH_rc(rc)
}


/**
 * Create a session that uses an encryption key and a MAC key derived from a
 *password
 *
 * @param connector Connector to the device
 * @param authkey_id Object ID of the Authentication Key used to authenticate
 *the session
 * @param password Password used to derive the session encryption key and MAC
 *key
 * @param password_len Length of the password in bytes
 * @param recreate_session If true, the session will be recreated if expired.
 *This caches the password in memory
 * @param session The created session
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if the connector, the password or the session
 *are NULL. #YHR_GENERIC_ERROR if failed to derive the session encryption key
 *and/or the MAC key or if PRNG related errors occur. #YHR_MEMORY_ERROR if
 *failed to allocate memory for the session. See #yh_rc for other possible
 *errors
 *
 * @see <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Session.html">Session</a>
 **/
func YH_create_session_derived(connector *YH_connector, authkey_id uint16, password string, recreate_session bool) (*YH_session, YH_rc) {
	p := C.CString(password)
	var session *YH_session
	rc := C.yh_create_session_derived(	(*C.yh_connector)(unsafe.Pointer(connector)),
																			C.uint16_t(authkey_id),
																			(*C.uint8_t)(unsafe.Pointer(p)),
																			C.size_t(len(password)),
																			C.bool(recreate_session),
																			(**C.yh_session)(unsafe.Pointer(&session)))

	C.free(unsafe.Pointer(p))
	return session, YH_rc(rc)
}

/**
 * Create a session that uses the specified encryption key and MAC key to derive
 *session-specific keys
 *
 * @param connector Connector to the device
 * @param authkey_id Object ID of the Authentication Key used to authenticate
 *the session
 * @param key_enc Encryption key used to derive the session encryption key
 * @param key_enc_len Length of the encryption key.
 * @param key_mac MAC key used to derive the session MAC key
 * @param key_mac_len Length of the MAC key.
 * @param recreate_session If true, the session will be recreated if expired.
 *This caches the password in memory
 * @param session created session
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL or incorrect.
 *         See #yh_rc for other possible errors
 *
 * @see <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Session.html">Session</a>,
 * <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Object.html">Authentication
 *Key</a>
 **/
func YH_create_session(connector *YH_connector, authkey_id uint16, key_enc []byte, key_enc_len int, key_mac []byte, key_mac_len int, recreate_session bool) (*YH_session, YH_rc) {
	var session *YH_session
	rc := C.yh_create_session(	(*C.yh_connector)(unsafe.Pointer(connector)),
															(C.uint16_t)(authkey_id),
															(*C.uint8_t)(unsafe.Pointer(&key_enc[0])), (C.size_t)(key_enc_len),
															(*C.uint8_t)(unsafe.Pointer(&key_mac[0])), (C.size_t)(key_mac_len),
															(C.bool)(recreate_session),
															(**C.yh_session)(unsafe.Pointer(&session)))


	return session, YH_rc(rc)
}


/**
 * Begin creating an external session. The session's encryption key and MAC key
 *are not stored in the device.
 *
 * This function must be followed by yh_finish_create_session_ext() to set the
 *session keys.
 *
 * @param connector Connector to the device
 * @param authkey_id Object ID of the Authentication Key used to authenticate
 *the session
 * @param context pointer to where context data is saved
 * @param card_cryptogram Card cryptogram
 * @param card_cryptogram_len Length of card cryptogram
 * @param session created session
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL.
 *         #YHR_MEMORY_ERROR if failed to allocate memory for the session.
 *         See #yh_rc for other possible errors
 *
 * @see <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Session.html">Session</a>
 **/
 func YH_begin_create_session_ext(connector *YH_connector, authkey_id uint16, card_cryptogram []byte, card_cryptogram_len int) (*YH_session, *uint8, YH_rc) {
 	var session *YH_session
	var context *uint8
 	rc := C.yh_begin_create_session_ext(	(*C.yh_connector)(unsafe.Pointer(connector)),
 																			(C.uint16_t)(authkey_id),
																			(**C.uint8_t)(unsafe.Pointer(&context)),
																			(*C.uint8_t)(unsafe.Pointer(&card_cryptogram[0])), (C.size_t)(card_cryptogram_len),
 																			(**C.yh_session)(unsafe.Pointer(&session)))

 	return session, context, YH_rc(rc)
}

/**
 * Finish creating external session. The session's encryption key and MAC key
 *are not stored in the device.
 *
 * This function must be called after yh_begin_create_session_ext().
 *
 * @param connector Connector to the device
 * @param session The session created with yh_begin_create_session_ext()
 * @param key_senc Session encryption key used to encrypt the messages exchanged
 *with the device
 * @param key_senc_len Lenght of the encryption key. Must be #YH_KEY_LEN
 * @param key_smac Session MAC key used for creating the authentication tag for
 *each message
 * @param key_smac_len Length of the MAC key. Must be #YH_KEY_LEN
 * @param key_srmac Session return MAC key used for creating the authentication
 *tag for each response message
 * @param key_srmac_len Length of the return MAC key. Must be #YH_KEY_LEN
 * @param card_cryptogram Card cryptogram
 * @param card_cryptogram_len Length of card cryptogram
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL or any of the
 *key lengths are not #YH_KEY_LEN.
 *         See #yh_rc for other possible errors
 *
 * @see <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Session.html">Session</a>
 **/
 func YH_finish_create_session_ext(connector *YH_connector, session *YH_session,
																	 key_senc []byte, key_senc_len int,
																	 key_smac []byte, key_smac_len int,
																	 key_srmac []byte, key_srmac_len int,
																	 card_cryptogram []byte, card_cryptogram_len int) YH_rc {

 	rc := C.yh_finish_create_session_ext(	(*C.yh_connector)(unsafe.Pointer(connector)), (*C.yh_session)(unsafe.Pointer(session)),
																				(*C.uint8_t)(unsafe.Pointer(&key_senc[0])), (C.size_t)(key_senc_len),
																				(*C.uint8_t)(unsafe.Pointer(&key_smac[0])), (C.size_t)(key_smac_len),
																				(*C.uint8_t)(unsafe.Pointer(&key_srmac[0])), (C.size_t)(key_srmac_len),
																				(*C.uint8_t)(unsafe.Pointer(&card_cryptogram[0])), (C.size_t)(card_cryptogram_len))

 	return YH_rc(rc)
}


/**
 * Free data associated with the session
 *
 * @param session Pointer to the session to destroy
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if the session is NULL.
 *
 * @see <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Session.html">Session</a>
 **/
func YH_destroy_session(session *YH_session) YH_rc {
	return YH_rc(C.yh_destroy_session((**C.yh_session)(unsafe.Pointer(&session))))
}

/**
 * Authenticate session
 *
 * @param session Session to authenticate
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if the session is NULL.
 *         #YHR_SESSION_AUTHENTICATION_FAILED if the session fails to
 *authenticate. See #yh_rc for other possible errors
 *
 * @see <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Session.html">Session</a>
 **/
func YH_authenticate_session(session *YH_session) YH_rc {
	return YH_rc(C.yh_authenticate_session((*C.yh_session)(unsafe.Pointer(session))))
}

/**
 * Get device version, device serial number, supported algorithms and available
 *log entries.
 *
 * @param connector Connector to the device
 * @param major Device major version number
 * @param minor Device minor version number
 * @param patch Device build version number
 * @param serial Device serial number
 * @param log_total Total number of log entries
 * @param log_used Number of written log entries
 * @param algorithms List of supported algorithms
 * @param n_algorithms Number of supported algorithms
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if the connector is NULL.
 *         #YHR_BUFFER_TOO_SMALL if n_algorithms is smaller than the number of
 *actually supported algorithms. See #yh_rc for other possible errors.
 *
 * @see <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Algorithms.html">Algorithms</a>
 **/
func YH_util_get_device_info(connector *YH_connector, major,
                              minor, patch *uint8, serial *uint32,
                              log_total, log_used *uint8,
                              algorithms []YH_algorithm, n_algorithms *int) YH_rc {

	rc := C.yh_util_get_device_info((*C.yh_connector)(unsafe.Pointer(connector)),
																	(*C.uint8_t)(unsafe.Pointer(major)), (*C.uint8_t)(unsafe.Pointer(minor)),
																	(*C.uint8_t)(unsafe.Pointer(patch)), (*C.uint32_t)(unsafe.Pointer(serial)),
																	(*C.uint8_t)(unsafe.Pointer(log_total)), (*C.uint8_t)(unsafe.Pointer(log_used)),
																	(*C.yh_algorithm)(unsafe.Pointer(&algorithms[0])), (*C.size_t)(unsafe.Pointer(n_algorithms)))
	return YH_rc(rc)
}

/**
 * List objects accessible from the session
 *
 * @param session Authenticated session to use
 * @param id Object ID to filter by (0 to not filter by ID)
 * @param type Object type to filter by (0 to not filter by type). See
 *#yh_object_type
 * @param domains Domains to filter by (0 to not filter by domain)
 * @param capabilities Capabilities to filter by (0 to not filter by
 *capabilities). See #yh_capabilities
 * @param algorithm Algorithm to filter by (0 to not filter by algorithm)
 * @param label Label to filter by
 * @param objects Array of objects returned
 * @param n_objects Max number of objects (will be set to number found on
 *return)
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL.
 *         #YHR_BUFFER_TOO_SMALL if n_objects is smaller than the number of
 *objects found. See #yh_rc for other possible errors.
 *
 * @see <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Object.html">Objects</a>,
 * <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Domain.html">Domains</a>,
 * <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Capability.html">Capabilities</a>,
 * <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Algorithms.html">Algorithms</a>,
 * <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Label.html">Labels</a>
 **/
 func YH_util_list_objects(session *YH_session, id uint16, object_type YH_object_type, domains uint16, capabilities *YH_capabilities,
                               algorithm YH_algorithm, label string, objects []YH_object_descriptor, n_objects *int) YH_rc {
	l := C.CString(label)
 	rc := C.yh_util_list_objects((*C.yh_session)(unsafe.Pointer(session)), (C.uint16_t)(id), (C.yh_object_type)(object_type),
																	(C.uint16_t)(domains), (*C.yh_capabilities)(unsafe.Pointer(capabilities)), (C.yh_algorithm)(algorithm), l,
 																	(*C.yh_object_descriptor)(unsafe.Pointer(&objects[0])), (*C.size_t)(unsafe.Pointer(n_objects)))
	C.free(unsafe.Pointer(l))
	return YH_rc(rc)
}

/**
 * Get metadata of the object with the specified Object ID and Type
 *
 * @param session Authenticated session to use
 * @param id Object ID of the object to get
 * @param type Object type. See #yh_object_type
 * @param object Object information
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if the session is NULL.
 *         See #yh_rc for other possible errors.
 *
 * @see <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Object.html">Objects</a>
 **/
 func YH_util_get_object_info(session *YH_session, id uint16, object_type YH_object_type, objects *YH_object_descriptor) YH_rc {
 	rc := C.yh_util_get_object_info((*C.yh_session)(unsafe.Pointer(session)),
 																	(C.uint16_t)(id), (C.yh_object_type)(object_type),
 																	(*C.yh_object_descriptor)(unsafe.Pointer(objects)))
	return YH_rc(rc)
}

/**
 * Get the value of the public key with the specified Object ID
 *
 * @param session Authenticated session to use
 * @param id Object ID of the public key
 * @param data Value of the public key
 * @param data_len Length of the public key in bytes
 * @param algorithm Algorithm of the key
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL.
 *         #YHR_BUFFER_TOO_SMALL if the actual key length was bigger than
 *data_len. See #yh_rc for other possible errors
 **/
 func YH_util_get_public_key(session *YH_session, id uint16, data []byte, data_len int, algorithm *YH_algorithm) YH_rc {


 	rc := C.yh_util_get_public_key((*C.yh_session)(unsafe.Pointer(session)),
 																	(C.uint16_t)(id), (*C.uint8_t)(unsafe.Pointer(&data[0])), (*C.size_t)(unsafe.Pointer(&data_len)),
 																	(*C.yh_algorithm)(unsafe.Pointer(algorithm)))

  return YH_rc(rc)
}

/**
 * Close a session
 *
 * @param session Session to close
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if the session is NULL.
 *         See #yh_rc for other possible errors
 **/
func YH_util_close_session(session *YH_session) YH_rc {
	return YH_rc(C.yh_util_close_session((*C.yh_session)(unsafe.Pointer(session))))
}

/**
 * Sign data using RSA-PKCS#1v1.5
 *
 * <tt>in</tt> is either a raw hashed message (sha1, sha256, sha384 or sha512)
 *or that with correct digestinfo pre-pended
 *
 * @param session Authenticated session to use
 * @param key_id Object ID of the signing key
 * @param hashed true if data is only hashed
 * @param in data to sign
 * @param in_len length of data to sign
 * @param out signed data
 * @param out_len length of signed data
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS input parameters are NULL or if
 *<tt>in_len</tt> is not 20, 34, 48 or 64. See #yh_rc for other possible errors
 **/
 func YH_util_sign_pkcs1v1_5(session *YH_session, key_id uint16, hashed bool, in []byte, in_len int, out []byte, out_len *int) YH_rc {

 	rc := C.yh_util_sign_pkcs1v1_5(	(*C.yh_session)(unsafe.Pointer(session)), (C.uint16_t)(key_id), (C.bool)(hashed),
																	(*C.uint8_t)(unsafe.Pointer(&in[0])), (C.size_t)(in_len),
 																	(*C.uint8_t)(unsafe.Pointer(&out[0])), (*C.size_t)(unsafe.Pointer(out_len)))

 	return YH_rc(rc)
 }

 /**
  * Sign data using RSA-PSS
  *
  * <tt>in</tt> is a raw hashed message (sha1, sha256, sha384 or sha512)
  *
  * @param session Authenticated session to use
  * @param key_id Object ID of the signing key
  * @param in Data to sign
  * @param in_len Length of data to sign
  * @param out Signed data
  * @param out_len Length of signed data
  * @param salt_len Length of salt
  * @param mgf1Algo Algorithm for mgf1 (mask generation function for PSS)
  *
  * @return #YHR_SUCCESS if successful.
  *         #YHR_INVALID_PARAMETERS input parameters are NULL or if
  *<tt>in_len</tt> is not 20, 34, 48 or 64. See #yh_rc for other possible errors
  *
  * @see <a href="https://tools.ietf.org/html/rfc8017#section-9.1">PSS
  *specifications</a>
  **/
func YH_util_sign_pss(session *YH_session, key_id uint16, in []byte, in_len int, out []byte, out_len *int, salt_len int, algorithm YH_algorithm) YH_rc {

	rc := C.yh_util_sign_pss(	(*C.yh_session)(unsafe.Pointer(session)), (C.uint16_t)(key_id),
														(*C.uint8_t)(unsafe.Pointer(&in[0])), (C.size_t)(in_len),
														(*C.uint8_t)(unsafe.Pointer(&out[0])), (*C.size_t)(unsafe.Pointer(out_len)),
														(C.size_t)(salt_len), (C.yh_algorithm)(algorithm))


 	return YH_rc(rc)
}

/**
 * Sign data using ECDSA
 *
 * <tt>in</tt> is a raw hashed message, a truncated hash to the curve length or
 *a padded hash to the curve length
 *
 * @param session Authenticated session to use
 * @param key_id Object ID of the signing key
 * @param in Data to sign
 * @param in_len Length of data to sign
 * @param out Signed data
 * @param out_len Length of signed data
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS input parameters are NULL or if
 *<tt>in_len</tt> is not 20, 28, 34, 48, 64 or 66. See #yh_rc for other possible
 *errors
 **/
 func YH_util_sign_ecdsa(session *YH_session, key_id uint16, in []byte, in_len int, out []byte, out_len *int) YH_rc {

  	rc := C.yh_util_sign_ecdsa(	(*C.yh_session)(unsafe.Pointer(session)), (C.uint16_t)(key_id),
																(*C.uint8_t)(unsafe.Pointer(&in[0])), (C.size_t)(in_len),
																(*C.uint8_t)(unsafe.Pointer(&out[0])), (*C.size_t)(unsafe.Pointer(out_len)))


  	return YH_rc(rc)
 }

/**
* Sign data using EdDSA
*
* @param session Authenticated session to use
* @param key_id Object ID of the signing key
* @param in Data to sign
* @param in_len Length of data to sign
* @param out Signed data
* @param out_len Length of signed data
*
* @return #YHR_SUCCESS if successful.
*         #YHR_INVALID_PARAMETERS input parameters are NULL or if
*<tt>in_len</tt> is bigger than YH_MSG_BUF_SIZE-2. See #yh_rc for other
*possible errors
**/
func YH_util_sign_eddsa(session *YH_session, key_id uint16, in []byte, in_len int, out []byte, out_len *int) YH_rc {

 	rc := C.yh_util_sign_eddsa(	(*C.yh_session)(unsafe.Pointer(session)), (C.uint16_t)(key_id),
															(*C.uint8_t)(unsafe.Pointer(&in[0])), (C.size_t)(in_len),
															(*C.uint8_t)(unsafe.Pointer(&out[0])), (*C.size_t)(unsafe.Pointer(out_len)))


 	return YH_rc(rc)
}

/**
 * Sign data using HMAC
 *
 * @param session Authenticated session to use
 * @param key_id Object ID of the signing key
 * @param in Data to HMAC
 * @param in_len Length of data to hmac
 * @param out HMAC
 * @param out_len Length of HMAC
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS input parameters are NULL or if
 *<tt>in_len</tt> is bigger than YH_MSG_BUF_SIZE-2. See #yh_rc for other
 *possible errors
 **/
func YH_util_sign_hmac(session *YH_session, key_id uint16, in []byte, in_len int, out []byte, out_len *int) YH_rc {

	rc := C.yh_util_sign_hmac((*C.yh_session)(unsafe.Pointer(session)), (C.uint16_t)(key_id),
														(*C.uint8_t)(unsafe.Pointer(&in[0])), (C.size_t)(in_len),
														(*C.uint8_t)(unsafe.Pointer(&out[0])), (*C.size_t)(unsafe.Pointer(out_len)))


	return YH_rc(rc)
}

/**
 * Get a fixed number of pseudo-random bytes from the device
 *
 * @param session Authenticated session to use
 * @param len Length of pseudo-random data to get
 * @param out Pseudo-random data out
 * @param out_len Length of pseudo-random data
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS input parameters are NULL.
 *         See #yh_rc for other possible errors
 **/
func YH_util_get_pseudo_random(session *YH_session, rlen int, out []byte, out_len *int) YH_rc {
	rc := C.yh_util_get_pseudo_random((*C.yh_session)(unsafe.Pointer(session)),
																		C.size_t(rlen),
																		(*C.uint8_t)(unsafe.Pointer(&out[0])),
																	  (*C.size_t)(unsafe.Pointer(out_len)))
	return YH_rc(rc)
}

/**
 * Import an RSA key into the device
 *
 * @param session Authenticated session to use
 * @param key_id Object ID the key. 0 if Object ID should be generated by
 *the device
 * @param label Label of the key. Maximum length is #YH_OBJ_LABEL_LEN
 * @param domains Domains to which the key belongs specified as an unsigned int.
 *See #yh_string_to_domains()
 * @param capabilities Capabilities of the key. See
 *#yh_string_to_capabilities()
 * @param algorithm Algorithm of the key to import. Must be one of:
 *#YH_ALGO_RSA_2048, #YH_ALGO_RSA_3072 or #YH_ALGO_RSA_4096
 * @param p P component of the RSA key to import
 * @param q Q component of the RSA key to import
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS input parameters are NULL or the algorithm is
 *not one of #YH_ALGO_RSA_2048, #YH_ALGO_RSA_3072 or #YH_ALGO_RSA_4096. See
 *#yh_rc for other possible errors
 **/
func YH_util_import_rsa_key(	session *YH_session,
																key_id *uint16,
																label string,
																domains uint16,
																capabilities *YH_capabilities,
																algorithm YH_algorithm,
																p, q []byte) YH_rc {

	l := C.CString(label)
	rc := C.yh_util_import_rsa_key(	(*C.yh_session)(unsafe.Pointer(session)), (*C.uint16_t)(unsafe.Pointer(key_id)),
																		l, (C.uint16_t)(domains), (*C.yh_capabilities)(unsafe.Pointer(capabilities)),
																		(C.yh_algorithm)(algorithm), (*C.uint8_t)(unsafe.Pointer(&p[0])), (*C.uint8_t)(unsafe.Pointer(&q[0])))
	C.free(unsafe.Pointer(l))
	return YH_rc(rc)
}

/**
 * Import an Elliptic Curve key into the device
 *
 * @param session Authenticated session to use
 * @param key_id Object ID of the key. 0 if the Object ID should be generated
 *by the device
 * @param label Label of the key. Maximum length is #YH_OBJ_LABEL_LEN
 * @param domains Domains to which the key belongs specified as
 *an unsigned int. See #yh_string_to_domains()
 * @param capabilities Capabilities of the key. See
 *#yh_string_to_capabilities()
 * @param algorithm Algorithm of the key to import. Must be one of:
 *#YH_ALGO_EC_P224, #YH_ALGO_EC_P256, #YH_ALGO_EC_K256, #YH_ALGO_EC_BP256,
 *#YH_ALGO_EC_P384, #YH_ALGO_EC_BP384, #YH_ALGO_EC_BP512 or #YH_ALGO_EC_P521
 * @param s the EC key to import
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS input parameters are NULL or the algorithm is
 *not one of #YH_ALGO_EC_P224, #YH_ALGO_EC_P256, #YH_ALGO_EC_K256,
 *#YH_ALGO_EC_BP256, #YH_ALGO_EC_P384, #YH_ALGO_EC_BP384, #YH_ALGO_EC_BP512 or
 *#YH_ALGO_EC_P521.
 *         See #yh_rc for other possible errors
 **/
func YH_util_import_ec_key(	session *YH_session,
																key_id *uint16,
																label string,
																domains uint16,
																capabilities *YH_capabilities,
																algorithm YH_algorithm,
																s []byte) YH_rc {

	l := C.CString(label)
	rc := C.yh_util_import_ec_key(	(*C.yh_session)(unsafe.Pointer(session)), (*C.uint16_t)(unsafe.Pointer(key_id)),
																		l, (C.uint16_t)(domains), (*C.yh_capabilities)(unsafe.Pointer(capabilities)),
																		(C.yh_algorithm)(algorithm), (*C.uint8_t)(unsafe.Pointer(&s[0])))
	C.free(unsafe.Pointer(l))
	return YH_rc(rc)
}

/**
 * Import an ED key into the device
 *
 * @param session Authenticated session to use
 * @param key_id Object ID of the key will have. 0 if the Object ID should be
 *generated by the device
 * @param label Label of the key. Maximum length is #YH_OBJ_LABEL_LEN
 * @param domains Domains to which the key belongs.  See #yh_string_to_domains()
 * @param capabilities Capabilities of the key. See
 *#yh_string_to_capabilities()
 * @param algorithm Algorithm of the key to import. Must be #YH_ALGO_EC_ED25519
 * @param k the ED key to import
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS input parameters are NULL or the algorithm is
 *not #YH_ALGO_EC_ED25519. See #yh_rc for other possible errors
 **/
func YH_util_import_ed_key(	session *YH_session,
																key_id *uint16,
																label string,
																domains uint16,
																capabilities *YH_capabilities,
																algorithm YH_algorithm,
																k []byte) YH_rc {

	l := C.CString(label)
	rc := C.yh_util_import_ed_key(	(*C.yh_session)(unsafe.Pointer(session)), (*C.uint16_t)(unsafe.Pointer(key_id)),
																		l, (C.uint16_t)(domains), (*C.yh_capabilities)(unsafe.Pointer(capabilities)),
																		(C.yh_algorithm)(algorithm), (*C.uint8_t)(unsafe.Pointer(&k[0])))
	C.free(unsafe.Pointer(l))
	return YH_rc(rc)
}

/**
 * Import an HMAC key into the device
 *
 * @param session Authenticated session to use
 * @param key_id Object ID of the key. 0 if the Object ID should be
 *generated by the device
 * @param label Label of the key. Maxium length is #YH_OBJ_LABEL_LEN
 * @param domains Domains to which the key belongs. See #yh_string_to_domains()
 * @param capabilities Capabilities of the key. See
 *#yh_string_to_capabilities()
 * @param algorithm Algorithm of the key to import. Must be one of:
 *#YH_ALGO_HMAC_SHA1, #YH_ALGO_HMAC_SHA256, #YH_ALGO_HMAC_SHA384
 *or #YH_ALGO_HMAC_SHA512
 * @param key The HMAC key to import
 * @param key_len Length of the HMAC key to import
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS input parameters are NULL.
 *         See #yh_rc for other possible errors
 **/
func YH_util_import_hmac_key(	session *YH_session,
																key_id *uint16,
																label string,
																domains uint16,
																capabilities *YH_capabilities,
																algorithm YH_algorithm,
																key []byte) YH_rc {

	l := C.CString(label)
	rc := C.yh_util_import_hmac_key(	(*C.yh_session)(unsafe.Pointer(session)), (*C.uint16_t)(unsafe.Pointer(key_id)),
																		l, (C.uint16_t)(domains), (*C.yh_capabilities)(unsafe.Pointer(capabilities)),
																		(C.yh_algorithm)(algorithm), (*C.uint8_t)(unsafe.Pointer(&key[0])), (C.size_t)(len(key)))
	C.free(unsafe.Pointer(l))
	return YH_rc(rc)
}

/**
 * Generate an RSA key in the device
 *
 * @param session Authenticated session to use
 * @param key_id Object ID of the key. 0 if the Object ID should be
 *generated by the device
 * @param label Label of the key. Maximum length is #YH_OBJ_LABEL_LEN
 * @param domains Domains to which the key belongs. See #yh_string_to_domains()
 * @param capabilities Capabilities of the key. See
 *#yh_string_to_capabilities()
 * @param algorithm Algorithm to use to generate the RSA key. Supported
 *algorithms: #YH_ALGO_RSA_2048, #YH_ALGO_RSA_3072 and #YH_ALGO_RSA_4096
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS input parameters are NULL or the algorithm is
 *not one of #YH_ALGO_RSA_2048, #YH_ALGO_RSA_3072 or #YH_ALGO_RSA_4096.
 *         See #yh_rc for other possible errors
 **/
func YH_util_generate_rsa_key(	session *YH_session, key_id *uint16, label string, domains uint16,
																capabilities *YH_capabilities, algorithm YH_algorithm) YH_rc {
	l := C.CString(label)
	rc := C.yh_util_generate_rsa_key((*C.yh_session)(unsafe.Pointer(session)),
																				(*C.uint16_t)(unsafe.Pointer(key_id)),
																				l, (C.uint16_t)(domains),
																				(*C.yh_capabilities)(unsafe.Pointer(capabilities)),
																				(C.yh_algorithm)(algorithm))
	C.free(unsafe.Pointer(l))
	return YH_rc(rc)
}


/**
 * Generate an Elliptic Curve key in the device
 *
 * @param session Authenticated session to use
 * @param key_id Object ID of the key. 0 if the Object ID should be generated
 *by the device
 * @param label Label of the key. Maximum length is #YH_OBJ_LABEL_LEN
 * @param domains Domains to which the key belongs. See #yh_string_to_domains()
 * @param capabilities Capabilities of the key. See
 *#yh_string_to_capabilities()
 * @param algorithm Algorithm to use to generate the EC key. Supported
 *algorithm: #YH_ALGO_EC_P224, #YH_ALGO_EC_P256, #YH_ALGO_EC_K256,
 *#YH_ALGO_EC_BP256, #YH_ALGO_EC_P384, #YH_ALGO_EC_BP384, #YH_ALGO_EC_BP512 and
 *#YH_ALGO_EC_P521.
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS input parameters are NULL or the algorithm is
 *not one of #YH_ALGO_EC_P224, #YH_ALGO_EC_P256, #YH_ALGO_EC_K256,
 *#YH_ALGO_EC_BP256, #YH_ALGO_EC_P384, #YH_ALGO_EC_BP384, #YH_ALGO_EC_BP512 or
 *#YH_ALGO_EC_P521.
 *         See #yh_rc for other possible errors
 **/
func YH_util_generate_ec_key(	session *YH_session, key_id *uint16, label string, domains uint16,
																capabilities *YH_capabilities, algorithm YH_algorithm) YH_rc {
	l := C.CString(label)
	rc := C.yh_util_generate_ec_key((*C.yh_session)(unsafe.Pointer(session)),
																				(*C.uint16_t)(unsafe.Pointer(key_id)),
																				l, (C.uint16_t)(domains),
																				(*C.yh_capabilities)(unsafe.Pointer(capabilities)),
																				(C.yh_algorithm)(algorithm))
	C.free(unsafe.Pointer(l))
	return YH_rc(rc)
}

/**
 * Generate an ED key in the device
 *
 * @param session Authenticated session to use
 * @param key_id Object ID of the key. 0 if the Object ID should be generated
 *by the device
 * @param label Label for the key. Maximum length #YH_OBJ_LABEL_LEN
 * @param domains Domains to which the key belongs. See #yh_string_to_domains()
 * @param capabilities Capabilities of the ED key. See
 *#yh_string_to_capabilities()
 * @param algorithm Algorithm to use to generate the ED key. Supported
 *algorithm: #YH_ALGO_EC_ED25519
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS input parameters are NULL or the algorithm is
 *not #YH_ALGO_EC_ED25519.
 *         See #yh_rc for other possible errors
 **/
func YH_util_generate_ed_key(	session *YH_session, key_id *uint16, label string, domains uint16,
																capabilities *YH_capabilities, algorithm YH_algorithm) YH_rc {
	l := C.CString(label)
	rc := C.yh_util_generate_ed_key((*C.yh_session)(unsafe.Pointer(session)),
																				(*C.uint16_t)(unsafe.Pointer(key_id)),
																				l, (C.uint16_t)(domains),
																				(*C.yh_capabilities)(unsafe.Pointer(capabilities)),
																				(C.yh_algorithm)(algorithm))
	C.free(unsafe.Pointer(l))
	return YH_rc(rc)
}

/**
 * Verify a generated HMAC
 *
 * @param session Authenticated session to use
 * @param key_id Object ID of the HMAC key
 * @param signature HMAC signature (20, 32, 48 or 64 bytes)
 * @param signature_len length of HMAC signature
 * @param data data to verify
 * @param data_len length of data to verify
 * @param verified true if verification succeeded
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS input parameters are NULL or if
 *<tt>signature_len</tt> + <tt>data_len</tt> is too long.
 *         See #yh_rc for other possible errors
 *
 **/
func YH_util_verify_hmac(	session *YH_session, key_id uint16, signature, data []byte, verified *bool) YH_rc {

	rc := C.yh_util_verify_hmac((*C.yh_session)(unsafe.Pointer(session)),
															(C.uint16_t)(key_id),
															(*C.uint8_t)(unsafe.Pointer(&signature[0])), (C.size_t)(len(signature)),
															(*C.uint8_t)(unsafe.Pointer(&data[0])), (C.size_t)(len(data)),
															(*C.bool)(unsafe.Pointer(verified)))

	return YH_rc(rc)
}

/**
 * Generate an HMAC key in the device
 *
 * @param session Authenticated session to use
 * @param key_id Object ID of the key. 0 if the Object ID should be
 *generated by the device
 * @param label Label of the key. Maximum length #YH_OBJ_LABEL_LEN
 * @param domains Domains to which the key belongs. See #yh_string_to_domains()
 * @param capabilities Capabilities of the key. See
 *#yh_string_to_capabilities()
 * @param algorithm Algorithm to use to generate the HMAC key. Supported
 *algorithims: #YH_ALGO_HMAC_SHA1, #YH_ALGO_HMAC_SHA256, #YH_ALGO_HMAC_SHA384
 *and #YH_ALGO_HMAC_SHA512
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS input parameters are NULL.
 *         See #yh_rc for other possible errors
 *
 **/
func YH_util_generate_hmac_key(	session *YH_session, key_id *uint16, label string, domains uint16,
																capabilities *YH_capabilities, algorithm YH_algorithm) YH_rc {
	l := C.CString(label)
	rc := C.yh_util_generate_hmac_key((*C.yh_session)(unsafe.Pointer(session)),
																				(*C.uint16_t)(unsafe.Pointer(key_id)),
																				l, (C.uint16_t)(domains),
																				(*C.yh_capabilities)(unsafe.Pointer(capabilities)),
																				(C.yh_algorithm)(algorithm))
	C.free(unsafe.Pointer(l))
	return YH_rc(rc)
}

/**
 * Decrypt data that was encrypted using RSA-PKCS#1v1.5
 *
 * @param session Authenticated session to use
 * @param key_id Object ID of the RSA key to use for decryption
 * @param in Encrypted data
 * @param in_len Length of encrypted data
 * @param out Decrypted data
 * @param out_len Length of decrypted data
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS input parameters are NULL or if
 *<tt>in_len</tt> is bigger than #YH_MSG_BUF_SIZE-2.
 *         See #yh_rc for other possible errors
 *
 **/
func YH_util_decrypt_pkcs1v1_5(	session *YH_session, key_id uint16, in []byte, in_len int, out []byte, out_len *int) YH_rc {
	rc := C.yh_util_decrypt_pkcs1v1_5(	(*C.yh_session)(unsafe.Pointer(session)), (C.uint16_t)(key_id),
																			(*C.uint8_t)(unsafe.Pointer(&in[0])), (C.size_t)(in_len),
																			(*C.uint8_t)(unsafe.Pointer(&out[0])), (*C.size_t)(unsafe.Pointer(out_len)))

	return YH_rc(rc)
}



/**
 * Decrypt data using RSA-OAEP
 *
 * @param session Authenticated session to use
 * @param key_id Object ID of the RSA key to use for decryption
 * @param in Encrypted data
 * @param in_len Length of encrypted data. Must be 256, 384 or 512
 * @param out Decrypted data
 * @param out_len Length of decrypted data
 * @param label Hash of OAEP label. Hash function must be SHA-1, SHA-256,
 *SHA-384 or SHA-512
 * @param label_len Length of hash of OAEP label. Must be 20, 32, 48 or 64
 * @param mgf1Algo MGF1 algorithm
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS input parameters are NULL.
 *         #YHR_WRONG_LENGTH if <tt>in_len</tt> or <tt>label_len</tt> are not
 *what expected.
 *         See #yh_rc for other possible errors
 *
 **/
func YH_util_decrypt_oaep(	session *YH_session, key_id uint16,
														in []byte, in_len int,
														out []byte, out_len *int,
														label []byte, label_len int,
														mgf1Algo YH_algorithm) YH_rc {
	rc := C.yh_util_decrypt_oaep(	(*C.yh_session)(unsafe.Pointer(session)), (C.uint16_t)(key_id),
															(*C.uint8_t)(unsafe.Pointer(&in[0])), (C.size_t)(in_len),
															(*C.uint8_t)(unsafe.Pointer(&out[0])), (*C.size_t)(unsafe.Pointer(out_len)),
															(*C.uint8_t)(unsafe.Pointer(&label[0])), (C.size_t)(label_len),
															(C.yh_algorithm)(mgf1Algo))

	return YH_rc(rc)
}

/**
 * Derive an ECDH key from a private EC key on the device and a provided public
 *EC key
 *
 * @param session Authenticated session to use
 * @param key_id Object ID of the EC private key to use for ECDH derivation
 * @param in Public key of another EC key-pair
 * @param in_len Length of public key
 * @param out Shared secret ECDH key
 * @param out_len Length of the shared ECDH key
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS input parameters are NULL or if
 *<tt>in_len</tt> is bigger than #YH_MSG_BUF_SIZE-2.
 *         See #yh_rc for other possible errors
 *
 **/
func YH_util_derive_ecdh(	session *YH_session, key_id uint16, in []byte, in_len int, out []byte, out_len *int) YH_rc {
	rc := C.yh_util_derive_ecdh(	(*C.yh_session)(unsafe.Pointer(session)), (C.uint16_t)(key_id),
																(*C.uint8_t)(unsafe.Pointer(&in[0])), (C.size_t)(in_len),
																(*C.uint8_t)(unsafe.Pointer(&out[0])), (*C.size_t)(unsafe.Pointer(out_len)))

	return YH_rc(rc)
}

/**
 * Delete an object in the device
 *
 * @param session Authenticated session to use
 * @param id Object ID of the object to delete
 * @param type Type of object to delete. See #yh_object_type
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if session is NULL.
 *         See #yh_rc for other possible errors
 *
 **/
func YH_util_delete_object(session *YH_session, id uint16, object_type YH_object_type) YH_rc {

	rc := C.yh_util_delete_object( 	(*C.yh_session)(unsafe.Pointer(session)),
																	(C.uint16_t)(id),
																	(C.yh_object_type)(object_type))

	return YH_rc(rc)
}

/**
 * Export an object under wrap from the device
 *
 * @param session Authenticated session to use
 * @param wrapping_key_id Object ID of the Wrap Key to use to wrap the object
 * @param target_type Type of the object to be exported. See #yh_object_type
 * @param target_id Object ID of the object to be exported
 * @param out Wrapped data
 * @param out_len Length of wrapped data
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL.
 *         See #yh_rc for other possible errors
 **/
func YH_util_export_wrapped(	session *YH_session,
															wrapping_key_id uint16,
															target_type YH_object_type,
															target_id uint16,
															out []byte, out_len *int) YH_rc {

	rc := C.yh_util_export_wrapped(	(*C.yh_session)(unsafe.Pointer(session)),
																	(C.uint16_t)(wrapping_key_id),
																	(C.yh_object_type)(target_type),
																	(C.uint16_t)(target_id),
																	(*C.uint8_t)(unsafe.Pointer(&out[0])), (*C.size_t)(unsafe.Pointer(out_len)))

	return YH_rc(rc)
}

/**
 * Import a wrapped object into the device. The object should have been
 *previously exported by #yh_util_export_wrapped()
 *
 * @param session Authenticated session to use
 * @param wrapping_key_id Object ID of the Wrap Key to use to unwrap the object
 * @param in Wrapped data
 * @param in_len Length of wrapped data
 * @param target_type Type of the imported object
 * @param target_id Object ID of the imported object
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL.
 *         See #yh_rc for other possible errors
 **/
 /*yh_rc yh_util_import_wrapped(yh_session *session, uint16_t wrapping_key_id,
 													 const uint8_t *in, size_t in_len,
 													 yh_object_type *target_type, uint16_t *target_id);*/
func YH_util_import_wrapped(	session *YH_session, wrapping_key_id uint16,
															in []byte, in_len int,
															target_type *YH_object_type, target_id *uint16) YH_rc {


	rc := C.yh_util_import_wrapped(	(*C.yh_session)(unsafe.Pointer(session)), (C.uint16_t)(wrapping_key_id),
																	(*C.uint8_t)(unsafe.Pointer(&in[0])), (C.size_t)(in_len),
																	(*C.yh_object_type)(unsafe.Pointer(target_type)), (*C.uint16_t)(unsafe.Pointer(target_id)))

	return YH_rc(rc)
}

/**
 * Import a Wrap Key into the device
 *
 * @param session Authenticated session to use
 * @param key_id Object ID the Wrap Key. 0 if the Object ID should be generated
 *by the device
 * @param label Label of the Wrap Key. Maximum length is #YH_OBJ_LABEL_LEN
 * @param domains Domains where the Wrap Key will be operating within. See
 *#yh_string_to_domains()
 * @param capabilities Capabilities of the Wrap Key. See
 *#yh_string_to_capabilities()
 * @param algorithm Algorithm of the Wrap Key. Supported algorithms:
 *#YH_ALGO_AES128_CCM_WRAP, #YH_ALGO_AES192_CCM_WRAP and
 *#YH_ALGO_AES256_CCM_WRAP
 * @param delegated_capabilities Delegated capabilities of the Wrap Key. See
 *#yh_string_to_capabilities()
 * @param in the Wrap Key to import
 * @param in_len Length of the Wrap Key to import
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL, <tt>in_len</tt>
 *is not what expected based on the algorithm and if the algorithms is not one
 *of #YH_ALGO_AES128_CCM_WRAP, #YH_ALGO_AES192_CCM_WRAP or
 *#YH_ALGO_AES256_CCM_WRAP.
 *         See #yh_rc for other possible errors
 **/

func YH_util_import_wrap_key(	session *YH_session, key_id *uint16, label string, domains uint16,
															capabilities *YH_capabilities, algorithm YH_algorithm, del_capabilites *YH_capabilities,
															in []byte, in_len int) YH_rc {

 	l := C.CString(label)
 	rc := C.yh_util_import_wrap_key(	(*C.yh_session)(unsafe.Pointer(session)), (*C.uint16_t)(unsafe.Pointer(key_id)), l, (C.uint16_t)(domains),
																		(*C.yh_capabilities)(unsafe.Pointer(capabilities)), (C.yh_algorithm)(algorithm), (*C.yh_capabilities)(unsafe.Pointer(del_capabilites)),
																		(*C.uint8_t)(unsafe.Pointer(&in[0])), (C.size_t)(in_len))

 	C.free(unsafe.Pointer(l))
 	return YH_rc(rc)
}

/**
 * Generate a Wrap Key that can be used for export, import, wrap data and unwrap
 *data in the device.
 *
 * @param session Authenticated session to use
 * @param key_id Object ID of the Wrap Key. 0 if the Object ID should be
 *generated by the device
 * @param label Label of the Wrap Key. Maximum length #YH_OBJ_LABEL_LEN
 * @param domains Domains where the Wrap Key will be operating within. See
 *#yh_string_to_domains()
 * @param capabilities Capabilities of the Wrap Key. See
 *#yh_string_to_capabilities()
 * @param algorithm Algorithm used to generate the Wrap Key
 * @param delegated_capabilities Delegated capabilitites of the Wrap Key. See
 *#yh_string_to_capabilities()
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL.
 *         See #yh_rc for other possible errors
 *
 * @see yh_object_type
 **/
func YH_util_generate_wrap_key(	session *YH_session, key_id *uint16, label string, domains uint16,
																capabilities *YH_capabilities, algorithm YH_algorithm, del_capabilites *YH_capabilities) YH_rc {
	l := C.CString(label)
	rc := C.yh_util_generate_wrap_key((*C.yh_session)(unsafe.Pointer(session)), (*C.uint16_t)(unsafe.Pointer(key_id)), l, (C.uint16_t)(domains),
																				(*C.yh_capabilities)(unsafe.Pointer(capabilities)), (C.yh_algorithm)(algorithm), (*C.yh_capabilities)(unsafe.Pointer(del_capabilites)))
	C.free(unsafe.Pointer(l))
	return YH_rc(rc)
}

/**
 * Get audit logs from the device.
 *
 * When audit enforce is set, if the log buffer is full, no new operations
 *(other than authentication operations) can be performed unless the log entries
 *are read by this command and then the log index is set by calling
 *#yh_util_set_log_index().
 *
 * @param session Authenticated session to use
 * @param unlogged_boot Number of unlogged boot events. Used if the log buffer
 *is full and audit enforce is set
 * @param unlogged_auth Number of unlogged authentication events. Used if the
 *log buffer is full and audit enforce is set
 * @param out Log entries on the device
 * @param n_items Number of log entries
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL.
 *         #YHR_BUFFER_TOO_SMALL if <tt>n_items</tt> is smaller than the actual
 *number of retrieved log entries.
 *         See #yh_rc for other possible errors
 **/
func YH_util_get_log_entries(	session *YH_session, unlogged_boot, unlogged_auth *uint16,
															out []YH_log_entry, n_items *int) YH_rc {

	rc := C.yh_util_get_log_entries((*C.yh_session)(unsafe.Pointer(session)),
																	(*C.uint16_t)(unsafe.Pointer(unlogged_boot)), (*C.uint16_t)(unsafe.Pointer(unlogged_auth)),
																	(*C.yh_log_entry)(unsafe.Pointer(&out[0])), (*C.size_t)(unsafe.Pointer(n_items)))

	return YH_rc(rc)
}


/**
 * Set the index of the last extracted log entry.
 *
 * This function should be called after #yh_util_get_log_entries() to inform the
 *device what the last extracted log entry is so new logs can be written. This
 *is used when forced auditing is enabled.
 *
 * @param session Authenticated session to use
 * @param index index to set. Should be the same index as the last entry
 *extracted using #yh_util_get_log_entries()
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if the session is NULL.
 *         See #yh_rc for other possible errors
 **/
func YH_util_set_log_index(	session *YH_session, index uint16) YH_rc {

	rc := C.yh_util_set_log_index((*C.yh_session)(unsafe.Pointer(session)),
																	(C.uint16_t)(index))

	return YH_rc(rc)
}

/**
 * Get an #YH_OPAQUE object (like an X.509 certificate) from the device
 *
 * @param session Authenticated session to use
 * @param object_id Object ID of the Opaque object
 * @param out the retrieved Opaque object
 * @param out_len Length of the retrieved Opaque object
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL.
 *         See #yh_rc for other possible errors
 **/
 /*yh_rc yh_util_get_opaque(yh_session *session, uint16_t object_id, uint8_t *out,
                          size_t *out_len);*/
func YH_util_get_opaque(	session *YH_session, object_id uint16,
													out []byte, out_len *int) YH_rc {


	rc := C.yh_util_get_opaque(	(*C.yh_session)(unsafe.Pointer(session)), (C.uint16_t)(object_id),
															(*C.uint8_t)(unsafe.Pointer(&out[0])), (*C.size_t)(unsafe.Pointer(out_len)))

	return YH_rc(rc)
}

/**
 * Import an #YH_OPAQUE object into the device
 *
 * @param session Authenticated session to use
 * @param object_id Object ID of the Opaque object. 0 if the Object ID should be
 *generated by the device
 * @param label Label of the Opaque object. Maximum length is #YH_OBJ_LABEL_LEN
 * @param domains Domains the Opaque object will be operating within. See
 *#yh_string_to_domains()
 * @param capabilities Capabilities of the Opaque object. See
 *#yh_string_to_capabilities()
 * @param algorithm Algorithm of the Opaque object
 * @param in the Opaque object to import
 * @param in_len Length of the Opaque object to import
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL or
 *<tt>in_len</tt> is too big.
 *         See #yh_rc for other possible errors
 **/

 /*yh_rc yh_util_import_opaque(yh_session *session, uint16_t *object_id,
                             const char *label, uint16_t domains,
                             const yh_capabilities *capabilities,
                             yh_algorithm algorithm, const uint8_t *in,
                             size_t in_len);*/
func YH_util_import_opaque(	session *YH_session, object_id *uint16, label string, domains uint16,
														capabilities *YH_capabilities, algorithm YH_algorithm,
														in []byte, in_len int) YH_rc {

	l := C.CString(label)
	rc := C.yh_util_import_opaque(	(*C.yh_session)(unsafe.Pointer(session)), (*C.uint16_t)(unsafe.Pointer(object_id)),
																	l, (C.uint16_t)(domains), (*C.yh_capabilities)(unsafe.Pointer(capabilities)), (C.yh_algorithm)(algorithm),
																	(*C.uint8_t)(unsafe.Pointer(&in[0])), (C.size_t)(in_len))

	return YH_rc(rc)
}

/**
 * Sign an SSH Certificate request. The function produces a signature that can
 *then be used to produce the SSH Certificate
 *
 * @param session Authenticated session to use
 * @param key_id Object ID of the key used to sign the request
 * @param template_id Object ID of the template to use as a certificate template
 * @param sig_algo Signature algorithm to use to sign the certificate request
 * @param in Certificate request
 * @param in_len Length of the certificate request
 * @param out Signature
 * @param out_len Length of the signature
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL or
 *<tt>in_len</tt> is too big.
 *         See #yh_rc for other possible errors
 **/
func YH_util_sign_ssh_certificate(	session *YH_session, key_id, template_id uint16, sig_algo YH_algorithm,
																		in []byte, in_len int, out []byte, out_len *int) YH_rc {

	rc := C.yh_util_sign_ssh_certificate(	(*C.yh_session)(unsafe.Pointer(session)), (C.uint16_t)(key_id), (C.uint16_t)(template_id), (C.yh_algorithm)(sig_algo),
																				(*C.uint8_t)(unsafe.Pointer(&in[0])), (C.size_t)(in_len),
																				(*C.uint8_t)(unsafe.Pointer(&out[0])), (*C.size_t)(unsafe.Pointer(out_len)))

	return YH_rc(rc)
}

/**
 * Import an #YH_AUTHENTICATION_KEY into the device
 *
 * @param session Authenticated session to use
 * @param key_id Object ID of the imported key. 0 if the Object ID should be
 *generated by the device
 * @param label Label of the key. Maximum length is #YH_OBJ_LABEL_LEN
 * @param domains Domains to which the key belongs. See #yh_string_to_domains()
 * @param capabilities Capabilities of the key. See #yh_string_to_capabilities()
 * @param delegated_capabilities Delegated capabilities of the key. See
 *#yh_string_to_capabilities()
 * @param key_enc Long lived encryption key of the Authentication Key to import
 * @param key_enc_len Length of the encryption key. Must be #YH_KEY_LEN
 * @param key_mac Long lived MAC key of the Authentication Key to import
 * @param key_mac_len Length of the MAC key. Must be #YH_KEY_LEN
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL or if
 *<tt>key_enc_len</tt> or <tt>key_mac_len</tt> are not the expected values.
 *         See #yh_rc for other possible errors
 *
 * @see <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Object.html">Authentication
 *Key</a>
 **/
 func YH_util_import_authentication_key(	session *YH_session, key_id *uint16, label string,
 																					domains uint16, capabilities, del_capabilites *YH_capabilities,
																					key_enc []byte, key_enc_len int,
																					key_mac []byte, key_mac_len int) YH_rc {
 	l := C.CString(label)

 	rc := C.yh_util_import_authentication_key(	(*C.yh_session)(unsafe.Pointer(session)), (*C.uint16_t)(unsafe.Pointer(key_id)),
																							l, (C.uint16_t)(domains),
																							(*C.yh_capabilities)(unsafe.Pointer(capabilities)), (*C.yh_capabilities)(unsafe.Pointer(del_capabilites)),
																							(*C.uint8_t)(unsafe.Pointer(&key_enc[0])), (C.size_t)(key_enc_len),
																							(*C.uint8_t)(unsafe.Pointer(&key_mac[0])), (C.size_t)(key_mac_len))
 	C.free(unsafe.Pointer(l))

 	return YH_rc(rc)
 }




/**
 * Import an #YH_AUTHENTICATION_KEY with long lived keys derived from a password
 *
 * @param session Authenticated session to use
 * @param key_id Object ID of the key. 0 if the Object ID should be generated by
 *the device
 * @param label Label of the key. Maximum length is #YH_OBJ_LABEL_LEN
 * @param domains Domains to which the key belongs. See #yh_string_to_domains()
 * @param capabilities Capabilities of the key. See #yh_string_to_capabilities()
 * @param delegated_capabilities Delegated capabilities of the key. See
 *#yh_string_to_capabilities()
 * @param password Password used to derive the long lived encryption key and MAC
 *key of the Athentication Key
 * @param password_len Length of password
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL.
 *         See #yh_rc for other possible errors
 * @see <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Object.html">Authentication
 *Key</a>
 **/
func YH_util_import_authentication_key_derived(	session *YH_session, key_id *uint16, label string, domains uint16,
																								capabilities, del_capabilites *YH_capabilities, password string) YH_rc {
	l := C.CString(label)
	p := C.CString(password)
	rc := C.yh_util_import_authentication_key_derived(	(*C.yh_session)(unsafe.Pointer(session)), (*C.uint16_t)(unsafe.Pointer(key_id)),
																											l, (C.uint16_t)(domains),
																											(*C.yh_capabilities)(unsafe.Pointer(capabilities)), (*C.yh_capabilities)(unsafe.Pointer(del_capabilites)),
																											(*C.uint8_t)(unsafe.Pointer(p)), (C.size_t)(len(password)))
	C.free(unsafe.Pointer(l))
	C.free(unsafe.Pointer(p))
	return YH_rc(rc)
}

/**
 * Replace the long lived encryption key and MAC key associated with an
 *#YH_AUTHENTICATION_KEY in the device
 *
 * @param session Authenticated session to use
 * @param key_id Object ID of the key to replace
 * @param key_enc New long lived encryption key
 * @param key_enc_len Length of the new encryption key. Must be #YH_KEY_LEN
 * @param key_mac New long lived MAC key
 * @param key_mac_len Length of the new MAC key. Must be #YH_KEY_LEN
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL or if
 *<tt>key_enc_len</tt> or <tt>key_mac_len</tt> are not the expected values.
 *         See #yh_rc for other possible errors
 *
 * @see <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Object.html">Authentication
 *Key</a>
 **/
func YH_util_change_authentication_key(	session *YH_session, key_id *uint16,
																				key_enc []byte, key_enc_len int,
																				key_mac []byte, key_mac_len int) YH_rc {


	rc := C.yh_util_change_authentication_key(	(*C.yh_session)(unsafe.Pointer(session)), (*C.uint16_t)(unsafe.Pointer(key_id)),
																						(*C.uint8_t)(unsafe.Pointer(&key_enc[0])), (C.size_t)(key_enc_len),
																						(*C.uint8_t)(unsafe.Pointer(&key_mac[0])), (C.size_t)(key_mac_len))


	return YH_rc(rc)
}

/**
 * Replace the long lived encryption key and MAC key associated with an
 *#YH_AUTHENTICATION_KEY in the device with keys derived from a password
 *
 * @param session Authenticated session to use
 * @param key_id Object ID of the key to replace
 * @param password Password to derive the new encryption key and MAC key
 * @param password_len Length of password
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL.
 *         See #yh_rc for other possible errors
 *
 * @see <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Object.html">Authentication
 *Key</a>
 *
 **/

func YH_util_change_authentication_key_derived(	session *YH_session, key_id *uint16, password string) YH_rc {
	p := C.CString(password)
	rc := C.yh_util_change_authentication_key_derived(	(*C.yh_session)(unsafe.Pointer(session)), (*C.uint16_t)(unsafe.Pointer(key_id)),
																											(*C.uint8_t)(unsafe.Pointer(p)), (C.size_t)(len(password)))
	C.free(unsafe.Pointer(p))
	return YH_rc(rc)
}

/**
 * Get a #YH_TEMPLATE object from the device
 *
 * @param session Authenticated session to use
 * @param object_id Object ID of the Template to get
 * @param out The retrieved Template
 * @param out_len Length of the retrieved Template
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL.
 *         See #yh_rc for other possible errors
 **/
func YH_util_get_template(	session *YH_session, object_id uint16, out []byte, out_len *int) YH_rc {

	rc := C.yh_util_get_template(	(*C.yh_session)(unsafe.Pointer(session)), (C.uint16_t)(object_id),
																(*C.uint8_t)(unsafe.Pointer(&out[0])), (*C.size_t)(unsafe.Pointer(out_len)))

	return YH_rc(rc)
}

/**
 * Import a #YH_TEMPLATE object into the device
 *
 * @param session Authenticated session to use
 * @param object_id Object ID of the Template. 0 if the Object ID should be
 *generated by the device
 * @param label Label of the Template. Maximum length is #YH_OBJ_LABEL_LEN
 * @param domains Domains the Template will be operating within. See
 *#yh_string_to_domains()
 * @param capabilities Capabilities of the Template. See
 *#yh_string_to_capabilities
 * @param algorithm Algorithm of the Template
 * @param in Template to import
 * @param in_len Length of the Template to import
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL or if
 *<tt>in_len</tt> is too big.
 *         See #yh_rc for other possible errors
 **/
func YH_util_import_template(	session *YH_session, object_id *uint16, label string, domains uint16,
															capabilities *YH_capabilities, algorithm YH_algorithm, in []byte, in_len int) YH_rc {
	l := C.CString(label)
	rc := C.yh_util_import_template(	(*C.yh_session)(unsafe.Pointer(session)), (*C.uint16_t)(unsafe.Pointer(object_id)),
																		l, (C.uint16_t)(domains),
																		(*C.yh_capabilities)(unsafe.Pointer(capabilities)),
																		(C.yh_algorithm)(algorithm),
																		(*C.uint8_t)(unsafe.Pointer(&in[0])), (C.size_t)(in_len))
	C.free(unsafe.Pointer(l))
	return YH_rc(rc)
}

/**
 * Create a Yubico OTP AEAD using the provided data
 *
 * @param session Authenticated session to use
 * @param key_id Object ID of the Otp-aead Key to use
 * @param key OTP key
 * @param private_id OTP private id
 * @param out The created AEAD
 * @param out_len Length of the created AEAD
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL.
 *         See #yh_rc for other possible errors
 **/
func YH_util_create_otp_aead(	session *YH_session, key_id uint16, key, private_id, out []byte, out_len *int) YH_rc {

	rc := C.yh_util_create_otp_aead(	(*C.yh_session)(unsafe.Pointer(session)), (C.uint16_t)(key_id),
																		(*C.uint8_t)(unsafe.Pointer(&key[0])), (*C.uint8_t)(unsafe.Pointer(&private_id[0])),
																		(*C.uint8_t)(unsafe.Pointer(&out[0])), (*C.size_t)(unsafe.Pointer(out_len)))

	return YH_rc(rc)
}


/**
 * Create OTP AEAD from random data
 *
 * @param session Authenticated session to use
 * @param key_id Object ID of the Otp-aead Key to use
 * @param out The created AEAD
 * @param out_len Length of the created AEAD
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL.
 *         See #yh_rc for other possible errors
 **/
func YH_util_randomize_otp_aead(	session *YH_session, key_id uint16, out []byte, out_len *int) YH_rc {

	rc := C.yh_util_randomize_otp_aead(	(*C.yh_session)(unsafe.Pointer(session)), (C.uint16_t)(key_id),
																		(*C.uint8_t)(unsafe.Pointer(&out[0])), (*C.size_t)(unsafe.Pointer(out_len)))

	return YH_rc(rc)
}

/**
 * Decrypt a Yubico OTP and return counters and time information.
 *
 * @param session Authenticated session to use
 * @param key_id Object ID of the key used for decryption
 * @param aead AEAD as created by #yh_util_create_otp_aead() or
 *#yh_util_randomize_otp_aead()
 * @param aead_len Length of AEAD
 * @param otp OTP
 * @param useCtr OTP use counter
 * @param sessionCtr OTP session counter
 * @param tstph OTP timestamp high
 * @param tstpl OTP timestamp low
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL.
 *         See #yh_rc for other possible errors
 **/
func YH_util_decrypt_otp(	session *YH_session, key_id uint16, aead []byte, aead_len int, otp []byte, useCtr *uint16, sessionCtr, tstph *uint8, tstpl *uint16) YH_rc {

	rc := C.yh_util_decrypt_otp(	(*C.yh_session)(unsafe.Pointer(session)), (C.uint16_t)(key_id),
																(*C.uint8_t)(unsafe.Pointer(&aead[0])), (C.size_t)(aead_len),
																(*C.uint8_t)(unsafe.Pointer(&otp[0])), (*C.uint16_t)(unsafe.Pointer(useCtr)),
																(*C.uint8_t)(unsafe.Pointer(sessionCtr)), (*C.uint8_t)(unsafe.Pointer(tstph)), (*C.uint16_t)(unsafe.Pointer(tstpl)))

	return YH_rc(rc)
}

/**
 * Import an #YH_OTP_AEAD_KEY used for Yubico OTP Decryption
 *
 * @param session Authenticated session to use
 * @param key_id Object ID of the AEAD Key. 0 if the Object ID should be
 *generated by the device
 * @param label Label of the AEAD Key. Maximum length is #YH_OBJ_LABEL_LEN
 * @param domains Domains the AEAD Key will be operating within. See
 *#yh_string_to_domains()
 * @param capabilities Capabilities of the AEAD Key. See
 *#yh_string_to_capabilities()
 * @param nonce_id Nonce ID
 * @param in AEAD Key to import
 * @param in_len Length of AEAD Key to import. Must be 16, 24 or 32
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL or if
 *<tt>in_len</tt> is not one of 16, 24 or 32.
 *         See #yh_rc for other possible errors
 **/
func YH_util_import_otp_aead_key(	session *YH_session, key_id *uint16, label string, domains uint16,
 																								capabilities *YH_capabilities, nonce_id uint32, in []byte, in_len int) YH_rc {
 	l := C.CString(label)
 	rc := C.yh_util_import_otp_aead_key(	(*C.yh_session)(unsafe.Pointer(session)), (*C.uint16_t)(unsafe.Pointer(key_id)),
																				l, (C.uint16_t)(domains),
																				(*C.yh_capabilities)(unsafe.Pointer(capabilities)),
																				(C.uint32_t)(nonce_id),
																				(*C.uint8_t)(unsafe.Pointer(&in[0])), (C.size_t)(in_len))
 	C.free(unsafe.Pointer(l))
 	return YH_rc(rc)
}


/**
 * Generate an #YH_OTP_AEAD_KEY for Yubico OTP decryption in the device.
 *
 * @param session Authenticated session to use
 * @param key_id Object ID of the AEAD Key. 0 if the Object ID should be
 *generated by the device
 * @param label Label of the AEAD Key. Maximum length is #YH_OBJ_LABEL_LEN
 * @param domains Domains the AEAD Key will be operating within. See
 *#yh_string_to_domains()
 * @param capabilities Capabilities of the AEAD Key. See
 *#yh_string_to_capabilities()
 * @param algorithm Algorithm used to generate the AEAD Key. Supported
 *algorithms: #YH_ALGO_AES128_YUBICO_OTP, #YH_ALGO_AES192_YUBICO_OTP and
 *#YH_ALGO_AES256_YUBICO_OTP
 * @param nonce_id Nonce ID
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL.
 *         See #yh_rc for other possible errors
 **/
func YH_util_generate_otp_aead_key(	session *YH_session, key_id *uint16, label string, domains uint16,
 																	capabilities *YH_capabilities, algorithm YH_algorithm, nonce_id uint32) YH_rc {
 	l := C.CString(label)
 	rc := C.yh_util_generate_otp_aead_key(	(*C.yh_session)(unsafe.Pointer(session)), (*C.uint16_t)(unsafe.Pointer(key_id)),
																				l, (C.uint16_t)(domains), (*C.yh_capabilities)(unsafe.Pointer(capabilities)),
																				(C.yh_algorithm)(algorithm), (C.uint32_t)(nonce_id))
 	C.free(unsafe.Pointer(l))
 	return YH_rc(rc)
}

/**
 * Get attestation of an Asymmetric Key in the form of an X.509 certificate
 *
 * @param session Authenticated session to use
 * @param key_id Object ID of the Asymmetric Key to attest
 * @param attest_id Object ID for the key used to sign the attestation
 *certificate
 * @param out The attestation certificate
 * @param out_len Length of the attestation certificate
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL.
 *         See #yh_rc for other possible errors
 **/
 func YH_util_sign_attestation_certificate(	session *YH_session, key_id, attest_id uint16, out []byte, out_len *int) YH_rc {
 	rc := C.yh_util_sign_attestation_certificate(	(*C.yh_session)(unsafe.Pointer(session)), (C.uint16_t)(key_id), (C.uint16_t)(attest_id),
 																		(*C.uint8_t)(unsafe.Pointer(&out[0])), (*C.size_t)(unsafe.Pointer(out_len)))
 	return YH_rc(rc)
 }

 /**
  * Set a device-global option
  *
  * @param session Authenticated session to use
  * @param option Option to set. See #yh_option
  * @param len Length of option value
  * @param val Option value
  *
  * @return #YHR_SUCCESS if successful.
  *         #YHR_INVALID_PARAMETERS if <tt>session</tt> or <tt>val</tt> are NULL
  *or if <tt>len</tt> is too long.
  *         See #yh_rc for other possible errors
  **/
func YH_util_set_option(session *YH_session, option YH_option, olen int, val []byte) YH_rc {
	rc := C.yh_util_set_option(	(*C.yh_session)(unsafe.Pointer(session)), (C.yh_option)(option),
															(C.size_t)(olen), (*C.uint8_t)(unsafe.Pointer(&val[0])))
	return YH_rc(rc)
}

 /**
  * Get a device-global option
  *
  * @param session Authenticated session to use
  * @param option Option to get. See #yh_option
  * @param out Option value
  * @param out_len Length of option value
  *
  * @return #YHR_SUCCESS if successful.
  *         #YHR_INVALID_PARAMETERS if input parameters are NULL.
  *         See #yh_rc for other possible errors
  **/
func YH_util_get_option(	session *YH_session, option YH_option, out []byte, out_len *int) YH_rc {
	rc := C.yh_util_get_option(	(*C.yh_session)(unsafe.Pointer(session)), (C.yh_option)(option),
																		(*C.uint8_t)(unsafe.Pointer(&out[0])), (*C.size_t)(unsafe.Pointer(out_len)))
	return YH_rc(rc)
}




/**
 * Report currently free storage. This is reported as free records, free pages
 *and page size.
 *
 * @param session Authenticated session to use
 * @param total_records Total number of records
 * @param free_records Number of free records
 * @param total_pages Total number of pages
 * @param free_pages Number of free pages
 * @param page_size Page size in bytes
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if the session is NULL.
 *         See #yh_rc for other possible errors
 **/
func YH_util_get_storage_info(session *YH_session, total_records, free_records, total_pages, free_pages, page_size *uint16) YH_rc {
    rc := C.yh_util_get_storage_info(	(*C.yh_session)(unsafe.Pointer(session)), (*C.uint16_t)(unsafe.Pointer(total_records)), (*C.uint16_t)(unsafe.Pointer(free_records)),
																		(*C.uint16_t)(unsafe.Pointer(total_pages)), (*C.uint16_t)(unsafe.Pointer(free_pages)), (*C.uint16_t)(unsafe.Pointer(page_size)))
		return YH_rc(rc)
}

/**
 * Encrypt (wrap) data using a #YH_WRAP_KEY.
 *
 * @param session Authenticated session to use
 * @param key_id Object ID of the Wrap Key to use
 * @param in Data to wrap
 * @param in_len Length of data to wrap
 * @param out Wrapped data
 * @param out_len Length of the wrapped data
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL or if
 *<tt>in_len</tt> is too big.
 *         See #yh_rc for other possible errors
 **/
func YH_util_wrap_data(	session *YH_session, key_id uint16, in []byte, in_len int, out []byte, out_len *int) YH_rc {
	rc := C.yh_util_wrap_data(	(*C.yh_session)(unsafe.Pointer(session)), (C.uint16_t)(key_id),
																	(*C.uint8_t)(unsafe.Pointer(&in[0])), (C.size_t)(in_len),
																	(*C.uint8_t)(unsafe.Pointer(&out[0])), (*C.size_t)(unsafe.Pointer(out_len)))
	return YH_rc(rc)
}

/**
 * Decrypt (unwrap) data using a #YH_WRAP_KEY.
 *
 * @param session Authenticated session to use
 * @param key_id Object ID of the Wrap Key to use
 * @param in Wrapped data
 * @param in_len Length of wrapped data
 * @param out Unwrapped data
 * @param out_len Length of unwrapped data
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL or if
 *<tt>in_len</tt> is too big.
 *         See #yh_rc for other possible errors
 **/
 func YH_util_unwrap_data(	session *YH_session, key_id uint16, in []byte, in_len int, out []byte, out_len *int) YH_rc {
 	rc := C.yh_util_unwrap_data(	(*C.yh_session)(unsafe.Pointer(session)), (C.uint16_t)(key_id),
 																	(*C.uint8_t)(unsafe.Pointer(&in[0])), (C.size_t)(in_len),
 																	(*C.uint8_t)(unsafe.Pointer(&out[0])), (*C.size_t)(unsafe.Pointer(out_len)))
 	return YH_rc(rc)
 }


 /**
  * Blink the LED of the device to identify it
  *
  * @param session Authenticated session to use
  * @param seconds Number of seconds to blink
  *
  * @return #YHR_SUCCESS if successful.
  *         #YHR_INVALID_PARAMETERS if the session is NULL.
  *         See #yh_rc for other possible errors
  **/
func YH_util_blink_device(session *YH_session, seconds uint8) YH_rc {
	return YH_rc(C.yh_util_blink_device((*C.yh_session)(unsafe.Pointer(session)), (C.uint8_t)(seconds)))
}

/**
 * Factory reset the device. Resets and reboots the device, deletes all Objects
 *and restores the default #YH_AUTHENTICATION_KEY.
 *
 * @param session Authenticated session to use
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if the session is NULL.
 *         See #yh_rc for other possible errors
 **/
func YH_util_reset_device(session *YH_session) YH_rc {
	result := C.yh_util_reset_device((*C.yh_session)(unsafe.Pointer(session)))
	return YH_rc(result)
}

/**
 * Get the session ID
 *
 * @param session Authenticated session to use
 * @param sid Session ID
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL.
 **/
func YH_get_session_id(session *YH_session, sid *uint8) YH_rc {
	result := C.yh_get_session_id((*C.yh_session)(unsafe.Pointer(session)), (*C.uint8_t)(unsafe.Pointer(sid)))
	return YH_rc(result)
}

/**
 * Check if the connector has a device connected
 *
 * @param connector Connector currently in use
 *
 * @return True if the connector is not NULL and there is a device connected to
 *it. False otherwise
 **/
func YH_connector_has_device(connector *YH_connector) bool {
	result := C.yh_connector_has_device((*C.yh_connector)(unsafe.Pointer(connector)))
	return bool(result)
}

/**
 * Get the connector version
 *
 * @param connector Connector currently in use
 * @param major Connector major version
 * @param minor Connector minor version
 * @param patch Connector patch version
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL.
 **/
func YH_get_connector_version(connector *YH_connector, major, minor, patch *uint8) YH_rc {
	result := C.yh_get_connector_version((*C.yh_connector)(unsafe.Pointer(connector)), (*C.uint8_t)(unsafe.Pointer(major)), (*C.uint8_t)(unsafe.Pointer(minor)), (*C.uint8_t)(unsafe.Pointer(patch)))
	return YH_rc(result)
}

/**
 * Get connector address
 *
 * @param connector Connector currently in use
 * @param address Pointer to the connector address as string
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL.
 **/
func YH_get_connector_address(connector *YH_connector, address **uint8) YH_rc {
	result := C.yh_get_connector_address((*C.yh_connector)(unsafe.Pointer(connector)), (**C.char)(unsafe.Pointer(address)))
	return YH_rc(result)
}


/**
 * Convert capability string to byte array
 *
 * @param capability String of capabilities separated by ',', ':' or '|'
 * @param result Array of #yh_capabilities
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL.
 *         #YHR_BUFFER_TOO_SMALL if <tt>capability</tt> is too big
 *
 * @par Examples:
 *
 *  * "get-opaque" => {"\x00\x00\x00\x00\x00\x00\x00\x01"}
 *  * "sign-hmac:verify-hmac|exportable-under-wrap," =>
 *{"\x00\x00\x00\x00\x00\xc1\x00\x00"}
 *  * ",,unwrap-data|:wrap-data,,," => {"\x00\x00\x00\x60\x00\x00\x00\x00"}
 *  * "0x7fffffffffffffff" => {"\x7f\xff\xff\xff\xff\xff\xff\xff"}
 *  * "0xffffffffffffffff" => {"\xff\xff\xff\xff\xff\xff\xff\xff"}
 *
 * @see <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Capability.html">Capability</a>
 **/
func YH_string_to_capabilities(capability string) (*YH_capabilities, YH_rc) {
	c := C.CString(capability)
	var result YH_capabilities
	rc := C.yh_string_to_capabilities(c, (*C.yh_capabilities)(unsafe.Pointer(&result)))
	C.free(unsafe.Pointer(c))
	return &result, YH_rc(rc)
}

/**
 * Convert an array of #yh_capabilities into strings separated by ','
 *
 * @param num Array of #yh_capabilities
 * @param result Array of the capabilies as strings
 * @param n_result Number of elements in result
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL.
 *         #YHR_BUFFER_TOO_SMALL if <tt>n_result</tt> is too small
 *
 * @see <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Capability.html">Capability</a>
 **/
/*yh_rc yh_capabilities_to_strings(const yh_capabilities *num,
                                 const char *result[], size_t *n_result);
func YH_capabilities_to_strings(num *YH_capabilities, capability []string, n_result *int) YH_rc {
	rc := C.yh_capabilities_to_strings((*C.yh_capabilities)(unsafe.Pointer(num)), (*C.size_t)(unsafe.Pointer(n_result)))
	return &result, YH_rc(rc)
} -> left out - to inconvenient*/

/**
 * Check if a capability is set
 *
 * @param capabilities Array of #yh_capabilities
 * @param capability Capability to check as a string.
 *
 * @return True if the <tt>capability</tt> is in <tt>capabilities</tt>. False
 *otherwise
 *
 * @par Code sample
 *
 *     char *capabilities_str = "sign-pkcs,decrypt-pkcs,set-option";
 *     yh_capabilities capabilities = {{0}};
 *     yh_string_to_capabilities(capabilities_str, &capabilities);
 *     //yh_check_capability(&capabilities, "something") => false
 *     //yh_check_capability(&capabilities, "sign-pss") => false
 *     //yh_check_capability(&capabilities, "decrypt-pkcs") => true
 *
 * @see <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Capability.html">Capability</a>
 **/
func YH_check_capability(capabilities *YH_capabilities, capability string) bool {
	c := C.CString(capability)
	result := C.yh_check_capability((*C.yh_capabilities)(unsafe.Pointer(capabilities)), c)
	C.free(unsafe.Pointer(c))
	return bool(result)
}

/**
 * Merge two sets of capabilities. The resulting set of capabilities contain all
 *capabilities from both arrays
 *
 * @param a Array of #yh_capabilities
 * @param b Array of #yh_capabilities
 * @param result Resulting array of #yh_capabilities
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL.
 *
 * @see <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Capability.html">Capability</a>
 **/
func YH_merge_capabilities(a, b, result *YH_capabilities) YH_rc {
	rc := C.yh_merge_capabilities((*C.yh_capabilities)(unsafe.Pointer(a)), (*C.yh_capabilities)(unsafe.Pointer(b)), (*C.yh_capabilities)(unsafe.Pointer(result)))
	return YH_rc(rc)
}

/**
 * Filter one set of capabilities with another. The resulting set of
 *capabilities contains only the capabilities that exist in both sets of input
 *capabilities
 *
 * @param capabilities Array of #yh_capabilities
 * @param filter Array of #yh_capabilities
 * @param result Resulting array of #yh_capabilities
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL.
 *
 * @see <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Capability.html">Capability</a>
 **/
func YH_filter_capabilities(capabilities, filter, result *YH_capabilities) YH_rc {
	rc := C.yh_filter_capabilities((*C.yh_capabilities)(unsafe.Pointer(capabilities)), (*C.yh_capabilities)(unsafe.Pointer(filter)), (*C.yh_capabilities)(unsafe.Pointer(result)))
	return YH_rc(rc)
}

/**
 * Check if an algorithm is a supported RSA algorithm.
 *
 * Supported RSA algorithms: #YH_ALGO_RSA_2048, #YH_ALGO_RSA_3072 and
 *#YH_ALGO_RSA_4096
 *
 * @param algorithm Algorithm to check. See #yh_algorithm
 *
 * @return True if the algorithm is one of the supported RSA algorithms . False
 *otherwise
 **/
func YH_is_rsa(algorithm YH_algorithm) bool {
	return bool(C.yh_is_rsa((C.yh_algorithm)(algorithm)))
}


/**
 * Check if an algorithm is a supported Elliptic Curve algorithm.
 *
 * Supported EC algorithms: #YH_ALGO_EC_P224, #YH_ALGO_EC_P256,
 *#YH_ALGO_EC_P384, #YH_ALGO_EC_P521, #YH_ALGO_EC_K256, #YH_ALGO_EC_BP256,
 *#YH_ALGO_EC_BP384 and #YH_ALGO_EC_BP512
 *
 * @param algorithm Algorithm to check. See #yh_algorithm
 *
 * @return True if the algorithm is one of the supported EC algorithms. False
 *otherwise
 **/
func YH_is_ec(algorithm YH_algorithm) bool {
	return bool(C.yh_is_ec((C.yh_algorithm)(algorithm)))
}

/**
 * Check if an algorithm is a supported ED algorithm.
 *
 * Supported ED algorithms: #YH_ALGO_EC_ED25519
 *
 * @param algorithm algorithm. See #yh_algorithm
 *
 * @return True if the algorithm is #YH_ALGO_EC_ED25519. False otherwise
 **/
func YH_is_ed(algorithm YH_algorithm) bool {
	return bool(C.yh_is_ed((C.yh_algorithm)(algorithm)))
}

/**
 * Check if algorithm is a supported HMAC algorithm.
 *
 * Supported HMAC algorithms: #YH_ALGO_HMAC_SHA1, #YH_ALGO_HMAC_SHA256,
 *#YH_ALGO_HMAC_SHA384 and #YH_ALGO_HMAC_SHA512
 *
 * @param algorithm Algorithm to check. See #yh_algorithm
 *
 * @return True if the algorithm is one of the supported HMAC algorithms. False
 *otherwise
 **/
func YH_is_hmac(algorithm YH_algorithm) bool {
	return bool(C.yh_is_hmac((C.yh_algorithm)(algorithm)))
}

/**
 * Get the expected key length of a key generated by the given algorithm
 *
 * @param algorithm Algorithm to check. See #yh_algorithm
 * @param result Expected bitlength of a key generated by the algorithm
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if <tt>result</tt> is NULL or if the
 *algorithm is no supported by YubiHSM 2. For a list of supported algorithms,
 *see #yh_algorithm
 **/
func YH_get_key_bitlength(algorithm YH_algorithm, result *int) YH_rc {
	rc := C.yh_get_key_bitlength((C.yh_algorithm)(algorithm), (*C.size_t)(unsafe.Pointer(result)))
	return YH_rc(rc)
}

/**
 * Convert an algorithm to its string representation.
 *
 * @param algo Algorithm to convert. See #yh_algorithm
 * @param result The algorithm as a String. "Unknown" if the algorithm is not
 *supported by YubiHSM 2.
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if <tt>result</tt> is NULL.
 *
 * @see <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Algorithms.html">Algorithms</a>
 **/
func YH_algo_to_string(algo YH_algorithm, result *string) YH_rc {
	var presult **C.char
	rc := C.yh_algo_to_string((C.yh_algorithm)(algo), (**C.char)(unsafe.Pointer(presult)))
	*result = C.GoString(*presult)
	return YH_rc(rc)
}

/**
 * Convert a string to an algorithm's numeric value
 *
 * @param string Algorithm as string. See #yh_algorithm
 * @param algo Algorithm numeric value
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL or if the
 *algorithm is not supported by YubiHSM 2.
 *
 * @par Code sample
 *
 *     yh_algorithm algorithm;
 *     //yh_string_to_algo(NULL, &algorithm) => YHR_INVALID_PARAMETERS
 *     //yh_string_to_algo("something", NULL) => YHR_INVALID_PARAMETERS
 *     //yh_string_to_algo("something", &algorithm) => YHR_INVALID_PARAMETERS
 *     //yh_string_to_algo("rsa-pkcs1-sha1", &algorithm) =>
 *YH_ALGO_RSA_PKCS1_SHA1
 *     //yh_string_to_algo("rsa2048", &algorithm) => YH_ALGO_RSA_2048
 *
 * @see <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Algorithms.html">Algorithms</a>
 **/
func YH_string_to_algo(algo_str string, algo *YH_algorithm) YH_rc {
	a := C.CString(algo_str)
	rc := C.yh_string_to_algo(a, (*C.yh_algorithm)(unsafe.Pointer(algo)))
	C.free(unsafe.Pointer(a))
	return YH_rc(rc)
}

/**
 * Convert a #yh_object_type to its string representation
 *
 * @param type Type to convert. See #yh_object_type
 * @param result The type as a String. "Unknown" if the type was not recognized
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if <tt>result</tt> is NULL.
 *
 * @par Code sample
 *
 *     const char *string;
 *     //yh_type_to_string(0, NULL) => YHR_INVALID_PARAMETERS
 *     //yh_type_to_string(99, &string) => string="Unknown"
 *     //yh_type_to_string(YH_OPAQUE, &string) => string="opaque"
 *     //yh_type_to_string(YH_AUTHENTICATION_KEY, &string) =>
 *string="authentication-key"
 *
 * @see <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Object.html">Object</a>
 **/
func YH_type_to_string(object_type YH_object_type, result *string) YH_rc {
	var presult **C.char
	rc := C.yh_type_to_string((C.yh_object_type)(object_type), (**C.char)(unsafe.Pointer(presult)))
	*result = C.GoString(*presult)
	return YH_rc(rc)
}

/**
 * Convert a string to a type's numeric value
 *
 * @param string Type as a String. See #yh_object_type
 * @param type Type numeric value
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL or if the type
 *was not recognized.
 *
 * @par Code sample
 *
 *     yh_object_type type;
 *     //yh_string_to_type(NULL, &type) => YHR_INVALID_PARAMETERS
 *     //yh_string_to_type("something", NULL) => YHR_INVALID_PARAMETERS
 *     //yh_string_to_type("something", &type) => YHR_INVALID_PARAMETERS
 *     //yh_string_to_type("opaque", &type) => type=YH_OPAQUE
 *     //yh_string_to_type("authentication-key", &type) =>
 *type=YH_AUTHENTICATION_KEY
 *
 * @see <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Object.html">Object</a>
 **/
func YH_string_to_type(object_str string, object_type *YH_object_type) YH_rc {
	o := C.CString(object_str)
	rc := C.yh_string_to_type(o, (*C.yh_object_type)(unsafe.Pointer(object_type)))
	C.free(unsafe.Pointer(o))
	return YH_rc(rc)
}

/**
 * Convert a string to an option's numeric value
 *
 * @param string Option as string. See #yh_option
 * @param option Option numeric value
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL or if the option
 *was not recognized.
 *
 * @par Code sample
 *
 *     yh_option option;
 *     //yh_string_to_option(NULL, &option) => YHR_INVALID_PARAMETERS
 *     //yh_string_to_option("something", NULL) => YHR_INVALID_PARAMETERS
 *     //yh_string_to_option("something", &option) => YHR_INVALID_PARAMETERS
 *     //yh_string_to_option("force-audit", &option) =>
 *option=YH_OPTION_FORCE_AUDIT
 *
 * @see <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Options.html">Options</a>
 **/
func yh_string_to_option(opt_str string, option *YH_option) YH_rc {
	o := C.CString(opt_str)
	rc := C.yh_string_to_option(o, (*C.yh_option)(unsafe.Pointer(option)))
	C.free(unsafe.Pointer(o))
	return YH_rc(rc)
}

/**
 * Verify an array of log entries
 *
 * @param logs Array of log entries
 * @param n_items number of log entries
 * @param last_previous_log Optional pointer to the entry before the first entry
 *in logs
 *
 * @return True if verification succeeds. False otherwise
 *
 * @see <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Logs.html">Logs</a>
 **/
func YH_verify_logs(logs []YH_log_entry, n_items int, last_previous_log *YH_log_entry) bool {
 	return bool(C.yh_verify_logs((*C.yh_log_entry)(unsafe.Pointer(&logs[0])), (C.size_t)(n_items), (*C.yh_log_entry)(unsafe.Pointer(last_previous_log))))
}


/**
 * Convert a string to a domain's numeric value.
 *
 * The domains string can contain one or several domains separated by ',', ':'
 *or
 *'|'. Each domain can be written in decimal or hex format
 *
 * @param domains String of domains
 * @param result Resulting parsed domains as an unsigned int
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL, if the domains
 *string is does not contains the expected values
 *
 * @par Examples
 *
 *  * "1" => 1
 *  * "1,2:3,4|5,6;7,8,9,10,11,12,13,14,15,16" => 0xffff
 *  * "1,16" => 0x8001
 *  * "16" => 0x8000
 *  * "16,15" => 0xc000
 *  * "1,0xf" => 0x4001
 *  * "0x1,0x2" => 3
 *  * "0x8888" => 0x8888
 *  * "0" => 0
 *  * "all" => 0xffff
 *  * "2" => 2
 *  * "2:4" => 10
 *
 * @see <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Domain.html">Domains</a>
 **/
func YH_string_to_domains(domains string, result *uint16) YH_rc {
	d := C.CString(domains)
	rc := C.yh_string_to_domains(d, (*C.uint16_t)(unsafe.Pointer(result)))
	C.free(unsafe.Pointer(d))
	return YH_rc(rc)
}

/**
 * Convert domains parameter to its String representation
 *
 * @param domains Encoded domains
 * @param string Domains as a string
 * @param max_len Maximum length of the string
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_BUFFER_TOO_SMALL if <tt>max_len</tt> is too small
 *
 * @par Examples
 *
 *  * 1 => "1"
 *  * 0x8001 => "1:16"
 *  * 0, ""
 *  * 0xffff => "1:2:3:4:5:6:7:8:9:10:11:12:13:14:15:16"
 *
 * @see <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Domain.html">Domains</a>
 **/
func YH_domains_to_string(domains uint16, char *string, max_len int) YH_rc {
	result := make([]byte, max_len)
	rc := C.yh_domains_to_string((C.uint16_t)(domains), (*C.char)(unsafe.Pointer(&result[0])), (C.size_t)(max_len))
	*char = string(result)
	return YH_rc(rc)
}
