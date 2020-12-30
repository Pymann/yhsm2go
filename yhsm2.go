package yubihsm2

/*
#cgo CFLAGS: -I/usr/include -std=c99
#cgo LDFLAGS: -L/usr/lib  -lyubihsm -lyubihsm_usb -lyubihsm_http
#include <stdlib.h>
#include <yubihsm.h>
*/
import "C"

import (
	"unsafe"
)

type (
	YH_session C.yh_session
	YH_connector C.yh_connector
	YH_capabilities C.yh_capabilities
)

func YH_strerror(err YH_rc) string {
	err_ch := C.yh_strerror(C.yh_rc(err))
	return C.GoString(err_ch)
}

func YH_init() YH_rc {
	return YH_rc(C.yh_init())
}

func YH_exit() YH_rc {
	return YH_rc(C.yh_exit())
}

func YH_init_connector(url string) (*YH_connector, YH_rc) {
	curl := C.CString(url)
	var connector *YH_connector
	rc := C.yh_init_connector(curl, (**C.yh_connector)(unsafe.Pointer(&connector)))
	C.free(unsafe.Pointer(curl))
	return connector, YH_rc(rc)
}

func YH_connect(connector *YH_connector, timeout int) YH_rc {
	return YH_rc(C.yh_connect((*C.yh_connector)(unsafe.Pointer(connector)), C.int(timeout)))
}

/*
yh_rc yh_create_session_derived(yh_connector *connector, uint16_t authkey_id,
                                const uint8_t *password, size_t password_len,
                                bool recreate_session, yh_session **session);*/
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


func YH_authenticate_session(session *YH_session) YH_rc {
	return YH_rc(C.yh_authenticate_session((*C.yh_session)(unsafe.Pointer(session))))
}



func YH_set_verbosity(connector *YH_connector, verbosity uint8) YH_rc {
	return YH_rc(C.yh_set_verbosity((*C.yh_connector)(unsafe.Pointer(connector)), C.uint8_t(verbosity)))
}

func YH_getet_verbosity(verbosity *uint8) YH_rc {
	return YH_rc(C.yh_get_verbosity((*C.uint8_t)(unsafe.Pointer(verbosity))))
}

/*yh_rc yh_util_get_device_info(yh_connector *connector, uint8_t *major,
                              uint8_t *minor, uint8_t *patch, uint32_t *serial,
                              uint8_t *log_total, uint8_t *log_used,
                              yh_algorithm *algorithms, size_t *n_algorithms);*/
func YH_util_get_device_info(connector *YH_connector, major,
                              minor, patch *uint8, serial *uint32,
                              log_total, log_used *uint8,
                              algorithms *YH_algorithm, n_algorithms *int) YH_rc {

	return YH_rc(C.yh_util_get_device_info((*C.yh_connector)(unsafe.Pointer(connector)),
																	(*C.uint8_t)(unsafe.Pointer(major)),
																	(*C.uint8_t)(unsafe.Pointer(minor)),
																	(*C.uint8_t)(unsafe.Pointer(patch)),
																	(*C.uint32_t)(unsafe.Pointer(serial)),
																	(*C.uint8_t)(unsafe.Pointer(log_total)),
																	(*C.uint8_t)(unsafe.Pointer(log_used)),
																	(*C.yh_algorithm)(unsafe.Pointer(algorithms)),
																	(*C.size_t)(unsafe.Pointer(n_algorithms))))
}

/*yh_rc yh_util_get_storage_info(yh_session *session, uint16_t *total_records,
                               uint16_t *free_records, uint16_t *total_pages,
                               uint16_t *free_pages, uint16_t *page_size);*/
func YH_util_get_storage_info(session *YH_session, total_records,
                               free_records, total_pages,
                               free_pages, page_size *uint16) YH_rc {
    rc := C.yh_util_get_storage_info(	(*C.yh_session)(unsafe.Pointer(session)),
																		(*C.uint16_t)(unsafe.Pointer(total_records)),
																		(*C.uint16_t)(unsafe.Pointer(free_records)),
																		(*C.uint16_t)(unsafe.Pointer(total_pages)),
																		(*C.uint16_t)(unsafe.Pointer(free_pages)),
																		(*C.uint16_t)(unsafe.Pointer(page_size)))
		return YH_rc(rc)
}

func YH_util_blink_device(session *YH_session, seconds uint8) YH_rc {
	return YH_rc(C.yh_util_blink_device((*C.yh_session)(unsafe.Pointer(session)), (C.uint8_t)(seconds)))
}

func YH_util_reset_device(session *YH_session) YH_rc {
	result := C.yh_util_reset_device((*C.yh_session)(unsafe.Pointer(session)))
	return YH_rc(result)
}

func YH_string_to_domains(domains string, result *uint16) YH_rc {
	d := C.CString(domains)
	rc := C.yh_string_to_domains(d, (*C.uint16_t)(unsafe.Pointer(result)))
	C.free(unsafe.Pointer(d))
	return YH_rc(rc)
}

/*yh_rc yh_string_to_capabilities(const char *capability,
                                yh_capabilities *result);*/
func YH_string_to_capabilities(capability string) (*YH_capabilities, YH_rc) {
	c := C.CString(capability)
	var result YH_capabilities
	rc := C.yh_string_to_capabilities(c, (*C.yh_capabilities)(unsafe.Pointer(&result)))
	C.free(unsafe.Pointer(c))
	return &result, YH_rc(rc)
}

/*yh_rc yh_util_import_authentication_key_derived(
  yh_session *session, uint16_t *key_id, const char *label, uint16_t domains,
  const yh_capabilities *capabilities,
  const yh_capabilities *delegated_capabilities, const uint8_t *password,
  size_t password_len);*/
func YH_util_import_authentication_key_derived(	session *YH_session,
																								key_id *uint16,
																								label string,
																								domains uint16,
																								capabilities, del_capabilites *YH_capabilities,
																								password string) YH_rc {
	l := C.CString(label)
	p := C.CString(password)
	result := C.yh_util_import_authentication_key_derived(	(*C.yh_session)(unsafe.Pointer(session)),
																													(*C.uint16_t)(unsafe.Pointer(key_id)),
																													l, (C.uint16_t)(domains),
																													(*C.yh_capabilities)(unsafe.Pointer(capabilities)),
																													(*C.yh_capabilities)(unsafe.Pointer(del_capabilites)),
																													(*C.uint8_t)(unsafe.Pointer(p)),
																													(C.size_t)(len(password)))
	C.free(unsafe.Pointer(l))
	C.free(unsafe.Pointer(p))
	return YH_rc(result)
}

/*yh_rc yh_util_get_pseudo_random(yh_session *session, size_t len, uint8_t *out,
                                size_t *out_len);*/
//this guy was curious, I had to set parameter out_len pointing to value len (equal numeric value), otherwise error, buffer to small.
func YH_util_get_pseudo_random(session *YH_session, len int) ([]byte, YH_rc) {
	ba := make([]byte, len)
	cba := C.CBytes(ba)
	rc := C.yh_util_get_pseudo_random((*C.yh_session)(unsafe.Pointer(session)),
																						C.size_t(len),
																						(*C.uint8_t)(cba),
																					  (*C.size_t)(unsafe.Pointer(&len)))
	ba = C.GoBytes(cba, C.int(len))
	C.free(cba)
	return ba, YH_rc(rc)
}

/*yh_rc yh_util_generate_wrap_key(	yh_session *session,
									uint16_t *key_id,
									const char *label,
									uint16_t domains,
									const yh_capabilities *capabilities,
									yh_algorithm algorithm,
									const yh_capabilities *delegated_capabilities);*/
func YH_util_generate_wrap_key(	session *YH_session,
																key_id *uint16,
																label string,
																domains uint16,
																capabilities *YH_capabilities,
																algorithm YH_algorithm,
																del_capabilites *YH_capabilities) YH_rc {
	l := C.CString(label)
	result := C.yh_util_generate_wrap_key((*C.yh_session)(unsafe.Pointer(session)),
																				(*C.uint16_t)(unsafe.Pointer(key_id)),
																				l, (C.uint16_t)(domains),
																				(*C.yh_capabilities)(unsafe.Pointer(capabilities)),
																				(C.yh_algorithm)(algorithm),
																				(*C.yh_capabilities)(unsafe.Pointer(del_capabilites)))
	C.free(unsafe.Pointer(l))
	return YH_rc(result)
}

func YH_util_close_session(session *YH_session) YH_rc {
	return YH_rc(C.yh_util_close_session((*C.yh_session)(unsafe.Pointer(session))))
}

func YH_destroy_session(session *YH_session) YH_rc {
	return YH_rc(C.yh_destroy_session((**C.yh_session)(unsafe.Pointer(&session))))
}

func YH_disconnect(connector *YH_connector) YH_rc {
	return YH_rc(C.yh_disconnect((*C.yh_connector)(unsafe.Pointer(connector))))
}
