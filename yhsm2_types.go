package yhsm2go

/*
#cgo CFLAGS: -I/usr/include -std=c99
#cgo LDFLAGS: -L/usr/lib  -lyubihsm -lyubihsm_usb -lyubihsm_http
#include <yubihsm.h>
*/
import "C"

type (
	YH_session C.yh_session
	YH_connector C.yh_connector
	YH_log_entry C.yh_log_entry
	YH_capabilities C.yh_capabilities
	YH_object_descriptor C.yh_object_descriptor
)
