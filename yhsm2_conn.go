package yhsm2go

import(
  "fmt"
  "errors"
)

type Connection struct{
  Connector *YH_connector
  Session *YH_session
  Url, Label, Domains string
  NumDomains uint16
  Last_err YH_rc
  emergency int
}

func (conn *Connection)Print_rc() {
  if conn.Last_err != 0 && conn.emergency > 0 {
    if conn.emergency == 1 {
      panic(conn.GetLastError())
    } else {
      fmt.Printf("Error %d: %s\n", conn.Last_err, YH_strerror(conn.Last_err))
    }
  }
}

func (conn *Connection)GetLastError() error {
  return errors.New(fmt.Sprintf("Error %d: %s\n", conn.Last_err, YH_strerror(conn.Last_err)))
}

func (conn *Connection)InitConn(url string, timeout int, verbosity uint8, emergency int) (YH_rc) {
  conn.emergency = emergency
  conn.Last_err = YH_init()
  if conn.Last_err != YHR_SUCCESS {
    conn.Print_rc()
    return conn.Last_err
  }
  conn.Url = url
  conn.Connector, conn.Last_err = YH_init_connector(url)
  if conn.Last_err != YHR_SUCCESS {
    conn.Print_rc()
    return conn.Last_err
  }

  if verbosity > 0 {
    conn.Last_err = YH_set_verbosity(conn.Connector, verbosity)
    if conn.Last_err != YHR_SUCCESS {
      conn.Print_rc()
      return conn.Last_err
    }
  }
  conn.Last_err = YH_connect(conn.Connector, timeout)
  if conn.Last_err != YHR_SUCCESS {
    conn.Print_rc()
    return conn.Last_err
  }
  return conn.Last_err
}

func (conn *Connection)DeInit() YH_rc {
  conn.Last_err = YH_disconnect(conn.Connector)
  if conn.Last_err != YHR_SUCCESS {
    conn.Print_rc()
    return conn.Last_err
  }
  conn.Last_err = YH_exit()
  conn.Print_rc()
  return conn.Last_err
}

func (conn *Connection)CreateSession(authkey_id uint16, password string, recreate_session bool) YH_rc {
  conn.Session, conn.Last_err = YH_create_session_derived(conn.Connector, authkey_id, password, recreate_session)
  if conn.Last_err != YHR_SUCCESS {
    conn.Print_rc()
    return conn.Last_err
  }
  conn.Last_err = YH_authenticate_session(conn.Session)
  conn.Print_rc()
  return conn.Last_err
}

func (conn *Connection)DestroySession() YH_rc {
  conn.Last_err = YH_util_close_session(conn.Session)
  if conn.Last_err != YHR_SUCCESS {
    conn.Print_rc()
    return conn.Last_err
  }
  conn.Last_err = YH_destroy_session(conn.Session)
  conn.Print_rc()
  return conn.Last_err
}

func (conn *Connection)FastConnection(url string, authkey_id uint16, password string) YH_rc {
  conn.InitConn(url, 0, 0, 1)
  conn.CreateSession(authkey_id, password, false)
  conn.Print_rc()
  return conn.Last_err
}

func (conn *Connection)Exit() YH_rc {
  conn.DestroySession()
  if conn.Last_err != YHR_SUCCESS {
    conn.Print_rc()
    return conn.Last_err
  }
  conn.DeInit()
  conn.Print_rc()
  return conn.Last_err
}

func (conn *Connection)SetVerbosity(verbosity uint8) YH_rc {
  conn.Last_err = YH_set_verbosity(conn.Connector, verbosity)
  conn.Print_rc()
  return conn.Last_err
}

func (conn *Connection)PrintDeviceInfo() YH_rc {
  var major, minor, patch uint8
  var serial uint32
  var log_total, log_used uint8
  algorithms := make([]YH_algorithm, 100)
  var n_algorithms int = 100
  conn.Last_err = YH_util_get_device_info(conn.Connector, &major, &minor, &patch, &serial, &log_total, &log_used, algorithms, &n_algorithms)
  conn.Print_rc()
  fmt.Printf("Device-Info\nFirmware: %d.%d.%d\nSerial: %d\nLogs %d/%d\nAlgos[%d]: %d\n", major, minor, patch, serial, log_total, log_used, n_algorithms, algorithms[0:n_algorithms])
  return conn.Last_err
}

func (conn *Connection)PrintStorageInfo() YH_rc {
  var total_records, free_records, total_pages, free_pages, page_size uint16
  conn.Last_err = YH_util_get_storage_info(conn.Session, &total_records, &free_records, &total_pages, &free_pages, &page_size)
  conn.Print_rc()
  fmt.Printf("Storage-Info\ntotal_records: %d\nfree_records: %d\ntotal_pages: %d\nfree_pages: %d\npage_size: %d\n", total_records, free_records, total_pages, free_pages, page_size)
  return conn.Last_err
}

func (conn *Connection)BlinkDevice(seconds uint8) YH_rc {
  conn.Last_err = YH_util_blink_device(conn.Session, seconds)
  conn.Print_rc()
  return conn.Last_err
}

func (conn *Connection)ResetDevice() YH_rc {
  conn.Last_err = YH_util_reset_device(conn.Session)
  conn.Print_rc()
  return conn.Last_err
}

func (conn *Connection)SetLabelDomains(label, domains string) YH_rc {
  conn.Label = label
  conn.Domains = domains
  conn.Last_err = YH_string_to_domains(conn.Domains, &conn.NumDomains)
  conn.Print_rc()
  return conn.Last_err
}

func (conn *Connection)DeleteObject(id uint16, object_type YH_object_type) YH_rc {
  conn.Last_err = YH_util_delete_object(conn.Session, id, object_type)
  conn.Print_rc()
  return conn.Last_err
}

func (conn *Connection)ImportAuthentication(key_id *uint16, capabilities, del_capabilites string, password string) YH_rc {
  var yh_auth_caps, del_yh_auth_caps *YH_capabilities
  yh_auth_caps, conn.Last_err = YH_string_to_capabilities(capabilities)
  conn.Print_rc()
  if conn.Last_err != YHR_SUCCESS {
    return conn.Last_err
  }
  del_yh_auth_caps, conn.Last_err = YH_string_to_capabilities(del_capabilites)
  conn.Print_rc()
  if conn.Last_err != YHR_SUCCESS {
    return conn.Last_err
  }
  conn.Last_err = YH_util_import_authentication_key_derived(conn.Session, key_id, conn.Label, conn.NumDomains, yh_auth_caps, del_yh_auth_caps, password)
  conn.Print_rc()
  return conn.Last_err
}

func (conn *Connection)GetPseudoRandom(rlen int) ([]byte, YH_rc) {
  ba := make([]byte, rlen)
  out_len := rlen
  conn.Last_err = YH_util_get_pseudo_random(conn.Session, rlen, ba, &out_len)
  conn.Print_rc()
  return ba[:out_len], conn.Last_err
}

func (conn *Connection)GenerateWrapkey(key_id *uint16, capabilities string, algorithm YH_algorithm, del_capabilites string) YH_rc {
  var yh_wkey_caps, del_yh_wkey_caps *YH_capabilities
  yh_wkey_caps, conn.Last_err = YH_string_to_capabilities(capabilities)
  conn.Print_rc()
  if conn.Last_err != YHR_SUCCESS {
    return conn.Last_err
  }
  del_yh_wkey_caps, conn.Last_err = YH_string_to_capabilities(del_capabilites)
  conn.Print_rc()
  if conn.Last_err != YHR_SUCCESS {
    return conn.Last_err
  }
  conn.Last_err = YH_util_generate_wrap_key(conn.Session, key_id, conn.Label, conn.NumDomains, yh_wkey_caps, algorithm, del_yh_wkey_caps)
  conn.Print_rc()
  return conn.Last_err
}

func (conn *Connection)ExportWrap(wrapping_key_id uint16, target_type YH_object_type, target_id uint16, max_out_len int) ([]byte, YH_rc) {
  ba := make([]byte, max_out_len)
  out_len := max_out_len
  conn.Last_err = YH_util_export_wrapped(conn.Session, wrapping_key_id, target_type, target_id, ba, &out_len)
  conn.Print_rc()
  return ba[:out_len], conn.Last_err
}

func (conn *Connection)ImportWrap(wrapping_key_id uint16, in []byte, target_type *YH_object_type, target_id *uint16) YH_rc {
  conn.Last_err = YH_util_import_wrapped(conn.Session, wrapping_key_id, in, len(in), target_type, target_id)
  conn.Print_rc()
  return conn.Last_err
}

func (conn *Connection)ImportWrapkey(key_id *uint16, capabilities string, algorithm YH_algorithm, del_capabilites string, in []byte) YH_rc {
  var yh_wkey_caps, del_yh_wkey_caps *YH_capabilities
  yh_wkey_caps, conn.Last_err = YH_string_to_capabilities(capabilities)
  conn.Print_rc()
  if conn.Last_err != YHR_SUCCESS {
    return conn.Last_err
  }
  del_yh_wkey_caps, conn.Last_err = YH_string_to_capabilities(del_capabilites)
  conn.Print_rc()
  if conn.Last_err != YHR_SUCCESS {
    return conn.Last_err
  }
  conn.Last_err = YH_util_import_wrap_key(conn.Session, key_id, conn.Label, conn.NumDomains, yh_wkey_caps, algorithm, del_yh_wkey_caps, in, len(in))
  conn.Print_rc()
  return conn.Last_err
}

func (conn *Connection)WrapData(key_id uint16, in []byte, max_out_len int) ([]byte, YH_rc) {
  ba := make([]byte, max_out_len)
  out_len := max_out_len
  conn.Last_err = YH_util_wrap_data(conn.Session, key_id, in, len(in), ba, &out_len)
  conn.Print_rc()
  return ba[:out_len], conn.Last_err
}

func (conn *Connection)UnWrapData(key_id uint16, in []byte, max_out_len int) ([]byte, YH_rc) {
  ba := make([]byte, max_out_len)
  out_len := max_out_len
  conn.Last_err = YH_util_unwrap_data(conn.Session, key_id, in, len(in), ba, &out_len)
  conn.Print_rc()
  return ba[:out_len], conn.Last_err
}

func (conn *Connection)GetOpaque(object_id uint16, max_out_len int) ([]byte, YH_rc) {
  ba := make([]byte, max_out_len)
  out_len := max_out_len
  conn.Last_err = YH_util_get_opaque(conn.Session, object_id,  ba, &out_len)
  conn.Print_rc()
  return ba[:out_len], conn.Last_err
}

func (conn *Connection)ImportOpaque(object_id *uint16, capabilities string, algorithm YH_algorithm, in []byte) YH_rc {
  var yh_opaque_caps *YH_capabilities
  yh_opaque_caps, conn.Last_err = YH_string_to_capabilities(capabilities)
  conn.Print_rc()
  if conn.Last_err != YHR_SUCCESS {
    return conn.Last_err
  }
  conn.Last_err = YH_util_import_opaque(conn.Session, object_id, conn.Label, conn.NumDomains, yh_opaque_caps, algorithm, in, len(in))
  conn.Print_rc()
  return conn.Last_err
}
