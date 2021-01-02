package main

import(
  "fmt"
  ygo "github.com/Pymann/yhsm2go"
  "reflect"
  "errors"
)

func main() {

  yubi_url := "yhusb://"
  auth_id := uint16(1)
  password := "password"
  var conn *ygo.YH_connector
  var sess *ygo.YH_session


  rc := ygo.YH_init()
  print_rc(rc)

  conn, rc = ygo.YH_init_connector(yubi_url)
  print_rc(rc)

  /*rc = ygo.YH_set_verbosity(conn, ygo.YH_VERB_ALL)
  print_rc(rc)*/

  fmt.Println("connecting...")
  rc = ygo.YH_connect(conn, 0)
  print_rc(rc)

  var major, minor, patch uint8
  var serial uint32
  var log_total, log_used uint8
  algorithms := make([]ygo.YH_algorithm, 100)
  var n_algorithms int = 100
  rc = ygo.YH_util_get_device_info(conn, &major, &minor, &patch, &serial, &log_total, &log_used, algorithms, &n_algorithms)
  print_rc(rc)
  fmt.Printf("Device Info:\nFirmware: %d.%d.%d\nSerial: %d\nLogs %d/%d\nAlgos[%d]: %d\n", major, minor, patch, serial, log_total, log_used, n_algorithms, algorithms[:n_algorithms])

  fmt.Println("getting session...")
  sess, rc = ygo.YH_create_session_derived(conn, auth_id, password, false)
  print_rc(rc)

  fmt.Println("authenticating...")
  rc = ygo.YH_authenticate_session(sess)
  print_rc(rc)

  var total_records, free_records, total_pages, free_pages, page_size uint16
  rc = ygo.YH_util_get_storage_info(sess, &total_records, &free_records, &total_pages, &free_pages, &page_size)
  print_rc(rc)
  fmt.Printf("total_records: %d\nfree_records: %d\ntotal_pages: %d\nfree_pages: %d\npage_size: %d\n", total_records, free_records, total_pages, free_pages, page_size)

  rlen := int(30)
  out_rlen := int(30)
  ba := make([]byte, out_rlen)
  fmt.Println("getting pseudo random...")
  rc = ygo.YH_util_get_pseudo_random(sess, rlen, ba, &out_rlen)
  print_rc(rc)
  fmt.Printf("out: %v\n", ba[:out_rlen])

  auth_id_new := uint16(0)
  label := "TestLabel"
  password_new := "43523452v342356b43v5234c234x4cx3y235c458n579m79m675v4"
  domains := uint16(0)
  rc = ygo.YH_string_to_domains("5", &domains)
  auth_caps := "reset-device|delete-authentication-key|exportable-under-wrap|export-wrapped|import-wrapped|unwrap-data|wrap-data|generate-asymmetric-key|generate-wrap-key|delete-wrap-key|get-log-entries|put-wrap-key|put-opaque|get-opaque|delete-opaque"
  del_auth_caps :=  "exportable-under-wrap|export-wrapped|import-wrapped|unwrap-data|wrap-data|delete-wrap-key|put-wrap-key|put-opaque|get-opaque|delete-opaque"

  yh_auth_caps, rc := ygo.YH_string_to_capabilities(auth_caps)
  del_yh_auth_caps, rc := ygo.YH_string_to_capabilities(del_auth_caps)
  print_rc(rc)
  rc = ygo.YH_util_import_authentication_key_derived(	sess,
  																								&auth_id_new,
  																								label,
  																								domains,
  																								yh_auth_caps, del_yh_auth_caps,
  																								password_new)
  print_rc(rc)
  fmt.Printf("new auth: %d\n", auth_id_new)

  rc = ygo.YH_util_close_session(sess)
  print_rc(rc)
  rc = ygo.YH_destroy_session(sess)
  print_rc(rc)
  rc = ygo.YH_disconnect(conn)
  print_rc(rc)
  rc = ygo.YH_exit()
  print_rc(rc)

  rc = ygo.YH_init()
  print_rc(rc)

  conn, rc = ygo.YH_init_connector(yubi_url)
  print_rc(rc)

  fmt.Println("connecting...")
  rc = ygo.YH_connect(conn, 0)
  print_rc(rc)

  fmt.Println("getting session...")
  sess, rc = ygo.YH_create_session_derived(conn, auth_id_new, password_new, false)
  print_rc(rc)

  fmt.Println("authenticating...")
  rc = ygo.YH_authenticate_session(sess)
  print_rc(rc)

  wkey_id := uint16(0)
  wkey_caps := "exportable-under-wrap|unwrap-data|wrap-data|delete-wrap-key|export-wrapped|import-wrapped"
  yh_wkey_caps, rc := ygo.YH_string_to_capabilities(wkey_caps)
  print_rc(rc)

  rc = ygo.YH_util_generate_wrap_key(sess, &wkey_id, label, domains, yh_wkey_caps, ygo.YH_ALGO_AES128_CCM_WRAP,yh_wkey_caps)
  print_rc(rc)
  fmt.Printf("new wkey: %d\n", wkey_id)

  bck_wkey_id := uint16(0)
  bck_wk := []byte{0x13, 0x4c, 0x99, 0x83, 0x44, 0x23, 0xab, 0xde, 0x12, 0xc3, 0xf0, 0x6d, 0x3a, 0x12, 0xbc, 0x01}
  rc = ygo.YH_util_import_wrap_key(sess, &bck_wkey_id, label, domains, yh_wkey_caps, ygo.YH_ALGO_AES128_CCM_WRAP,yh_wkey_caps, bck_wk, len(bck_wk))
  print_rc(rc)
  fmt.Printf("new bck_wkey: %d\n", bck_wkey_id)

  master := []byte{32, 113, 28, 66, 188, 105, 186, 112, 144, 99, 95, 110, 93, 146, 101, 122, 136, 119, 136, 183, 219, 208, 223, 212, 46, 160, 37, 71, 137, 169, 238, 48}
  wrapped_master_len := 1000
  wrapped_master := make([]byte, wrapped_master_len)
  rc = ygo.YH_util_wrap_data(sess, wkey_id, master, len(master), wrapped_master, &wrapped_master_len)
  print_rc(rc)
  fmt.Printf("wrapped-master: %v\n", wrapped_master[:wrapped_master_len])

  out_len_unwrap := int(100)
  unwrapped_master := make([]byte, out_len_unwrap)
  rc = ygo.YH_util_unwrap_data(sess, wkey_id, wrapped_master[:wrapped_master_len], wrapped_master_len, unwrapped_master, &out_len_unwrap)
  print_rc(rc)
  fmt.Printf("unwrapped-master: %v\n", unwrapped_master[:out_len_unwrap])

  if reflect.DeepEqual(unwrapped_master[:out_len_unwrap], master) {
    fmt.Printf("Normal- and wrapped-unwrapped-seed are deep-equal\n")
  } else {
    fmt.Printf("Normal- and wrapped-unwrapped-seed are NOT deep-equal\n")
  }

  export_wkey_len := 1000
  export_wkey := make([]byte, export_wkey_len)
  rc = ygo.YH_util_export_wrapped(sess, bck_wkey_id, ygo.YH_WRAP_KEY, wkey_id, export_wkey, &export_wkey_len)
  print_rc(rc)
  fmt.Printf("Exported Wrapkey: %v\n", export_wkey[:export_wkey_len])

  object_id := uint16(0)
  yh_opaque_caps, rc := ygo.YH_string_to_capabilities("exportable-under-wrap")
  print_rc(rc)
  rc = ygo.YH_util_import_opaque(sess, &object_id, label, domains, yh_opaque_caps, ygo.YH_ALGO_OPAQUE_DATA, wrapped_master, len(wrapped_master))
  print_rc(rc)

  get_opaque_len := 1000
  get_opaque := make([]byte, get_opaque_len)
  rc = ygo.YH_util_get_opaque(sess, object_id, get_opaque, &get_opaque_len)
  print_rc(rc)

  if reflect.DeepEqual(wrapped_master, get_opaque[:get_opaque_len]) {
    fmt.Printf("Imported and exported opaque are deep-equal\n")
  }

  rc = ygo.YH_util_close_session(sess)
  print_rc(rc)
  rc = ygo.YH_destroy_session(sess)
  print_rc(rc)
  rc = ygo.YH_disconnect(conn)
  print_rc(rc)
  rc = ygo.YH_exit()
  print_rc(rc)

}

func print_rc(rc ygo.YH_rc) {
  if rc != 0 {
    panic(errors.New(fmt.Sprintf("Error %d: %s\n",rc, ygo.YH_strerror(rc))))
  }
}
