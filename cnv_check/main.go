package main

import(
  "fmt"
  ygo "github.com/Pymann/yhsm2go"
  "errors"
)

func print_rc(rc ygo.YH_rc) {
  if rc != 0 {
    panic(errors.New(fmt.Sprintf("Error %d: %s\n",rc, ygo.YH_strerror(rc))))
  }
}

func main() {
  domains := uint16(0)
  rc := ygo.YH_string_to_domains("1", &domains)
  print_rc(rc)
  fmt.Printf("'1' -> %d\n", domains)
  domains_str := string("Error")
  rc = ygo.YH_domains_to_string(domains, &domains_str, 10)
  print_rc(rc)
  fmt.Printf("1 -> '%s'\n", domains_str)

  object_str := string("Error")
  otype := ygo.YH_ASYMMETRIC_KEY
  rc = ygo.YH_type_to_string(otype, &object_str)
  fmt.Printf("%d -> '%s'\n", otype, object_str)

  var object_type ygo.YH_object_type
  rc = ygo.YH_string_to_type(object_str, &object_type)
  fmt.Printf("'%s' -> %d\n", object_str, object_type)

  algo_str := string("Error")
  algo := ygo.YH_ALGO_RSA_PSS_SHA384
  rc = ygo.YH_algo_to_string(algo, &algo_str)
  fmt.Printf("%d -> '%s'\n", algo, algo_str)

}
