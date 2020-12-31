package yubihsm2


// Debug levels
/// Debug level quiet. No messages printed out
const (
  YH_VERB_QUIET uint8 = 0x00
  /// Debug level intermediate. Intermediate results printed out
  YH_VERB_INTERMEDIATE uint8 = 0x01
  /// Debug level crypto. Crypto results printed out
  YH_VERB_CRYPTO uint8 = 0x02
  /// Debug level raw. Raw messages printed out
  YH_VERB_RAW uint8 = 0x04
  /// Debug level info. General information messages printed out
  YH_VERB_INFO uint8 = 0x08
  /// Debug level error. Error messages printed out
  YH_VERB_ERR uint8 = 0x10
  /// Debug level all. All previous options enabled
  YH_VERB_ALL uint8 = 0xff
)

/**
 * Options for the connector, set with yh_set_connector_option()
 */
type YH_connector_option int
const (
  /// File with CA certificate to validate the connector with (const char *).
  /// Not implemented on Windows
  YH_CONNECTOR_HTTPS_CA YH_connector_option = 1
  /// Proxy server to use for connecting to the connector (const char *). Not
  /// implemented on Windows
  YH_CONNECTOR_PROXY_SERVER YH_connector_option = 2
)

/**
 * Global options
 */
type YH_option int
const (
  /// Enable/Disable Forced Audit mode
  YH_OPTION_FORCE_AUDIT YH_option = 1
  /// Enable/Disable logging of specific commands
  YH_OPTION_COMMAND_AUDIT YH_option = 3
)



type YH_rc int
const (
  /// Returned value when function was successful
  YHR_SUCCESS YH_rc  = 0
  /// Returned value when unable to allocate memory
  YHR_MEMORY_ERROR YH_rc = -1
  /// Returned value when failing to initialize libyubihsm
  YHR_INIT_ERROR YH_rc = -2
  /// Returned value when a connection error was encountered
  YHR_CONNECTION_ERROR YH_rc = -3
  /// Returned value when failing to find a suitable connector
  YHR_CONNECTOR_NOT_FOUND YH_rc = -4
  /// Returned value when an argument to a function is invalid
  YHR_INVALID_PARAMETERS YH_rc = -5
  /// Returned value when there is a mismatch between expected and received
  /// length of an argument to a function
  YHR_WRONG_LENGTH YH_rc = -6
  /// Returned value when there is not enough space to store data
  YHR_BUFFER_TOO_SMALL YH_rc = -7
  /// Returned value when failing to verify cryptogram
  YHR_CRYPTOGRAM_MISMATCH YH_rc = -8
  /// Returned value when failing to authenticate the session
  YHR_SESSION_AUTHENTICATION_FAILED YH_rc = -9
  /// Returned value when failing to verify MAC
  YHR_MAC_MISMATCH YH_rc = -10
  /// Returned value when the device returned no error
  YHR_DEVICE_OK YH_rc = -11
  /// Returned value when the device receives and invalid command
  YHR_DEVICE_INVALID_COMMAND YH_rc = -12
  /// Returned value when the device receives a malformed command invalid data
  YHR_DEVICE_INVALID_DATA YH_rc = -13
  /// Returned value when the device session is invalid
  YHR_DEVICE_INVALID_SESSION YH_rc = -14
  /// Return value when the device fails to encrypt or verify the message
  YHR_DEVICE_AUTHENTICATION_FAILED YH_rc = -15
  /// Return value when no more sessions can be opened on the device
  YHR_DEVICE_SESSIONS_FULL YH_rc = -16
  /// Return value when failing to create a device session
  YHR_DEVICE_SESSION_FAILED YH_rc = -17
  /// Return value when encountering a storage failure on the device
  YHR_DEVICE_STORAGE_FAILED YH_rc = -18
  /// Return value when there is a mismatch between expected and received
  /// length of an argument to a function on the device
  YHR_DEVICE_WRONG_LENGTH YH_rc = -19
  /// Return value when the permissions to perform the operation are wrong
  YHR_DEVICE_INSUFFICIENT_PERMISSIONS YH_rc = -20
  /// Return value when the log buffer is full and forced audit is set
  YHR_DEVICE_LOG_FULL YH_rc = -21
  /// Return value when the object not found on the device
  YHR_DEVICE_OBJECT_NOT_FOUND YH_rc = -22
  /// Return value when an invalid Object ID is used
  YHR_DEVICE_INVALID_ID YH_rc = -23
  /// Return value when an invalid OTP is submitted
  YHR_DEVICE_INVALID_OTP YH_rc = -24
  /// Return value when the device is in demo mode and has to be power cycled
  YHR_DEVICE_DEMO_MODE YH_rc = -25
  /// Return value when the command execution has not terminated
  YHR_DEVICE_COMMAND_UNEXECUTED YH_rc = -26
  /// Return value when encountering an unknown error
  YHR_GENERIC_ERROR YH_rc = -27
  /// Return value when trying to add an object with an ID that already exists
  YHR_DEVICE_OBJECT_EXISTS YH_rc = -28
  /// Return value when connector operation failed
  YHR_CONNECTOR_ERROR YH_rc = -29
  /// Return value when encountering SSH CA constraint violation
  YHR_DEVICE_SSH_CA_CONSTRAINT_VIOLATION YH_rc = -30
)

/**
 * Object types
 *
 * @see <a
 * hrefYH_rc ="https://developers.yubico.com/YubiHSM2/Concepts/Object.html">Objects</a>
 */

type YH_object_type int
const (
  /// Opaque Object is an unchecked kind of Object normally used to store
  /// raw data in the device
  YH_OPAQUE YH_object_type = 0x01
  /// Authentication Key is used to establish Sessions with a device
  YH_AUTHENTICATION_KEY YH_object_type = 0x02
  /// Asymmetric Key is the private key of an asymmetric key-pair
  YH_ASYMMETRIC_KEY YH_object_type = 0x03
  /// Wrap Key is a secret key used to wrap and unwrap Objects during the
  /// export and import process
  YH_WRAP_KEY YH_object_type = 0x04
  /// HMAC Key is a secret key used when computing and verifying HMAC signatures
  YH_HMAC_KEY YH_object_type = 0x05
  /// Template is a binary object used for example to validate SSH certificate
  /// requests
  YH_TEMPLATE YH_object_type = 0x06
  /// OTP AEAD Key is a secret key used to decrypt Yubico OTP values
  YH_OTP_AEAD_KEY YH_object_type = 0x07
  /// Public Key is the public key of an asymmetric key-pair. The public key
  /// never exists in device and is mostly here for PKCS#11.
  YH_PUBLIC_KEY YH_object_type = 0x83
)



/**
 * Algorithms
 *
 * @see <a
 * hrefYH_rc ="https://developers.yubico.com/YubiHSM2/Concepts/Algorithms.html">Objects</a>
 */
type YH_algorithm int32

const (
  /// rsa-pkcs1-sha1
  YH_ALGO_RSA_PKCS1_SHA1 YH_algorithm = 1
  /// rsa-pkcs1-sha256
  YH_ALGO_RSA_PKCS1_SHA256 YH_algorithm = 2
  /// rsa-pkcs1-sha384
  YH_ALGO_RSA_PKCS1_SHA384 YH_algorithm = 3
  /// rsa-pkcs1-sha512
  YH_ALGO_RSA_PKCS1_SHA512 YH_algorithm = 4
  /// rsa-pss-sha1
  YH_ALGO_RSA_PSS_SHA1 YH_algorithm = 5
  /// rsa-pss-sha256
  YH_ALGO_RSA_PSS_SHA256 YH_algorithm = 6
  /// rsa-pss-sha384
  YH_ALGO_RSA_PSS_SHA384 YH_algorithm = 7
  /// rsa-pss-sha512
  YH_ALGO_RSA_PSS_SHA512 YH_algorithm = 8
  /// rsa2048
  YH_ALGO_RSA_2048 YH_algorithm = 9
  /// rsa3072
  YH_ALGO_RSA_3072 YH_algorithm = 10
  /// rsa4096
  YH_ALGO_RSA_4096 YH_algorithm = 11
  /// ecp256
  YH_ALGO_EC_P256 YH_algorithm = 12
  /// ecp384
  YH_ALGO_EC_P384 YH_algorithm = 13
  /// ecp521
  YH_ALGO_EC_P521 YH_algorithm = 14
  /// eck256
  YH_ALGO_EC_K256 YH_algorithm = 15
  /// ecbp256
  YH_ALGO_EC_BP256 YH_algorithm = 16
  /// ecbp384
  YH_ALGO_EC_BP384 YH_algorithm = 17
  /// ecbp512
  YH_ALGO_EC_BP512 YH_algorithm = 18
  /// hmac-sha1
  YH_ALGO_HMAC_SHA1 YH_algorithm = 19
  /// hmac-sha256
  YH_ALGO_HMAC_SHA256 YH_algorithm = 20
  /// hmac-sha384
  YH_ALGO_HMAC_SHA384 YH_algorithm = 21
  /// hmac-sha512
  YH_ALGO_HMAC_SHA512 YH_algorithm = 22
  /// ecdsa-sha1
  YH_ALGO_EC_ECDSA_SHA1 YH_algorithm = 23
  /// ecdh
  YH_ALGO_EC_ECDH YH_algorithm = 24
  /// rsa-oaep-sha1
  YH_ALGO_RSA_OAEP_SHA1 YH_algorithm = 25
  /// rsa-oaep-sha256
  YH_ALGO_RSA_OAEP_SHA256 YH_algorithm = 26
  /// rsa-oaep-sha384
  YH_ALGO_RSA_OAEP_SHA384 YH_algorithm = 27
  /// rsa-oaep-sha512
  YH_ALGO_RSA_OAEP_SHA512 YH_algorithm = 28
  /// aes128-ccm-wrap
  YH_ALGO_AES128_CCM_WRAP YH_algorithm = 29
  /// opaque-data
  YH_ALGO_OPAQUE_DATA YH_algorithm = 30
  /// opaque-x509-certificate
  YH_ALGO_OPAQUE_X509_CERTIFICATE YH_algorithm = 31
  /// mgf1-sha1
  YH_ALGO_MGF1_SHA1 YH_algorithm = 32
  /// mgf1-sha256
  YH_ALGO_MGF1_SHA256 YH_algorithm = 33
  /// mgf1-sha384
  YH_ALGO_MGF1_SHA384 YH_algorithm = 34
  /// mgf1-sha512
  YH_ALGO_MGF1_SHA512 YH_algorithm = 35
  /// template-ssh
  YH_ALGO_TEMPLATE_SSH YH_algorithm = 36
  /// aes128-yubico-otp
  YH_ALGO_AES128_YUBICO_OTP YH_algorithm = 37
  /// aes128-yubico-authentication
  YH_ALGO_AES128_YUBICO_AUTHENTICATION YH_algorithm = 38
  /// aes192-yubico-otp
  YH_ALGO_AES192_YUBICO_OTP YH_algorithm = 39
  /// aes256-yubico-otp
  YH_ALGO_AES256_YUBICO_OTP YH_algorithm = 40
  /// aes192-ccm-wrap
  YH_ALGO_AES192_CCM_WRAP YH_algorithm = 41
  /// aes256-ccm-wrap
  YH_ALGO_AES256_CCM_WRAP YH_algorithm = 42
  /// ecdsa-sha256
  YH_ALGO_EC_ECDSA_SHA256 YH_algorithm = 43
  /// ecdsa-sha384
  YH_ALGO_EC_ECDSA_SHA384 YH_algorithm = 44
  /// ecdsa-sha512
  YH_ALGO_EC_ECDSA_SHA512 YH_algorithm = 45
  /// ed25519
  YH_ALGO_EC_ED25519 YH_algorithm = 46
  /// ecp224
  YH_ALGO_EC_P224 YH_algorithm = 47

  YH_MAX_ALGORITHM_COUNT YH_algorithm = 0xff
)
