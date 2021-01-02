package yhsm2go

const (
  /// Length of context array for authentication
  YH_CONTEXT_LEN uint16 = 16
  /// Length of host challenge for authentication
  YH_HOST_CHAL_LEN uint16 = 8
  /// Maximum length of message buffer
  YH_MSG_BUF_SIZE uint16 = 2048
  /// Length of authentication keys
  YH_KEY_LEN uint16 = 16
  /// Device vendor ID
  YH_VID uint16 = 0x1050
  /// Device product ID
  YH_PID uint16 = 0x0030
  /// Response flag for commands
  YH_CMD_RESP_FLAG uint16 = 0x80
  /// Max items the device may hold
  YH_MAX_ITEMS_COUNT uint16 = 256
  /// Max sessions the device may hold
  YH_MAX_SESSIONS uint16 = 16
  /// Default encryption key
  YH_DEFAULT_ENC_KEY string = `\x09\x0b\x47\xdb\xed\x59\x56\x54\x90\x1d\xee\x1c\xc6\x55\xe4\x20`
  /// Default MAC key
  YH_DEFAULT_MAC_KEY string = `\x59\x2f\xd4\x83\xf7\x59\xe2\x99\x09\xa0\x4c\x45\x05\xd2\xce\x0a`
  /// Default authentication key password
  YH_DEFAULT_PASSWORD string = "password"
  /// Salt to be used for PBKDF2 key derivation
  YH_DEFAULT_SALT string = "Yubico"
  /// Number of iterations for PBKDF2 key derivation
  YH_DEFAULT_ITERS uint16 = 10000
  /// Length of capabilities array
  YH_CAPABILITIES_LEN uint16 = 8
  /// Max log entries the device may hold
  YH_MAX_LOG_ENTRIES uint16 = 64
  /// Max length of object labels
  YH_OBJ_LABEL_LEN uint16 = 40
  /// Max number of domains
  YH_MAX_DOMAINS uint16 = 16
  /// Size that the log digest is truncated to
  YH_LOG_DIGEST_SIZE uint16 = 16
  /// URL scheme used for direct USB access
  YH_USB_URL_SCHEME string = "yhusb://"
)

// Debug levels
const (
  /// Debug level quiet. No messages printed out
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

const (
/// This is the overhead when doing aes-ccm wrapping: 1 byte identifier, 13
/// bytes nonce and 16 bytes mac
  YH_CCM_WRAP_OVERHEAD uint8 = (1 + 13 + 16)
)

/**
 * Options for the connector, set with yh_set_connector_option()
 */
type YH_connector_option int32
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
type YH_option int32
const (
  /// Enable/Disable Forced Audit mode
  YH_OPTION_FORCE_AUDIT YH_option = 1
  /// Enable/Disable logging of specific commands
  YH_OPTION_COMMAND_AUDIT YH_option = 3
)



type YH_rc int32
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

type YH_object_type int32
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


/// Max number of algorithms defined here
const (
  YH_MAX_ALGORITHM_COUNT uint8 = 0xff
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
)

/**
 * Command definitions
 */
type YH_cmd int32
const (
  /// Echo data back from the device.
  YHC_ECHO YH_cmd = 0x01
  YHC_ECHO_R YH_cmd = YHC_ECHO | YH_cmd(YH_CMD_RESP_FLAG)
  /// Create a session with the device.
  YHC_CREATE_SESSION YH_cmd = 0x03
  YHC_CREATE_SESSION_R YH_cmd = YHC_CREATE_SESSION | YH_cmd(YH_CMD_RESP_FLAG)
  /// Authenticate the session to the device
  YHC_AUTHENTICATE_SESSION YH_cmd = 0x04
  YHC_AUTHENTICATE_SESSION_R YH_cmd = YHC_AUTHENTICATE_SESSION | YH_cmd(YH_CMD_RESP_FLAG)
  /// Send a command over an established session
  YHC_SESSION_MESSAGE YH_cmd = 0x05
  YHC_SESSION_MESSAGE_R YH_cmd = YHC_SESSION_MESSAGE | YH_cmd(YH_CMD_RESP_FLAG)
  /// Get device metadata
  YHC_GET_DEVICE_INFO YH_cmd = 0x06
  YHC_GET_DEVICE_INFO_R YH_cmd = YHC_GET_DEVICE_INFO | YH_cmd(YH_CMD_RESP_FLAG)
  /// Factory reset a device
  YHC_RESET_DEVICE YH_cmd = 0x08
  YHC_RESET_DEVICE_R YH_cmd = YHC_RESET_DEVICE | YH_cmd(YH_CMD_RESP_FLAG)
  /// Close session
  YHC_CLOSE_SESSION YH_cmd = 0x40
  YHC_CLOSE_SESSION_R YH_cmd = YHC_CLOSE_SESSION | YH_cmd(YH_CMD_RESP_FLAG)
  /// Get storage information
  YHC_GET_STORAGE_INFO YH_cmd = 0x041
  YHC_GET_STORAGE_INFO_R YH_cmd = YHC_GET_STORAGE_INFO | YH_cmd(YH_CMD_RESP_FLAG)
  /// Import an Opaque Object into the device
  YHC_PUT_OPAQUE YH_cmd = 0x42
  YHC_PUT_OPAQUE_R YH_cmd = YHC_PUT_OPAQUE | YH_cmd(YH_CMD_RESP_FLAG)
  /// Get an Opaque Object from device
  YHC_GET_OPAQUE YH_cmd = 0x43
  YHC_GET_OPAQUE_R YH_cmd = YHC_GET_OPAQUE | YH_cmd(YH_CMD_RESP_FLAG)
  /// Import an Authentication Key into the device
  YHC_PUT_AUTHENTICATION_KEY YH_cmd = 0x44
  YHC_PUT_AUTHENTICATION_KEY_R YH_cmd = YHC_PUT_AUTHENTICATION_KEY | YH_cmd(YH_CMD_RESP_FLAG)
  /// Import an Asymmetric Key into the device
  YHC_PUT_ASYMMETRIC_KEY YH_cmd = 0x45
  YHC_PUT_ASYMMETRIC_KEY_R YH_cmd = YHC_PUT_ASYMMETRIC_KEY | YH_cmd(YH_CMD_RESP_FLAG)
  /// Generate an Asymmetric Key in the device
  YHC_GENERATE_ASYMMETRIC_KEY YH_cmd = 0x46
  YHC_GENERATE_ASYMMETRIC_KEY_R YH_cmd = YHC_GENERATE_ASYMMETRIC_KEY | YH_cmd(YH_CMD_RESP_FLAG)
  /// Sign data using RSA-PKCS#1v1.5
  YHC_SIGN_PKCS1 YH_cmd = 0x47
  YHC_SIGN_PKCS1_R YH_cmd = YHC_SIGN_PKCS1 | YH_cmd(YH_CMD_RESP_FLAG)
  /// List objects in the device
  YHC_LIST_OBJECTS YH_cmd = 0x48
  YHC_LIST_OBJECTS_R YH_cmd = YHC_LIST_OBJECTS | YH_cmd(YH_CMD_RESP_FLAG)
  /// Decrypt data that was encrypted using RSA-PKCS#1v1.5
  YHC_DECRYPT_PKCS1 YH_cmd = 0x49
  YHC_DECRYPT_PKCS1_R YH_cmd = YHC_DECRYPT_PKCS1 | YH_cmd(YH_CMD_RESP_FLAG)
  /// Get an Object under wrap from the device.
  YHC_EXPORT_WRAPPED YH_cmd = 0x4a
  YHC_EXPORT_WRAPPED_R YH_cmd = YHC_EXPORT_WRAPPED | YH_cmd(YH_CMD_RESP_FLAG)
  /// Import a wrapped Object into the device
  YHC_IMPORT_WRAPPED YH_cmd = 0x4b
  YHC_IMPORT_WRAPPED_R YH_cmd = YHC_IMPORT_WRAPPED | YH_cmd(YH_CMD_RESP_FLAG)
  /// Import a Wrap Key into the device
  YHC_PUT_WRAP_KEY YH_cmd = 0x4c
  YHC_PUT_WRAP_KEY_R YH_cmd = YHC_PUT_WRAP_KEY | YH_cmd(YH_CMD_RESP_FLAG)
  /// Get all current audit log entries from the device Log Store
  YHC_GET_LOG_ENTRIES YH_cmd = 0x4d
  YHC_GET_LOG_ENTRIES_R YH_cmd = YHC_GET_LOG_ENTRIES | YH_cmd(YH_CMD_RESP_FLAG)
  /// Get all metadata about an Object
  YHC_GET_OBJECT_INFO YH_cmd = 0x4e
  YHC_GET_OBJECT_INFO_R YH_cmd = YHC_GET_OBJECT_INFO | YH_cmd(YH_CMD_RESP_FLAG)
  /// Set a device-global options that affect general behavior
  YHC_SET_OPTION YH_cmd = 0x4f
  YHC_SET_OPTION_R YH_cmd = YHC_SET_OPTION | YH_cmd(YH_CMD_RESP_FLAG)
  /// Get a device-global option
  YHC_GET_OPTION YH_cmd = 0x50
  YHC_GET_OPTION_R YH_cmd = YHC_GET_OPTION | YH_cmd(YH_CMD_RESP_FLAG)
  /// Get a fixed number of pseudo-random bytes from the device
  YHC_GET_PSEUDO_RANDOM YH_cmd = 0x51
  YHC_GET_PSEUDO_RANDOM_R YH_cmd = YHC_GET_PSEUDO_RANDOM | YH_cmd(YH_CMD_RESP_FLAG)
  /// Import a HMAC key into the device
  YHC_PUT_HMAC_KEY YH_cmd = 0x52
  YHC_PUT_HMAC_KEY_R YH_cmd = YHC_PUT_HMAC_KEY | YH_cmd(YH_CMD_RESP_FLAG)
  /// Perform an HMAC operation in the device
  YHC_SIGN_HMAC YH_cmd = 0x53
  YHC_SIGN_HMAC_R YH_cmd = YHC_SIGN_HMAC | YH_cmd(YH_CMD_RESP_FLAG)
  /// Get the public key of an Asymmetric Key in the device
  YHC_GET_PUBLIC_KEY YH_cmd = 0x54
  YHC_GET_PUBLIC_KEY_R YH_cmd = YHC_GET_PUBLIC_KEY | YH_cmd(YH_CMD_RESP_FLAG)
  /// Sign data using RSA-PSS
  YHC_SIGN_PSS YH_cmd = 0x55
  YHC_SIGN_PSS_R YH_cmd = YHC_SIGN_PSS | YH_cmd(YH_CMD_RESP_FLAG)
  /// Sign data using ECDSA
  YHC_SIGN_ECDSA YH_cmd = 0x56
  YHC_SIGN_ECDSA_R YH_cmd = YHC_SIGN_ECDSA | YH_cmd(YH_CMD_RESP_FLAG)
  /// Perform an ECDH key exchange operation with a private key in the device
  YHC_DERIVE_ECDH YH_cmd = 0x57
  YHC_DERIVE_ECDH_R YH_cmd = YHC_DERIVE_ECDH | YH_cmd(YH_CMD_RESP_FLAG)
  /// Delete object in the device
  YHC_DELETE_OBJECT YH_cmd = 0x58
  YHC_DELETE_OBJECT_R YH_cmd = YHC_DELETE_OBJECT | YH_cmd(YH_CMD_RESP_FLAG)
  /// Decrypt data using RSA-OAEP
  YHC_DECRYPT_OAEP YH_cmd = 0x59
  YHC_DECRYPT_OAEP_R YH_cmd = YHC_DECRYPT_OAEP | YH_cmd(YH_CMD_RESP_FLAG)
  /// Generate an HMAC Key in the device
  YHC_GENERATE_HMAC_KEY YH_cmd = 0x5a
  YHC_GENERATE_HMAC_KEY_R YH_cmd = YHC_GENERATE_HMAC_KEY | YH_cmd(YH_CMD_RESP_FLAG)
  /// Generate a Wrap Key in the device
  YHC_GENERATE_WRAP_KEY YH_cmd = 0x5b
  YHC_GENERATE_WRAP_KEY_R YH_cmd = YHC_GENERATE_WRAP_KEY | YH_cmd(YH_CMD_RESP_FLAG)
  /// Verify a generated HMAC
  YHC_VERIFY_HMAC YH_cmd = 0x5c
  YHC_VERIFY_HMAC_R YH_cmd = YHC_VERIFY_HMAC | YH_cmd(YH_CMD_RESP_FLAG)
  /// Sign SSH certificate request
  YHC_SIGN_SSH_CERTIFICATE YH_cmd = 0x5d
  YHC_SIGN_SSH_CERTIFICATE_R YH_cmd = YHC_SIGN_SSH_CERTIFICATE | YH_cmd(YH_CMD_RESP_FLAG)
  /// Import a template into the device
  YHC_PUT_TEMPLATE YH_cmd = 0x5e
  YHC_PUT_TEMPLATE_R YH_cmd = YHC_PUT_TEMPLATE | YH_cmd(YH_CMD_RESP_FLAG)
  /// Get a template from the device
  YHC_GET_TEMPLATE YH_cmd = 0x5f
  YHC_GET_TEMPLATE_R YH_cmd = YHC_GET_TEMPLATE | YH_cmd(YH_CMD_RESP_FLAG)
  /// Decrypt a Yubico OTP
  YHC_DECRYPT_OTP YH_cmd = 0x60
  YHC_DECRYPT_OTP_R YH_cmd = YHC_DECRYPT_OTP | YH_cmd(YH_CMD_RESP_FLAG)
  /// Create a Yubico OTP AEAD
  YHC_CREATE_OTP_AEAD YH_cmd = 0x61
  YHC_CREATE_OTP_AEAD_R YH_cmd = YHC_CREATE_OTP_AEAD | YH_cmd(YH_CMD_RESP_FLAG)
  /// Generate an OTP AEAD from random data
  YHC_RANDOMIZE_OTP_AEAD YH_cmd = 0x62
  YHC_RANDOMIZE_OTP_AEAD_R YH_cmd = YHC_RANDOMIZE_OTP_AEAD | YH_cmd(YH_CMD_RESP_FLAG)
  /// Re-encrypt a Yubico OTP AEAD from one OTP AEAD Key to another OTP AEAD Key
  YHC_REWRAP_OTP_AEAD YH_cmd = 0x63
  YHC_REWRAP_OTP_AEAD_R YH_cmd = YHC_REWRAP_OTP_AEAD | YH_cmd(YH_CMD_RESP_FLAG)
  /// Get attestation of an Asymmetric Key
  YHC_SIGN_ATTESTATION_CERTIFICATE YH_cmd = 0x64
  YHC_SIGN_ATTESTATION_CERTIFICATE_R YH_cmd = YHC_SIGN_ATTESTATION_CERTIFICATE | YH_cmd(YH_CMD_RESP_FLAG)
  /// Import an OTP AEAD Key into the device
  YHC_PUT_OTP_AEAD_KEY YH_cmd = 0x65
  YHC_PUT_OTP_AEAD_KEY_R YH_cmd = YHC_PUT_OTP_AEAD_KEY | YH_cmd(YH_CMD_RESP_FLAG)
  /// Generate an OTP AEAD Key in the device
  YHC_GENERATE_OTP_AEAD_KEY YH_cmd = 0x66
  YHC_GENERATE_OTP_AEAD_KEY_R YH_cmd = YHC_GENERATE_OTP_AEAD_KEY | YH_cmd(YH_CMD_RESP_FLAG)
  /// Set the last extracted audit log entry
  YHC_SET_LOG_INDEX YH_cmd = 0x67
  YHC_SET_LOG_INDEX_R YH_cmd = YHC_SET_LOG_INDEX | YH_cmd(YH_CMD_RESP_FLAG)
  /// Encrypt (wrap) data using a Wrap Key
  YHC_WRAP_DATA YH_cmd = 0x68
  YHC_WRAP_DATA_R YH_cmd = YHC_WRAP_DATA | YH_cmd(YH_CMD_RESP_FLAG)
  /// Decrypt (unwrap) data using a Wrap Key
  YHC_UNWRAP_DATA YH_cmd = 0x69
  YHC_UNWRAP_DATA_R YH_cmd = YHC_UNWRAP_DATA | YH_cmd(YH_CMD_RESP_FLAG)
  /// Sign data using EdDSA
  YHC_SIGN_EDDSA YH_cmd = 0x6a
  YHC_SIGN_EDDSA_R YH_cmd = YHC_SIGN_EDDSA | YH_cmd(YH_CMD_RESP_FLAG)
  /// Blink the LED of the device
  YHC_BLINK_DEVICE YH_cmd = 0x6b
  YHC_BLINK_DEVICE_R YH_cmd = YHC_BLINK_DEVICE | YH_cmd(YH_CMD_RESP_FLAG)
  /// Replace the Authentication Key used to establish the current Session.
  YHC_CHANGE_AUTHENTICATION_KEY YH_cmd = 0x6c
  YHC_CHANGE_AUTHENTICATION_KEY_R YH_cmd = YHC_CHANGE_AUTHENTICATION_KEY | YH_cmd(YH_CMD_RESP_FLAG)
  /// The response byte returned from the device if the command resulted in an
  /// error
  YHC_ERROR YH_cmd = 0x7f
)

var YH_capability = map[string]uint8{
  "change-authentication-key": 0x2e,
  "create-otp-aead": 0x1e,
  "decrypt-oaep": 0x0a,
  "decrypt-otp": 0x1d,
  "decrypt-pkcs": 0x09,
  "delete-asymmetric-key": 0x29,
  "delete-authentication-key": 0x28,
  "delete-hmac-key": 0x2b,
  "delete-opaque": 0x27,
  "delete-otp-aead-key": 0x2d,
  "delete-template": 0x2c,
  "delete-wrap-key": 0x2a,
  "derive-ecdh": 0x0b,
  "export-wrapped": 0x0c,
  "exportable-under-wrap": 0x10,
  "generate-asymmetric-key": 0x04,
  "generate-hmac-key": 0x15,
  "generate-otp-aead-key": 0x24,
  "generate-wrap-key": 0x0f,
  "get-log-entries": 0x18,
  "get-opaque": 0x00,
  "get-option": 0x12,
  "get-pseudo-random": 0x13,
  "get-template": 0x1a,
  "import-wrapped": 0x0d,
  "put-asymmetric-key": 0x03,
  "put-authentication-key": 0x02,
  "put-mac-key": 0x14,
  "put-opaque": 0x01,
  "put-otp-aead-key": 0x23,
  "put-template": 0x1b,
  "put-wrap-key": 0x0e,
  "randomize-otp-aead": 0x1f,
  "reset-device": 0x1c,
  "rewrap-from-otp-aead-key": 0x20,
  "rewrap-to-otp-aead-key": 0x21,
  "set-option": 0x11,
  "sign-attestation-certificate": 0x22,
  "sign-ecdsa": 0x07,
  "sign-eddsa": 0x08,
  "sign-hmac": 0x16,
  "sign-pkcs": 0x05,
  "sign-pss": 0x06,
  "sign-ssh-certificate": 0x19,
  "unwrap-data": 0x26,
  "verify-hmac": 0x17,
  "wrap-data": 0x25}

var YH_algorithms = map[string]YH_algorithm{
  "aes128-ccm-wrap": YH_ALGO_AES128_CCM_WRAP,
  "aes128-yubico-authentication": YH_ALGO_AES128_YUBICO_AUTHENTICATION,
  "aes128-yubico-otp": YH_ALGO_AES128_YUBICO_OTP,
  "aes192-ccm-wrap": YH_ALGO_AES192_CCM_WRAP,
  "aes192-yubico-otp": YH_ALGO_AES192_YUBICO_OTP,
  "aes256-ccm-wrap": YH_ALGO_AES256_CCM_WRAP,
  "aes256-yubico-otp": YH_ALGO_AES256_YUBICO_OTP,
  "ecbp256": YH_ALGO_EC_BP256,
  "ecbp384": YH_ALGO_EC_BP384,
  "ecbp512": YH_ALGO_EC_BP512,
  "ecdh": YH_ALGO_EC_ECDH,
  "ecdsa-sha1": YH_ALGO_EC_ECDSA_SHA1,
  "ecdsa-sha256": YH_ALGO_EC_ECDSA_SHA256,
  "ecdsa-sha384": YH_ALGO_EC_ECDSA_SHA384,
  "ecdsa-sha512": YH_ALGO_EC_ECDSA_SHA512,
  "eck256": YH_ALGO_EC_K256,
  "ecp224": YH_ALGO_EC_P224,
  "ecp256": YH_ALGO_EC_P256,
  "ecp384": YH_ALGO_EC_P384,
  "ecp521": YH_ALGO_EC_P521,
  "ed25519": YH_ALGO_EC_ED25519,
  "hmac-sha1": YH_ALGO_HMAC_SHA1,
  "hmac-sha256": YH_ALGO_HMAC_SHA256,
  "hmac-sha384": YH_ALGO_HMAC_SHA384,
  "hmac-sha512": YH_ALGO_HMAC_SHA512,
  "mgf1-sha1": YH_ALGO_MGF1_SHA1,
  "mgf1-sha256": YH_ALGO_MGF1_SHA256,
  "mgf1-sha384": YH_ALGO_MGF1_SHA384,
  "mgf1-sha512": YH_ALGO_MGF1_SHA512,
  "opaque-data": YH_ALGO_OPAQUE_DATA,
  "opaque-x509-certificate": YH_ALGO_OPAQUE_X509_CERTIFICATE,
  "rsa-oaep-sha1": YH_ALGO_RSA_OAEP_SHA1,
  "rsa-oaep-sha256": YH_ALGO_RSA_OAEP_SHA256,
  "rsa-oaep-sha384": YH_ALGO_RSA_OAEP_SHA384,
  "rsa-oaep-sha512": YH_ALGO_RSA_OAEP_SHA512,
  "rsa-pkcs1-sha1": YH_ALGO_RSA_PKCS1_SHA1,
  "rsa-pkcs1-sha256": YH_ALGO_RSA_PKCS1_SHA256,
  "rsa-pkcs1-sha384": YH_ALGO_RSA_PKCS1_SHA384,
  "rsa-pkcs1-sha512": YH_ALGO_RSA_PKCS1_SHA512,
  "rsa-pss-sha1": YH_ALGO_RSA_PSS_SHA1,
  "rsa-pss-sha256": YH_ALGO_RSA_PSS_SHA256,
  "rsa-pss-sha384": YH_ALGO_RSA_PSS_SHA384,
  "rsa-pss-sha512": YH_ALGO_RSA_PSS_SHA512,
  "rsa2048": YH_ALGO_RSA_2048,
  "rsa3072": YH_ALGO_RSA_3072,
  "rsa4096": YH_ALGO_RSA_4096,
  "template-ssh": YH_ALGO_TEMPLATE_SSH}

var YH_types = map[string]YH_object_type{
  "authentication-key": YH_AUTHENTICATION_KEY,
  "asymmetric-key": YH_ASYMMETRIC_KEY,
  "hmac-key": YH_HMAC_KEY,
  "opaque": YH_OPAQUE,
  "otp-aead-key": YH_OTP_AEAD_KEY,
  "template": YH_TEMPLATE,
  "wrap-key": YH_WRAP_KEY}

var YH_options = map[string]YH_option{
  "command-audit": YH_OPTION_COMMAND_AUDIT,
  "force-audit": YH_OPTION_FORCE_AUDIT}


const (
/// The object was generated on the device
 YH_ORIGIN_GENERATED uint8 = 0x01
/// The object was imported into the device
 YH_ORIGIN_IMPORTED uint8 = 0x02
/// The object was imported into the device under wrap. This is used in
/// combination with objects original 'origin'
 YH_ORIGIN_IMPORTED_WRAPPED uint8 = 0x10
)
