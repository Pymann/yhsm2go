# yubihsm2
This repository is a golang wrapper of yubihsm2 library from yubico.com.

Just install the libraries from yubico: https://developers.yubico.com/YubiHSM2/Releases/
I recommend to take the latest release.

Then you can go install github.com/Pymann/yubihsm2/hsm_check and run compiled binary 'hsm_check' in your <GOPATH>/bin - folder.
This binary will perform a test for the golang wrapper and prove its working.
  
Also class 'Connection' in yubihsm2_conn.go, that wraps session interactions, bringing some convenience, is available.
