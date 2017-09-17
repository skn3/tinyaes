#Import "<std>"
#Import "<tinyaes>"

Using tinyaes..
Using std..

Function Main:Void()
	Local value := "Φello world"
	Local key := "cat"'DOGwoofMEOW12"
	Local encrypted := AESEncrypt(value, key)
	Local decrypted := AESDecrypt(encrypted, key)
	
	Print "[results]"
	Print "value = "+value
	Print "key = "+key
	Print "encrypted = "+encrypted
	Print "decrypted = "+decrypted
End
