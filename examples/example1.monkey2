#Import "<std>"
#Import "<tinyaes>"

Using tinyaes..
Using std..

Function Main:Void()
	Print "hello world"
	'Print  Mod 16
	
	Local value := "hello world"
	Local key := "catDOGwoofMEOW12"
	Local encrypted := AESEncrypt(value, key)
	Local decrypted := AESDecrypt(encrypted, key)
	
	Print "value = "+value
	Print "key = "+key
	Print "encrypted = "+encrypted
	Print "decrypted = "+decrypted
End