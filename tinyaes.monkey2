Namespace tinyaes
 
#Import "<libc>"
#Import "<std>"
#Import "<monkey>"

#Import "lib/aes.h"
#Import "lib/aes.c"

Using libc.. 
Using std.memory
Using std.stringio
Using monkey.math
 
Extern
 
Function AES_ECB_encrypt:Void(input:UByte Ptr, key:UByte Ptr, output:UByte Ptr, length:UInt)	
Function AES_ECB_decrypt:Void(input:UByte Ptr, key:UByte Ptr, output:UByte Ptr, length:UInt)
Function AES_CBC_encrypt_buffer:Void(output:UByte Ptr, input:UByte Ptr, length:UInt, key:UByte Ptr, iv:UByte Ptr)
Function AES_CBC_decrypt_buffer:Void(output:UByte Ptr, input:UByte Ptr, length:UInt, key:UByte Ptr, iv:UByte Ptr)
	
Private

Const BLOCK_SIZE := 128
Const PAD_CHAR := String.FromChar(0)
Const KEY_SIZE := BLOCK_SIZE / 8

'helpers
#rem
Function PrintBuffer:Void(buffer:DataBuffer, label:String="buffer")
	Local build := label+" = "
	For Local index := 0 Until buffer.Length
		If index > 0
			build += ", "
		Endif
		build += Hex(buffer.PeekUByte(index))
	Next
	Print build
End
#end

Function FillBuffer:Void(buffer:DataBuffer, value:UByte)
	For Local index := 0 Until buffer.Length
		buffer.PokeUByte(index, value)
	Next
End

Function BufferFromString:DataBuffer(value:String, unicode:Bool)
	Local buffer:DataBuffer
	
	If unicode
		'copy wide chars too
		buffer = New DataBuffer(value.CStringLength)
		buffer.PokeString(0, value)
	Else
		'just a byte buffer
		buffer = New DataBuffer(value.Length)
		
		For Local index := 0 Until value.Length
			buffer.PokeUByte(index, value[index])
		Next
	Endif
	
	'toot!
	Return buffer
End

Function ProcessWithBuffer:DataBuffer(encrypt:Bool, unicode:Bool, input:DataBuffer, key:String, keySize:Int)
	'verify the key
	Local bufferKey := BufferFromString(key, unicode)
	If bufferKey.Length <> keySize
		'simple check for unicode in key
		If bufferKey.Length <> key.Length
			Throw New AESError("invalid key size (possible unicode in key)")
		Else
			Throw New AESError("invalid key size")
		Endif
	Endif
		
	'create chunk buffers
	Local bufferChunk := New DataBuffer(keySize)
	Local bufferAES := New DataBuffer(keySize)
	
	'calculate some stuff
	Local chunksTotal:Int = Ceil(Float(input.Length) / keySize)
	
	'create output buffer
	Local bufferOutput := New DataBuffer(chunksTotal * keySize)
	
	'iterate chunks
	For Local chunk := 0 Until chunksTotal
		Local chunkOffset := (chunk*keySize)
		Local chunkSize := Min(keySize, input.Length-chunkOffset)
		
		'empty and fill the chunk buffer
		FillBuffer(bufferChunk, 0)
		input.CopyTo(bufferChunk, chunkOffset, 0, chunkSize)
		
		'AES time
		If encrypt
			AES_ECB_encrypt(bufferChunk.Data, bufferKey.Data, bufferAES.Data, keySize)
		Else
			AES_ECB_decrypt(bufferChunk.Data, bufferKey.Data, bufferAES.Data, keySize)
		Endif
		
		'dump chunk aes into output
		bufferAES.CopyTo(bufferOutput, 0, chunkOffset, keySize)
	Next
	
	'cleanup
	bufferChunk.Discard()
	bufferAES.Discard()
	bufferKey.Discard()
	
	'woot :D
	Return bufferOutput
End

Function ProcessWithString:String(encrypt:Bool, unicode:Bool, input:String, key:String, keySize:Int)
	'create input buffer (if we are decrypting then this will never be in unicode)
	Local bufferInput := BufferFromString(input, encrypt And unicode)
	
	'process and fetch output buffer
	Local bufferOutput := ProcessWithBuffer(encrypt, unicode, bufferInput, key, keySize)
	
	'convert the output into a string
	Local result := bufferOutput.PeekString(0)
	
	'cleanup
	bufferOutput.Discard()
	
	'woot :D
	Return result
End
	
Public

'errors
Class AESError Extends Throwable
	Field msg:String
		
	Method New(msg:String)
		Self.msg = msg
	End
	
	Method ToString:String() Virtual
		Return msg
	End
End

'glue/api code
Function AESEncrypt:String(input:String, key:String)
	Return ProcessWithString(True, True, input, key, KEY_SIZE)
End

Function AESDecrypt:String(input:String, key:String)
	Return ProcessWithString(False, True, input, key, KEY_SIZE)
End