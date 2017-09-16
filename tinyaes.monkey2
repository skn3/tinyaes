Namespace tinyaes
 
#Import "<libc>"
#Import "<std>"

#Import "lib/aes.h"
#Import "lib/aes.c"

Using libc.. 
Using std.memory
Using std.stringio
 
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
Function PadString:String(input:String, size:Int)
	'get pad size and see if we need to do any padding
	Local difference := size - (input.Length Mod size)
	If difference = 0
		Return input
	Endif
	
	'do pad
	Return input+PAD_CHAR.Dup(size-difference)
End

Function FillBuffer:Void(buffer:DataBuffer, value:UByte)
	For Local index := 0 Until buffer.Length
		buffer.PokeUByte(index, value)
	Next
End

Function PrintBuffer:Void(buffer:DataBuffer, label:String="buffer")
	For Local index := 0 Until buffer.Length
		Print label+"("+index+")="+Hex(buffer.PeekUByte(index))
	Next
End

Function ProcessChunks:String(encrypt:Bool, input:String, key:String, keySize:Int)
	'verify the key length
	If key.Length <> keySize
		Throw New AESError("invalid key size")
	Endif
	
	If encrypt
		Print "AESEncrypt"
	Else
		Print "AESDecrypt"
	Endif
	
	Print "input = "+input
	Print "input.Length = "+input.Length
	
	'create key buffer
	Local bufferKey := New DataBuffer(keySize)
	bufferKey.PokeString(0, key)
	
	Print "[key]"
	PrintBuffer(bufferKey,"key")
	
	'created padded text
	Local paddedText := PadString(input, keySize)
	Local bufferInput := New DataBuffer(keySize)
	Local bufferOutput := New DataBuffer(keySize)
	Local chunks := paddedText.Length / keySize
	
	Print "chunks = "+chunks
	Print "paddedText = "+paddedText
	
	Local buildString:String
	For Local chunk := 0 Until chunks
		Local chunkString := input.Mid(chunk*keySize, keySize)
		Print "chunkString = "+chunkString
		Print "chunkString.Length = "+chunkString.Length
		Print "chunkString.CStringLength = "+chunkString.CStringLength
		
		FillBuffer(bufferInput, 0)
		chunkString.ToCString(bufferInput.Data, keySize)
		
		Print "[input]"
		PrintBuffer(bufferInput,"input")
		
		If encrypt
			AES_ECB_encrypt(bufferInput.Data, bufferKey.Data, bufferOutput.Data, keySize)
			
			'bufferOutput.CopyTo(bufferInput, 0, 0, keySize)
			'AES_ECB_decrypt(bufferInput.Data, bufferKey.Data, bufferOutput.Data, keySize)
		Else
			AES_ECB_decrypt(bufferInput.Data, bufferKey.Data, bufferOutput.Data, keySize)
		Endif
		
		Print "[output]"
		PrintBuffer(bufferOutput,"output")
		
		For Local index := 0 Until keySize
			buildString += String.FromChar(bufferOutput.PeekUByte(index))
		Next
		'buildString += String.FromCString(bufferOutput.Data, keySize)
	Next
	
	Return buildString
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
	Return ProcessChunks(True, input, key, KEY_SIZE)
End

Function AESDecrypt:String(input:String, key:String)
	Return ProcessChunks(False, input, key, KEY_SIZE)
End
