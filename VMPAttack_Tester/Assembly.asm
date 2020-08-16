PUBLIC __vmpfnc

INCLUDE VMProtectSDKa.inc

.code

__vmpfnc PROC
	call VMProtectIsVirtualMachinePresent
	ret
__vmpfnc ENDP

END

