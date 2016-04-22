dnl Configury specific to the libfabric mxr provider

dnl Called to configure this provider
dnl
dnl Arguments:
dnl
dnl $1: action if configured successfully
dnl $2: action if not configured successfully
dnl
AC_DEFUN([FI_MXR_CONFIGURE],[
	# Determine if we can support the mxr provider
	mxr_h_happy=0
	AS_IF([test x"$enable_mxr" != x"no"],
          [mxr_h_happy=1],
          [mxr_h_happy=0])

	AS_IF([test $mxr_h_happy -eq 1], [$1], [$2])
])
