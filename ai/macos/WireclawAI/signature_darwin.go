//go:build darwin && cgo

package main

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>
#include <string.h>

static int equal_value(CFDictionaryRef dict, CFStringRef key, CFTypeRef value) {
 if (!dict || CFGetTypeID(dict) != CFDictionaryGetTypeID()) return 0;
 CFTypeRef actual = CFDictionaryGetValue(dict, key);
 return actual && CFEqual(actual, value);
}
static int exact_entitlements(CFDictionaryRef info, int role) {
 CFDictionaryRef ent = (CFDictionaryRef)CFDictionaryGetValue(info, kSecCodeInfoEntitlementsDict);
 if (role == 2) return !ent || (CFGetTypeID(ent) == CFDictionaryGetTypeID() && CFDictionaryGetCount(ent) == 0);
 if (!ent || CFGetTypeID(ent) != CFDictionaryGetTypeID() || CFDictionaryGetCount(ent) != 2) return 0;
 return equal_value(ent, CFSTR("com.apple.security.app-sandbox"), kCFBooleanTrue) &&
        equal_value(ent, role == 0 ? CFSTR("com.apple.security.network.server") : CFSTR("com.apple.security.inherit"), kCFBooleanTrue);
}

// No subprocess, network request, trust override or path lookup occurs here.
// The app's resource seal binds its nested code and manifests; their explicit
// checks below also reject missing signatures and unexpected entitlements.
static int wireclaw_validate_code(const char *path, int role) {
 int ok = 0;
 CFURLRef url = NULL;
 SecStaticCodeRef code = NULL;
 CFDictionaryRef info = NULL;
 SecCodeRef self = NULL;
 CFDictionaryRef selfInfo = NULL;
 url = CFURLCreateFromFileSystemRepresentation(NULL, (const UInt8 *)path, strlen(path), role == 0);
 if (!url || SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code) != errSecSuccess) goto done;
 SecCSFlags flags = kSecCSStrictValidate | kSecCSCheckAllArchitectures;
 if (role == 0) flags |= kSecCSCheckNestedCode;
 if (SecStaticCodeCheckValidity(code, flags, NULL) != errSecSuccess) goto done;
 if (SecCodeCopySigningInformation(code, kSecCSSigningInformation, &info) != errSecSuccess) goto done;
 if (!exact_entitlements(info, role)) goto done;
 if (role == 0) {
  if (!equal_value(info, kSecCodeInfoIdentifier, CFSTR("com.wireclaw.WireclawAI"))) goto done;
  CFDictionaryRef plist = (CFDictionaryRef)CFDictionaryGetValue(info, kSecCodeInfoPList);
  if (!equal_value(plist, CFSTR("CFBundleIdentifier"), CFSTR("com.wireclaw.WireclawAI")) ||
      !equal_value(plist, CFSTR("CFBundleExecutable"), CFSTR("WireclawAI"))) goto done;
  if (SecCodeCopySelf(kSecCSDefaultFlags, &self) != errSecSuccess ||
      SecCodeCheckValidity(self, kSecCSDefaultFlags, NULL) != errSecSuccess ||
      SecCodeCopySigningInformation(self, kSecCSSigningInformation, &selfInfo) != errSecSuccess) goto done;
  CFTypeRef currentHash = CFDictionaryGetValue(selfInfo, kSecCodeInfoUnique);
  if (!currentHash || !equal_value(info, kSecCodeInfoUnique, currentHash)) goto done;
 } else if (role == 1) {
  if (!equal_value(info, kSecCodeInfoIdentifier, CFSTR("llama-server"))) goto done;
 } else {
  CFStringRef identifier = CFStringCreateWithCString(NULL, strrchr(path, '/') + 1, kCFStringEncodingUTF8);
  int matches = identifier && equal_value(info, kSecCodeInfoIdentifier, identifier);
  if (identifier) CFRelease(identifier);
  if (!matches) goto done;
 }
 ok = 1;
 done:
 if (selfInfo) CFRelease(selfInfo);
 if (self) CFRelease(self);
 if (info) CFRelease(info);
 if (code) CFRelease(code);
 if (url) CFRelease(url);
 return ok;
}
*/
import "C"

import "unsafe"

func verifyCodeSignature(path, role string) error {
	var kind C.int
	switch role {
	case "app":
		kind = 0
	case "helper":
		kind = 1
	case "library":
		kind = 2
	default:
		return errBundleVerification
	}
	p := C.CString(path)
	defer C.free(unsafe.Pointer(p))
	if C.wireclaw_validate_code(p, kind) != 1 {
		return errBundleVerification
	}
	return nil
}
