#import <Foundation/Foundation.h>
#import <CoreFoundation/CoreFoundation.h>
#import <Security/Security.h>
#import "secureenclave.h"


// CFStringToCString creates a copy of the bytes of data
// converted to UTF-8 encoding.
char* CFStringToCString(CFStringRef data) {
  CFIndex len = CFStringGetLength(data);
  if (!len)
    return NULL;

  CFIndex realLen = CFStringGetMaximumSizeForEncoding(len, kCFStringEncodingUTF8);
  char* buf = (char*)malloc((size_t)realLen + 1);
  if (!buf)
    return NULL;
  memset(buf, 0, (size_t)realLen + 1);

  Boolean ok = CFStringGetCString(data, buf, realLen + 1, kCFStringEncodingUTF8);
  if (!ok)
    return NULL;

  return buf;
}

unsigned char* CFDataToUint8(CFDataRef data) {
  CFIndex len = CFDataGetLength(data);
  if (!len)
    return NULL;

  UInt8* buf = (UInt8*)malloc((size_t)len);
  if (!buf)
    return NULL;
  memset(buf, 0, (size_t)len);

  CFRange range = CFRangeMake(0, len);
  CFDataGetBytes(data, range, buf);

  return (unsigned char*)buf;
}

// Extract the public key data from a SecKeyRef
// Returns null if it couldn't find the data
CFDataRef ExtractPubKey(SecKeyRef pubKey) {
  CFDataRef val = NULL;
  CFDataRef res = NULL;
  CFDictionaryRef keyAttrs = SecKeyCopyAttributes(pubKey);
  if (CFDictionaryContainsKey(keyAttrs, kSecValueData) == true)
    val = (CFDataRef)CFDictionaryGetValue(keyAttrs, kSecValueData);

  if (val)
    res = CFDataCreateCopy(kCFAllocatorDefault, val);

  if (keyAttrs)
    CFRelease((CFTypeRef)keyAttrs);

  return res;
}

size_t createKey(unsigned char** ret, char** retErr){
    CFErrorRef error = NULL;

    // ignoring the depreciated warning for "kSecAttrAccessibleAlwaysThisDeviceOnly" becuase this is the setting
    // we need to be able to access secure enclave for this particualar key even when device is locked
    // this was depreciated without providing an alternative
    // it's expected that a new key would need to be generated on a full re-install of launcher that removes the launcher.db
    #pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    SecAccessControlRef access = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                                 kSecAttrAccessibleAlwaysThisDeviceOnly,
                                                                 kSecAccessControlPrivateKeyUsage,
                                                                 &error);

    if (error) {
        CFStringRef errStr = CFErrorCopyDescription(error);
        CFRelease(error);
        *retErr = CFStringToCString(errStr);
        CFRelease(errStr);
        return 0;
    }

    NSDictionary* attributes =
    @{ (id)kSecAttrKeyType: (id)kSecAttrKeyTypeECSECPrimeRandom,
        (id)kSecAttrKeySizeInBits: @256,
        (id)kSecAttrTokenID: (id)kSecAttrTokenIDSecureEnclave,
        (id)kSecPrivateKeyAttrs:
        @{  (id)kSecAttrIsPermanent: @YES,
            (id)kSecAttrAccessControl: (id)access,
        },
    };

    // create the private key
    SecKeyRef privateKey = SecKeyCreateRandomKey((__bridge CFDictionaryRef)attributes, &error);

    CFRelease(access);
    CFRelease(attributes);

    if ((error) || (!privateKey)) {
        CFStringRef errStr = NULL;
        if (!error){
          errStr = CFSTR("no private key or error returned by SecKeyCreateRandomKey");
        } else {
          errStr = CFErrorCopyDescription(error);
          CFRelease(error);
        }

        *retErr = CFStringToCString(errStr);
        CFRelease(errStr);
        return 0;
    }

    // get public key from private key
    SecKeyRef publicKey = SecKeyCopyPublicKey(privateKey);
    CFRelease(privateKey);

    if (!publicKey) {
      CFStringRef errStr = CFSTR("public key was not able to be derived from private key by SecKeyCopyPublicKey");
      *retErr = CFStringToCString(errStr);
      CFRelease(errStr);
      return 0;
    }

    // extract just the public key data
    CFDataRef publicKeyRef = ExtractPubKey(publicKey);
    *ret = CFDataToUint8(publicKeyRef);
    CFIndex size = CFDataGetLength(publicKeyRef);
    CFRelease(publicKeyRef);
    return size;
}

OSStatus findPrivateKey(CFDataRef pubKeySha1, SecKeyRef *key) {
    NSDictionary* attributes =
    @{ (id)kSecClass: (id)kSecClassKey,
        (id)kSecAttrKeyType: (id)kSecAttrKeyTypeEC,
        (id)kSecAttrTokenID: (id)kSecAttrTokenIDSecureEnclave,
        (id)kSecAttrKeyClass: (id)kSecAttrKeyClassPrivate,
        (id)kSecReturnRef: (id)kCFBooleanTrue,
        (id)kSecMatchLimit: (id)kSecMatchLimitOne,
        (id)kSecAttrApplicationLabel: (__bridge id)pubKeySha1,
    };

    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)attributes, (__bridge void *)key);
    CFRelease(attributes);
    return status;
}

size_t findKey(unsigned char* hash, unsigned char** ret, char** retErr){
    #define sha1HashSize 20
    CFDataRef cfHash = CFDataCreateWithBytesNoCopy(kCFAllocatorDefault, (UInt8*)hash, sha1HashSize, kCFAllocatorNull);
    SecKeyRef privateKey = NULL;
    OSStatus status = findPrivateKey(cfHash, (__bridge void *)&privateKey);

    CFRelease(cfHash);

    if ((status != 0) || (!privateKey)) {
      NSString *msg = [NSString stringWithFormat:@"finding key pair: status %i", (int)status];
      *retErr = CFStringToCString((__bridge CFStringRef)msg);
      CFRelease(msg);
      return 0;
    }

    // get public key from private key
    SecKeyRef publicKey = SecKeyCopyPublicKey(privateKey);
    CFRelease(privateKey);

    if (!publicKey) {
      CFStringRef errStr = CFSTR("failed to copy public key");
      *retErr = CFStringToCString(errStr);
      CFRelease(errStr);
      return 0;
    }

    // extract just the public key data
    CFDataRef publicKeyRef = ExtractPubKey(publicKey);
    *ret = CFDataToUint8(publicKeyRef);
    CFIndex size = CFDataGetLength(publicKeyRef);
    CFRelease(publicKeyRef);
    return size;
}

size_t ecdh(unsigned char* hash, unsigned char* counterParty, int counterPartySize, unsigned char** ret, char** retErr){
    CFDataRef cfHash = CFDataCreateWithBytesNoCopy(kCFAllocatorDefault, (UInt8*)hash, 20, kCFAllocatorNull);
    SecKeyRef privateKey = NULL;
    OSStatus status = findPrivateKey(cfHash, (__bridge void *)&privateKey);

    if ((status != 0) || (!privateKey)) {
      NSString *msg = [NSString stringWithFormat:@"finding key: status %i", (int)status];
      *retErr = CFStringToCString((__bridge CFStringRef)msg);
      CFRelease(msg);
      return 0;
    }

    CFDataRef cfCounterParty = CFDataCreateWithBytesNoCopy(kCFAllocatorDefault, (UInt8*)counterParty, counterPartySize, kCFAllocatorNull);
    CFErrorRef error = NULL;

    NSDictionary* createAttributes =
    @{ (id)kSecClass: (id)kSecClassKey,
        (id)kSecAttrKeyClass: (id)kSecAttrKeyClassPublic,
        (id)kSecAttrKeyType: (id)kSecAttrKeyTypeEC,
        (id)kSecReturnRef: (id)kCFBooleanTrue,
    };

    SecKeyRef publicKey = SecKeyCreateWithData(cfCounterParty, (__bridge CFDictionaryRef)createAttributes, &error);
    if ((error) || (!publicKey)) {
        CFStringRef errStr = NULL;
        if (!privateKey){
          errStr = CFSTR("no public key or error returned by SecKeyCreateWithData");
        } else {
          errStr = CFErrorCopyDescription(error);
          CFRelease(error);
        }

        *retErr = CFStringToCString(errStr);
        CFRelease(errStr);
        return 0;
    }

    NSDictionary* exchangeAttributes =
    @{ (id)kSecAttrKeySizeInBits: @256,
        (id)kSecKeyKeyExchangeParameterRequestedSize: @32,
    };

    CFDataRef shared = SecKeyCopyKeyExchangeResult(
      privateKey,
      (__bridge CFStringRef)kSecKeyAlgorithmECDHKeyExchangeStandard,
      publicKey,
      (__bridge CFDictionaryRef)exchangeAttributes,
      &error);

    if ((error) || (!shared)) {
        CFStringRef errStr = CFErrorCopyDescription(error);
        CFRelease(error);
        *retErr = CFStringToCString(errStr);
        CFRelease(errStr);
        return 0;
    }

    *ret = CFDataToUint8(shared);
    CFIndex size = CFDataGetLength(shared);
    CFRelease(shared);
    return size;
}

Wrapper *wrapCreateKey() {
	Wrapper *res = (Wrapper *)malloc(sizeof(Wrapper));
	if (!res)
		return NULL;
	memset(res, 0, sizeof(Wrapper));
	res->size = createKey(&res->buf, &res->error);
	return res;
}

Wrapper *wrapFindKey(void *hash) {
	Wrapper *res = (Wrapper *)malloc(sizeof(Wrapper));
	if (!res)
		return NULL;
	memset(res, 0, sizeof(Wrapper));
	res->size = findKey((unsigned char *)hash, &res->buf, &res->error);
	return res;
}

Wrapper *wrapECDH(void *hash, void *counterParty, int counterPartySize) {
	Wrapper *res = (Wrapper *)malloc(sizeof(Wrapper));
	if (!res)
		return NULL;
	memset(res, 0, sizeof(Wrapper));
	res->size = ecdh((unsigned char *)hash, (unsigned char *)counterParty, counterPartySize, &res->buf, &res->error);
	return res;
}
