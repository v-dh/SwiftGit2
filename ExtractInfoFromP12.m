//
//  ExtractInfoFromP12.m
//  SECOIA
//
//  Created by vdh on 26/06/2019.
//  Copyright © 2019 Orange. All rights reserved.
//

#import "ExtractInfoFromP12.h"

@implementation ExtractInfoFromP12

+ (CFArrayRef) GetSSLinfoFromp12:(NSString*) fileNAme andPassword:(NSString*) password {
	
	NSString* path = [[NSBundle mainBundle] pathForResource:fileNAme ofType:@"p12"];
	NSData* data = [NSData dataWithContentsOfFile:path];
	SecIdentityRef myIdentity;
	SecTrustRef         trust;
	CFArrayRef myCertArray;
	CFStringRef p12Password = (__bridge CFStringRef)password;
	
	OSStatus st = extractIdentityAndTrust((__bridge CFDataRef)data, &myIdentity, &trust, &myCertArray, p12Password);
	if (st == noErr) {
		
		CFArrayRef certificates = CFArrayCreate(NULL, (const void **)&myIdentity, 1, NULL);
		CFMutableArrayRef tmpArray = CFArrayCreateMutableCopy(NULL, 0, certificates);
		CFIndex numberOfCertInChain = CFArrayGetCount(myCertArray);
		
		for(int i = 0; i < numberOfCertInChain ; ++i  )
		{
			SecCertificateRef cert = (SecCertificateRef) CFArrayGetValueAtIndex(myCertArray,i);
			CFArrayAppendValue(tmpArray,cert);
		}
		
		return (CFArrayRef)tmpArray;
	}
	return nil;
}

OSStatus extractIdentityAndTrust(CFDataRef inPKCS12Data, SecIdentityRef *outIdentity, SecTrustRef *outTrust, CFArrayRef *outCertArray, CFStringRef keyPassword)
{
	OSStatus securityError = errSecSuccess;
	
	const void *keys[] =   { kSecImportExportPassphrase };
	const void *values[] = { keyPassword };
	CFDictionaryRef optionsDictionary = NULL;
	
	/* Create a dictionary containing the passphrase if one
	 was specified.  Otherwise, create an empty dictionary. */
	optionsDictionary = CFDictionaryCreate(
										   NULL, keys,
										   values, (keyPassword ? 1 : 0),
										   NULL, NULL);
	
	CFArrayRef items = NULL;
	securityError = SecPKCS12Import(inPKCS12Data,
									optionsDictionary,
									&items);
	
	if (securityError == 0) {
		CFDictionaryRef myIdentityAndTrust = CFArrayGetValueAtIndex (items, 0);
		const void *tempIdentity = NULL;
		tempIdentity = CFDictionaryGetValue (myIdentityAndTrust, kSecImportItemIdentity);
		CFRetain(tempIdentity);
		*outIdentity = (SecIdentityRef)tempIdentity;
		
		const void *tempTrust = NULL;
		tempTrust = CFDictionaryGetValue (myIdentityAndTrust, kSecImportItemTrust);
		
		CFRetain(tempTrust);
		*outTrust = (SecTrustRef)tempTrust;
		
		const void *tempChain = NULL;
		tempChain = CFDictionaryGetValue (myIdentityAndTrust, kSecImportItemCertChain);
		
		CFRetain(tempChain);
		*outCertArray = (CFArrayRef) tempChain;
	}
	
	if (optionsDictionary)
		CFRelease(optionsDictionary);
	
	if (items)
		CFRelease(items);
	
	return securityError;
}

@end
