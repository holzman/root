// @(#)root/net:$Id$
// Author: Fabio Hernandez 30/01/2013
//         based on an initial version by Marcelo Sousa (class THTTPMessage)

/*************************************************************************
 * Copyright (C) 1995-2011, Rene Brun and Fons Rademakers.               *
 * All rights reserved.                                                  *
 *                                                                       *
 * For the licensing terms see $ROOTSYS/LICENSE.                         *
 * For the list of contributors see $ROOTSYS/README/CREDITS.             *
 *************************************************************************/

//////////////////////////////////////////////////////////////////////////
//                                                                      //
// TS3HTTPRequest                                                       //
//                                                                      //
// An object of this class represents an HTTP request extended to be    //
// compatible with Amazon's S3 protocol.                                //
// Specifically, such a request contains an 'Authorization' header with //
// information used by the S3 server for authenticating this request.   //
// The authentication information is computed based on a pair of access //
// key and secret key which are both provided to the user by the S3     //
// service provider (e.g. Amazon, Google, etc.).                        //
// The secret key is used to compute a signature of selected fields in  //
// the request. The algorithm for computing the signature is documented //
// in:                                                                  //
//                                                                      //
// Google storage:                                                      //
// http://code.google.com/apis/storage/docs/reference/v1/developer-guidev1.html#authentication
//                                                                      //
// Amazon:                                                              //
// http://docs.aws.amazon.com/AmazonS3/latest/dev/S3_Authentication2.html 
//                                                                      //
//////////////////////////////////////////////////////////////////////////

#include "TS3HTTPRequest.h"
#include "TBase64.h"
#if defined(MAC_OS_X_VERSION_10_7)
#include <CommonCrypto/CommonHMAC.h>
#define SHA_DIGEST_LENGTH 20
#else
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#endif

#include <stdio.h>
#include <time.h>
#include <string.h>

ClassImp(TS3HTTPRequest)

//______________________________________________________________________________
TS3HTTPRequest::TS3HTTPRequest()
               : fAuthType(kNoAuth), fHost("NoHost")
{
}

//______________________________________________________________________________
TS3HTTPRequest::TS3HTTPRequest(EHTTPVerb httpVerb, const TString& host,
   const TString& bucket, const TString& objectKey, EAuthType authType,
   const TString& accessKey, const TString& secretKey)
{
   // Default constructor

   fVerb      = httpVerb;      
   fHost      = host;       
   fBucket    = bucket;     
   fObjectKey = objectKey;
   fAuthType  = authType;
   fAccessKey = accessKey;  
   fSecretKey = secretKey;
}

//______________________________________________________________________________
TS3HTTPRequest::TS3HTTPRequest(const TS3HTTPRequest& r)
               : TObject(r)
{
   // Copy constructor

   fVerb      = r.fVerb;      
   fHost      = r.fHost;       
   fBucket    = r.fBucket;     
   fObjectKey = r.fObjectKey;
   fAuthType  = r.fAuthType;
   fAccessKey = r.fAccessKey;  
   fSecretKey = r.fSecretKey;
   fTimeStamp = r.fTimeStamp;
   fTimeStamp2 = r.fTimeStamp2;
}

//______________________________________________________________________________
TString TS3HTTPRequest::ComputeSignature(TS3HTTPRequest::EHTTPVerb httpVerb) const
{
   // Returns this request's signature

   // Please note, the order of the fields used for computing
   // the signature is important. Make sure that the changes you
   // make are compatible with the reference documentation.
   //
   // Refs:
   //    AMAZON  http://awsdocs.s3.amazonaws.com/S3/latest/s3-qrc.pdf
   //    GOOGLE: http://code.google.com/apis/storage/docs/reference/v1/developer-guidev1.html#authentication


   TString toSign = TString::Format("%s\n\n\n%s\n",  // empty Content-MD5 and Content-Type
                                    (const char*)HTTPVerbToTString(httpVerb),
                                    (const char*)fTimeStamp);

   //   Info("ComputeSignature", "BH %s\n", toSign.Data());
   if (fAuthType == kGoogle) {
      // Must use API version 1. Google Storage API v2 only
      // accepts OAuth authentication.
      // This header is not strictly needed but if used for computing
      // the signature, the request must contain it as a header
      // (see method MakeAuthHeader)
      // Ref: https://developers.google.com/storage/docs/reference/v1/apiversion1
      toSign += "x-goog-api-version:1\n"; // Lowercase, no spaces around ':'
   }

   toSign += "/" + fBucket + fObjectKey;

   unsigned char digest[SHA_DIGEST_LENGTH] = {0};
#if defined(MAC_OS_X_VERSION_10_7)
   CCHmac(kCCHmacAlgSHA1, fSecretKey.Data(), fSecretKey.Length() , (unsigned char *)toSign.Data(), toSign.Length(), digest);
#else
   unsigned int *sd = NULL;
   HMAC(EVP_sha1(), fSecretKey.Data(), fSecretKey.Length() , (unsigned char *)toSign.Data(), toSign.Length(), digest, sd);
#endif

   return TBase64::Encode((const char *)digest, SHA_DIGEST_LENGTH);
}

//______________________________________________________________________________
TString TS3HTTPRequest::HTTPVerbToTString(TS3HTTPRequest::EHTTPVerb httpVerb) const
{
   switch (httpVerb) {
      case kGET:    return TString("GET");
      case kPOST:   return TString("POST");
      case kPUT:    return TString("PUT");
      case kDELETE: return TString("DELETE");
      case kHEAD:   return TString("HEAD");
      case kCOPY:   return TString("COPY");
      default:      return TString("");
   }
}

//______________________________________________________________________________
TS3HTTPRequest& TS3HTTPRequest::SetTimeStamp()
{
   // Sets this request's time stamp according to:
   //   http://code.google.com/apis/storage/docs/reference-headers.html#date

   time_t now = time(NULL);
   char result[128], result2[128];
#ifdef _REENTRANT
   struct tm dateFormat;
   strftime(result, sizeof(result), "%a, %d %b %Y %H:%M:%S GMT",
      gmtime_r(&now, &dateFormat));
   strftime(result2, sizeof(result2), "%Y%m%dT%H%M%SZ",
      gmtime_r(&now, &dateFormat));
#else
   strftime(result, sizeof(result), "%a, %d %b %Y %H:%M:%S GMT",
      gmtime(&now));
   strftime(result2, sizeof(result2), "%Y%m%dT%H%M%SZ",
      gmtime_r(&now, &dateFormat));	    
#endif
   fTimeStamp = result;
   fTimeStamp2 = result2;
   return *this;
}

//______________________________________________________________________________
TString TS3HTTPRequest::MakeRequestLine(TS3HTTPRequest::EHTTPVerb httpVerb) const
{
   // Returns the first line of a HTTP request for this object. Note that since
   // we don't use the virtual host syntax which is supported by Amazon, we
   // must include the bucket name in thr resource. For example, we don't use
   // http://mybucket.s3.amazonaws.com/path/to/my/file but instead
   // http://s3.amazonaws.com/mybucket/path/to/my/file so the HTTP request
   // will be of the form "GET /mybucket/path/to/my/file HTTP/1.1"
   // Also note that the path must include the leading '/'.

   return TString::Format("%s /%s%s HTTP/1.1",
                          (const char*)HTTPVerbToTString(httpVerb),
                          (const char*)fBucket,
                          (const char*)fObjectKey);
}

//______________________________________________________________________________
TString TS3HTTPRequest::MakeHostHeader() const
{
   // Returns the 'Host' header to include in the HTTP request.

   return "Host:" + fHost;
}

//______________________________________________________________________________
TString TS3HTTPRequest::MakeDateHeader() const
{
   // Returns the date header for this HTTP request

   return "Date:" + fTimeStamp2;
}

//______________________________________________________________________________
TString TS3HTTPRequest::MakeAuthPrefix() const
{
   // Returns the authentication prefix 

   switch (fAuthType) {
      case kNoAuth: return "";
      case kGoogle: return "GOOG1";
      case kAmazon:
      default:      return "AWS";
   }
}

//______________________________________________________________________________
TString TS3HTTPRequest::MakeAuthHeader(TS3HTTPRequest::EHTTPVerb httpVerb) const
{
   // Returns the authentication header for this HTTP request

   if (fAuthType == kNoAuth)
      return "";
   
   TString x = TString::Format("Authorization: %s %s:%s%s",
      (const char*)MakeAuthPrefix(),
      (const char*)fAccessKey,
      (const char*)ComputeSignature(httpVerb),
      (fAuthType == kGoogle) ? "\r\nx-goog-api-version: 1" : "");

   Info("MakeAuthHeader", "\n%s", x.Data());
   exit(1);
     
   return TString::Format("Authorization: %s %s:%s%s",
      (const char*)MakeAuthPrefix(),
      (const char*)fAccessKey,
      (const char*)ComputeSignature(httpVerb),
      (fAuthType == kGoogle) ? "\r\nx-goog-api-version: 1" : "");
}

TString TS3HTTPRequest::GetSHA256Hash(TString payload) const
{
  /*  
   unsigned char *ibuf, obuf[32];
   char hash[65];
   SHA256(ibuf, 0, obuf);
   for (int i=0; i<32; i++) {
     sprintf(&hash[2*i], "%02x", obuf[i]);
   }
  */

  unsigned char obuf[32];
  char hash[65];
  SHA256((unsigned char*) payload.Data(), payload.Length(), obuf);
   for (int i=0; i<32; i++) {
     sprintf(&hash[2*i], "%02x", obuf[i]);
   }
   
   return TString(hash);
}

  
//______________________________________________________________________________
TString TS3HTTPRequest::GetRequest(TS3HTTPRequest::EHTTPVerb httpVerb, Bool_t appendCRLF)
{
   // Returns the HTTP request ready to be sent to the server

   // Set time stamp before computing this request's signature. The signature
   // includes the date.
   SetTimeStamp(); 
   TString dateheader = MakeDateHeader();
   TString hostheader = MakeHostHeader();
   TString hash = GetSHA256Hash("");
   TString request = TString::Format("%s\r\n%s\r\n%s\r\n",
				     (const char*)MakeRequestLine(httpVerb),
				     (const char*)dateheader,
				     (const char*)hostheader);


   dateheader.ToLower();
   hostheader.ToLower();
   TString reqline = TString::Format("%s\r\n/%s%s\r\n\r\n%s\r\n%s\r\n\r\ndate;host\r\n%s",
				     (const char*)HTTPVerbToTString(httpVerb),
				     (const char*)fBucket,
				     (const char*)fObjectKey,
				     (const char*)dateheader,
				     (const char*)hostheader,
				     (const char*)hash);

   //  TString signingString = 
   //     TString::Format("%s\n%s\n%s\n%s",
   //     (const char*)fTimeStamp2 
   //   reqline = reqline.Strip(TString::kTrailing, '\n');
   //   Info("BH GetRequest req", "\n%s", request.Data());
   Info("BH getrequest reqline ", "---%s---\n", reqline.Data());

   exit(1);
   request = "GET /?foo=Zoo&foo=aha http/1.1\nDate:Mon, 09 Sep 2011 23:36:00 GMT\nHost:host.foo.com\n";

   Info("BH GetRequest", "\n%s", request.Data());
   TString authHeader = MakeAuthHeader(httpVerb);
   if (!authHeader.IsNull())
      request += authHeader + "\r\n";
   if (appendCRLF)
      request += "\r\n";
   return request;

   Info("BH", "gr: %s", request.Data());

}
