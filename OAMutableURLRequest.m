//
//  OAMutableURLRequest.m
//  OAuthConsumer
//
//  Created by Jon Crosby on 10/19/07.
//  Copyright 2007 Kaboomerang LLC. All rights reserved.
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.


#import "OAMutableURLRequest.h"


@interface OAMutableURLRequest (Private)
- (void)_generateTimestamp;
- (void)_generateNonce;
- (NSString *)_signatureBaseString;
@end

@implementation OAMutableURLRequest
@synthesize signature, nonce;
@synthesize consumer, token, realm, signatureProvider, timestamp;


#pragma mark init

- (id)initWithURL:(NSURL *)aUrl
		 consumer:(OAConsumer *)aConsumer
			token:(OAToken *)aToken
            realm:(NSString *)aRealm
signatureProvider:(id<OASignatureProviding, NSObject>)aProvider {
    self = [super initWithURL:aUrl
           cachePolicy:NSURLRequestReloadIgnoringCacheData
       timeoutInterval:10.0];
    
	if(self){
		self.consumer = aConsumer;
		self.token = aToken;
		self.realm = aRealm;
		self.signatureProvider = aProvider;
		
		if(token == nil){
			OAToken *n = [[OAToken alloc] init];
			self.token = n;
			[n release];
		}
		
		if(realm == nil){
			self.realm = @"";
		}
		
		if(signatureProvider == nil){
			OAHMAC_SHA1SignatureProvider *n = [[OAHMAC_SHA1SignatureProvider alloc] init];
			self.signatureProvider = n;
			[n release];
		}
		  
		[self _generateTimestamp];
		[self _generateNonce];
	}
    return self;
}

// Setting a timestamp and nonce to known
// values can be helpful for testing
- (id)initWithURL:(NSURL *)aUrl
		 consumer:(OAConsumer *)aConsumer
			token:(OAToken *)aToken
            realm:(NSString *)aRealm
signatureProvider:(id<OASignatureProviding, NSObject>)aProvider
            nonce:(NSString *)aNonce
        timestamp:(NSString *)aTimestamp {
    [self initWithURL:aUrl
             consumer:aConsumer
                token:aToken
                realm:aRealm
    signatureProvider:aProvider];
    
    self.nonce = aNonce;
	self.timestamp = aTimestamp;
    
    return self;
}

- (void) dealloc;
{

	self.consumer = nil;
	self.token = nil;
	self.realm = nil;
	self.signatureProvider = nil;
	self.timestamp = nil;
	
	[nonce release];
	nonce = nil;
	
//	[signature release];
	signature = nil;
	
    [super dealloc];
}


- (void)prepare {
    // sign
	NSLog(@"\nprep_string:%@", [self _signatureBaseString]);
	self.signature = [signatureProvider signClearText:[self _signatureBaseString]
                                      withSecret:[NSString stringWithFormat:@"%@&%@",
                                                  self.consumer.secret,
                                                  self.token.secret ? self.token.secret : @""]];
    
    // set OAuth headers
	NSMutableArray *chunks = [[NSMutableArray alloc] init];
	[chunks addObject:[NSString stringWithFormat:@"realm=\"%@\"", [self.realm encodedURLParameterString]]];
	[chunks addObject:[NSString stringWithFormat:@"oauth_consumer_key=\"%@\"", [self.consumer.key encodedURLParameterString]]];

	NSDictionary *tokenParameters = [self.token parameters];
	for (NSString *k in tokenParameters) {
		[chunks addObject:[NSString stringWithFormat:@"%@=\"%@\"", k, [[tokenParameters objectForKey:k] encodedURLParameterString]]];
	}

	[chunks addObject:[NSString stringWithFormat:@"oauth_signature_method=\"%@\"", [[self.signatureProvider name] encodedURLParameterString]]];
	[chunks addObject:[NSString stringWithFormat:@"oauth_signature=\"%@\"", [self.signature encodedURLParameterString]]];
	[chunks addObject:[NSString stringWithFormat:@"oauth_timestamp=\"%@\"", self.timestamp]];
	[chunks addObject:[NSString stringWithFormat:@"oauth_nonce=\"%@\"", self.nonce]];
	[chunks	addObject:@"oauth_version=\"1.0\""];
	
	NSString *oauthHeader = [NSString stringWithFormat:@"OAuth %@", [chunks componentsJoinedByString:@", "]];
	[chunks release];

    [self setValue:oauthHeader forHTTPHeaderField:@"Authorization"];
}

- (void)_generateTimestamp {
    self.timestamp = [NSString stringWithFormat:@"%d", time(NULL)];
}

- (void)_generateNonce {
    CFUUIDRef theUUID = CFUUIDCreate(NULL);
    CFStringRef string = CFUUIDCreateString(NULL, theUUID);
    CFRelease(theUUID);
    self.nonce = (NSString *)string;
}

- (NSString *)_signatureBaseString {
    // OAuth Spec, Section 9.1.1 "Normalize Request Parameters"
    // build a sorted array of both request parameters and OAuth header parameters
	NSDictionary *tokenParameters = [self.token parameters];
	// 6 being the number of OAuth params in the Signature Base String
	NSMutableArray *parameterPairs = [[NSMutableArray alloc] initWithCapacity:(5 + [[self parameters] count] + [tokenParameters count])];
    
    [parameterPairs addObject:[[[[OARequestParameter alloc] initWithName:@"oauth_consumer_key" value:self.consumer.key] autorelease] URLEncodedNameValuePair]];
    [parameterPairs addObject:[[[[OARequestParameter alloc] initWithName:@"oauth_signature_method" value:[self.signatureProvider name]] autorelease] URLEncodedNameValuePair]];
    [parameterPairs addObject:[[[[OARequestParameter alloc] initWithName:@"oauth_timestamp" value:self.timestamp] autorelease] URLEncodedNameValuePair]];
    [parameterPairs addObject:[[[[OARequestParameter alloc] initWithName:@"oauth_nonce" value:self.nonce] autorelease] URLEncodedNameValuePair]];
    [parameterPairs addObject:[[[[OARequestParameter alloc] initWithName:@"oauth_version" value:@"1.0"] autorelease] URLEncodedNameValuePair]];
	

	for(NSString *k in tokenParameters) {
		[parameterPairs addObject:[[OARequestParameter requestParameter:k value:[tokenParameters objectForKey:k]] URLEncodedNameValuePair]];
	}
    
	if (![[self valueForHTTPHeaderField:@"Content-Type"] hasPrefix:@"multipart/form-data"]) {
		for (OARequestParameter *param in [self parameters]) {
			[parameterPairs addObject:[param URLEncodedNameValuePair]];
		}
	}
    
    NSArray *sortedPairs = [parameterPairs sortedArrayUsingSelector:@selector(compare:)];
    [parameterPairs release], parameterPairs = nil;
    NSString *normalizedRequestParameters = [sortedPairs componentsJoinedByString:@"&"];
    
//	NSLog(@"Normalized: %@", normalizedRequestParameters);
    // OAuth Spec, Section 9.1.2 "Concatenate Request Elements"
    return [NSString stringWithFormat:@"%@&%@&%@",
            [self HTTPMethod],
            [[[self URL] URLStringWithoutQuery] encodedURLParameterString],
            [normalizedRequestParameters encodedURLString]];
}

@end
