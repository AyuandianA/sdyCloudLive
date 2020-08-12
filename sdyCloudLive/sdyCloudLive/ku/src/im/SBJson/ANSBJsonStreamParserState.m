/*
 Copyright (c) 2010, Stig Brautaset.
 All rights reserved.

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are
 met:

   Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.

   Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

   Neither the name of the the author nor the names of its contributors
   may be used to endorse or promote products derived from this software
   without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#if !__has_feature(objc_arc)
#error "This source file must be compiled with ARC enabled!"
#endif

#import "ANSBJsonStreamParserState.h"

#define SINGLETON \
+ (id)sharedInstance { \
    static id state = nil; \
    if (!state) { \
        @synchronized(self) { \
            if (!state) state = [[self alloc] init]; \
        } \
    } \
    return state; \
}

@implementation ANSBJsonStreamParserState

+ (id)sharedInstance { return nil; }

- (BOOL)parser:(ANSBJsonStreamParser*)parser shouldAcceptToken:(sbjson_token_t)token {
	return NO;
}

- (ANSBJsonStreamParserStatus)parserShouldReturn:(ANSBJsonStreamParser*)parser {
	return ANSBJsonStreamParserWaitingForData;
}

- (void)parser:(ANSBJsonStreamParser*)parser shouldTransitionTo:(sbjson_token_t)tok {}

- (BOOL)needKey {
	return NO;
}

- (NSString*)name {
	return @"<aaiie!>";
}

- (BOOL)isError {
    return NO;
}

@end

#pragma mark -

@implementation ANSBJsonStreamParserStateStart

SINGLETON

- (BOOL)parser:(ANSBJsonStreamParser*)parser shouldAcceptToken:(sbjson_token_t)token {
	return token == sbjson_token_array_open || token == sbjson_token_object_open;
}

- (void)parser:(ANSBJsonStreamParser*)parser shouldTransitionTo:(sbjson_token_t)tok {

	ANSBJsonStreamParserState *state = nil;
	switch (tok) {
		case sbjson_token_array_open:
			state = [ANSBJsonStreamParserStateArrayStart sharedInstance];
			break;

		case sbjson_token_object_open:
			state = [ANSBJsonStreamParserStateObjectStart sharedInstance];
			break;

		case sbjson_token_array_close:
		case sbjson_token_object_close:
			if (parser.supportMultipleDocuments)
				state = parser.state;
			else
				state = [ANSBJsonStreamParserStateComplete sharedInstance];
			break;

		case sbjson_token_eof:
			return;

		default:
			state = [ANSBJsonStreamParserStateError sharedInstance];
			break;
	}


	parser.state = state;
}

- (NSString*)name { return @"before outer-most array or object"; }

@end

#pragma mark -

@implementation ANSBJsonStreamParserStateComplete

SINGLETON

- (NSString*)name { return @"after outer-most array or object"; }

- (ANSBJsonStreamParserStatus)parserShouldReturn:(ANSBJsonStreamParser*)parser {
	return ANSBJsonStreamParserComplete;
}

@end

#pragma mark -

@implementation ANSBJsonStreamParserStateError

SINGLETON

- (NSString*)name { return @"in error"; }

- (ANSBJsonStreamParserStatus)parserShouldReturn:(ANSBJsonStreamParser*)parser {
	return ANSBJsonStreamParserError;
}

- (BOOL)isError {
    return YES;
}

@end

#pragma mark -

@implementation ANSBJsonStreamParserStateObjectStart

SINGLETON

- (NSString*)name { return @"at beginning of object"; }

- (BOOL)parser:(ANSBJsonStreamParser*)parser shouldAcceptToken:(sbjson_token_t)token {
	switch (token) {
		case sbjson_token_object_close:
		case sbjson_token_string:
        case sbjson_token_encoded:
			return YES;
			break;
		default:
			return NO;
			break;
	}
}

- (void)parser:(ANSBJsonStreamParser*)parser shouldTransitionTo:(sbjson_token_t)tok {
	parser.state = [ANSBJsonStreamParserStateObjectGotKey sharedInstance];
}

- (BOOL)needKey {
	return YES;
}

@end

#pragma mark -

@implementation ANSBJsonStreamParserStateObjectGotKey

SINGLETON

- (NSString*)name { return @"after object key"; }

- (BOOL)parser:(ANSBJsonStreamParser*)parser shouldAcceptToken:(sbjson_token_t)token {
	return token == sbjson_token_entry_sep;
}

- (void)parser:(ANSBJsonStreamParser*)parser shouldTransitionTo:(sbjson_token_t)tok {
	parser.state = [ANSBJsonStreamParserStateObjectSeparator sharedInstance];
}

@end

#pragma mark -

@implementation ANSBJsonStreamParserStateObjectSeparator

SINGLETON

- (NSString*)name { return @"as object value"; }

- (BOOL)parser:(ANSBJsonStreamParser*)parser shouldAcceptToken:(sbjson_token_t)token {
	switch (token) {
		case sbjson_token_object_open:
		case sbjson_token_array_open:
		case sbjson_token_bool:
		case sbjson_token_null:
        case sbjson_token_integer:
        case sbjson_token_real:
        case sbjson_token_string:
        case sbjson_token_encoded:
			return YES;
			break;

		default:
			return NO;
			break;
	}
}

- (void)parser:(ANSBJsonStreamParser*)parser shouldTransitionTo:(sbjson_token_t)tok {
	parser.state = [ANSBJsonStreamParserStateObjectGotValue sharedInstance];
}

@end

#pragma mark -

@implementation ANSBJsonStreamParserStateObjectGotValue

SINGLETON

- (NSString*)name { return @"after object value"; }

- (BOOL)parser:(ANSBJsonStreamParser*)parser shouldAcceptToken:(sbjson_token_t)token {
	switch (token) {
		case sbjson_token_object_close:
        case sbjson_token_value_sep:
			return YES;
			break;
		default:
			return NO;
			break;
	}
}

- (void)parser:(ANSBJsonStreamParser*)parser shouldTransitionTo:(sbjson_token_t)tok {
	parser.state = [ANSBJsonStreamParserStateObjectNeedKey sharedInstance];
}


@end

#pragma mark -

@implementation ANSBJsonStreamParserStateObjectNeedKey

SINGLETON

- (NSString*)name { return @"in place of object key"; }

- (BOOL)parser:(ANSBJsonStreamParser*)parser shouldAcceptToken:(sbjson_token_t)token {
    return sbjson_token_string == token || sbjson_token_encoded == token;
}

- (void)parser:(ANSBJsonStreamParser*)parser shouldTransitionTo:(sbjson_token_t)tok {
	parser.state = [ANSBJsonStreamParserStateObjectGotKey sharedInstance];
}

- (BOOL)needKey {
	return YES;
}

@end

#pragma mark -

@implementation ANSBJsonStreamParserStateArrayStart

SINGLETON

- (NSString*)name { return @"at array start"; }

- (BOOL)parser:(ANSBJsonStreamParser*)parser shouldAcceptToken:(sbjson_token_t)token {
	switch (token) {
		case sbjson_token_object_close:
        case sbjson_token_entry_sep:
        case sbjson_token_value_sep:
			return NO;
			break;

		default:
			return YES;
			break;
	}
}

- (void)parser:(ANSBJsonStreamParser*)parser shouldTransitionTo:(sbjson_token_t)tok {
	parser.state = [ANSBJsonStreamParserStateArrayGotValue sharedInstance];
}

@end

#pragma mark -

@implementation ANSBJsonStreamParserStateArrayGotValue

SINGLETON

- (NSString*)name { return @"after array value"; }


- (BOOL)parser:(ANSBJsonStreamParser*)parser shouldAcceptToken:(sbjson_token_t)token {
	return token == sbjson_token_array_close || token == sbjson_token_value_sep;
}

- (void)parser:(ANSBJsonStreamParser*)parser shouldTransitionTo:(sbjson_token_t)tok {
	if (tok == sbjson_token_value_sep)
		parser.state = [ANSBJsonStreamParserStateArrayNeedValue sharedInstance];
}

@end

#pragma mark -

@implementation ANSBJsonStreamParserStateArrayNeedValue

SINGLETON

- (NSString*)name { return @"as array value"; }


- (BOOL)parser:(ANSBJsonStreamParser*)parser shouldAcceptToken:(sbjson_token_t)token {
	switch (token) {
		case sbjson_token_array_close:
        case sbjson_token_entry_sep:
		case sbjson_token_object_close:
		case sbjson_token_value_sep:
			return NO;
			break;

		default:
			return YES;
			break;
	}
}

- (void)parser:(ANSBJsonStreamParser*)parser shouldTransitionTo:(sbjson_token_t)tok {
	parser.state = [ANSBJsonStreamParserStateArrayGotValue sharedInstance];
}

@end

