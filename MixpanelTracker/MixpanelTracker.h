/*
 Copyright (c) 2014, Pierre-Olivier Latour
 All rights reserved.
 
 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:
 * Redistributions of source code must retain the above copyright
 notice, this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
 notice, this list of conditions and the following disclaimer in the
 documentation and/or other materials provided with the distribution.
 * The name of Pierre-Olivier Latour may not be used to endorse
 or promote products derived from this software without specific
 prior written permission.
 
 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 DISCLAIMED. IN NO EVENT SHALL PIERRE-OLIVIER LATOUR BE LIABLE FOR ANY
 DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#import <AppKit/AppKit.h>

#define MIXPANEL_TRACK_EVENT(__NAME__, __PROPERTIES__) [[MixpanelTracker sharedTracker] recordEventWithName:(__NAME__) properties:(__PROPERTIES__)]
#define MIXPANEL_TRACK_PURCHASE(__AMOUNT__, __ATTRIBUTES__) [[MixpanelTracker sharedTracker] recordPurchaseWithAmount:(__AMOUNT__) attributes:(__ATTRIBUTES__)]

@interface MixpanelTracker : NSObject
+ (MixpanelTracker*)sharedTracker;
+ (void)startWithToken:(NSString*)token;  // Call from -applicationDidFinishLaunching:

- (void)sendEventWithName:(NSString*)name properties:(NSDictionary*)properties completionBlock:(void (^)(BOOL success))block;
- (void)updateUserProfileWithOperation:(NSString*)operation value:(id)value updateLastSeen:(BOOL)update completionBlock:(void (^)(BOOL success))block;

- (void)recordEventWithName:(NSString*)name properties:(NSDictionary*)properties;
- (void)recordUserProfileCreation;
- (void)recordUserProfileUpdateWithAddedProperties:(NSDictionary*)addedProperties removedProperties:(NSArray*)removedProperties;
- (void)recordPurchaseWithAmount:(float)amount attributes:(NSDictionary*)attributes;
@end
