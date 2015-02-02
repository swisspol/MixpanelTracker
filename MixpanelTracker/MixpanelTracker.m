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

#import <SystemConfiguration/SystemConfiguration.h>
#import <IOKit/network/IOEthernetController.h>
#import <CommonCrypto/CommonDigest.h>
#import <sys/sysctl.h>

#import "MixpanelTracker.h"
#import "Base64.h"

// See https://mixpanel.com/help/reference/http

#define kAPIHostname @"api.mixpanel.com"
#define kAPITimeOut 5.0
#define kAPIMaxBatchSize 50

#define kLogFile @"MixpanelTracker.plist"
#if !DEBUG
#define kLogMaxWriteDelay 60.0
#define kLogMaxWritePending 20
#define kLogMaxSendDelay 300.0
#define kLogMaxSendPending 50
#else
#define kLogMaxWriteDelay 10.0
#define kLogMaxWritePending 5
#define kLogMaxSendDelay 30.0
#define kLogMaxSendPending 10
#endif

#define kLogEntry_Kind @"Kind"
#define kLogEntry_Timestamp @"Timestamp"

#define kLogEntry_Kind_Event @"Event"
#define kLogEntry_EventName @"Name"
#define kLogEntry_EventProperties @"Properties"

#define kLogEntry_Kind_ProfileCreation @"ProfileCreation"

#define kLogEntry_Kind_ProfileUpdate @"ProfileUpdate"
#define kLogEntry_ProfileUpdateAddedProperties @"AddedProperties"
#define kLogEntry_ProfileUpdateRemovedProperties @"RemovedProperties"

#define kLogEntry_Kind_Purchase @"Purchase"
#define kLogEntry_PurchaseAmount @"Amount"
#define kLogEntry_PurchaseAttributes @"Attributes"

static NSString* const MixpanelTrackerUserProfilePropertyCreated = @"Created";
static NSString* const MixpanelTrackerUserProfilePropertyName = @"Name";
static NSString* const MixpanelTrackerUserProfilePropertyComputerModel = @"Computer Model";
static NSString* const MixpanelTrackerUserProfilePropertyComputerName = @"Computer Name";
static NSString* const MixpanelTrackerUserProfilePropertyAppVersion = @"App Version";
static NSString* const MixpanelTrackerUserProfilePropertyOSVersion = @"OS Version";

static NSString* const MixpanelTrackerEventNameLaunch = @"Launch";
static NSString* const MixpanelTrackerEventNameQuit = @"Quit";

static BOOL _CheckNetwork() {
  BOOL online = YES;
  SCNetworkReachabilityRef reachabilityRef = SCNetworkReachabilityCreateWithName(kCFAllocatorDefault, [kAPIHostname UTF8String]);
  if (reachabilityRef) {
    SCNetworkConnectionFlags flags;
    if (SCNetworkReachabilityGetFlags(reachabilityRef, &flags) && (!(flags & kSCNetworkReachabilityFlagsReachable) || (flags & kSCNetworkReachabilityFlagsConnectionRequired))) {
      online = NO;
    }
    CFRelease(reachabilityRef);
  }
  return online;
}

static NSData* _CopyPrimaryMACAddress() {
  NSData* data = nil;
  mach_port_t masterPort;
  if (IOMasterPort(MACH_PORT_NULL, &masterPort) == KERN_SUCCESS) {
    CFMutableDictionaryRef matchingDict = IOBSDNameMatching(masterPort, 0, "en0");
    io_iterator_t iterator;
    if (IOServiceGetMatchingServices(masterPort, matchingDict, &iterator) == KERN_SUCCESS) {  // Consumes a reference to "matchingDict"
      io_object_t service;
      while ((service = IOIteratorNext(iterator)) != 0) {
        io_object_t parentService;
        if (IORegistryEntryGetParentEntry(service, kIOServicePlane, &parentService) == KERN_SUCCESS) {
          if (data == nil) {
            CFTypeRef property = IORegistryEntryCreateCFProperty(parentService, CFSTR(kIOMACAddress), kCFAllocatorDefault, 0);
            if (property) {
              data = CFBridgingRelease(property);
            }
          }
          IOObjectRelease(parentService);
        }
        IOObjectRelease(service);
      }
      IOObjectRelease(iterator);
    }
  }
  return data;
}

static inline NSString* _HashToString(const unsigned char* hash, NSUInteger size) {
  char buffer[2 * size];
  for (NSUInteger i = 0; i < size; ++i) {
    char byte = hash[i];
    unsigned char byteHi = (byte & 0xF0) >> 4;
    buffer[2 * i + 0] = byteHi >= 10 ? 'A' + byteHi - 10 : '0' + byteHi;
    unsigned char byteLo = byte & 0x0F;
    buffer[2 * i + 1] = byteLo >= 10 ? 'A' + byteLo - 10 : '0' + byteLo;
  }
  return [[NSString alloc] initWithBytes:buffer length:(2 * size) encoding:NSASCIIStringEncoding];
}

static NSString* _GetDefaultDistinctID() {
  NSData* data = _CopyPrimaryMACAddress();
  if (data) {
    unsigned char hash[CC_MD5_DIGEST_LENGTH];
    CC_MD5_CTX context;
    CC_MD5_Init(&context);
    CC_MD5_Update(&context, data.bytes, data.length);
    const char* userName = [NSUserName() UTF8String];
    CC_MD5_Update(&context, userName, strlen(userName));
    CC_MD5_Final(hash, &context);
    return _HashToString(hash, sizeof(hash));
  }
  return @"<default>";
}

static NSDictionary* _GetDefaultUserProfileProperties() {
  size_t size;
  sysctlbyname("hw.model", NULL, &size, NULL, 0);
  char* machine = malloc(size);
  sysctlbyname("hw.model", machine, &size, NULL, 0);
  NSString* computerModel = [NSString stringWithUTF8String:machine];
  free(machine);
  NSString* computerName = CFBridgingRelease(SCDynamicStoreCopyComputerName(NULL, NULL));
  NSString* appVersion = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"];
  NSData* data = [NSData dataWithContentsOfFile:@"/System/Library/CoreServices/SystemVersion.plist"];
  NSDictionary* propertyList = [NSPropertyListSerialization propertyListFromData:data mutabilityOption:NSPropertyListImmutable format:NULL errorDescription:NULL];
  NSString* osVersion = [propertyList objectForKey:@"ProductVersion"];
  return @{
           MixpanelTrackerUserProfilePropertyName: NSFullUserName(),
           MixpanelTrackerUserProfilePropertyComputerModel: computerModel ? computerModel : @"",
           MixpanelTrackerUserProfilePropertyComputerName: computerName ? computerName : @"",
           MixpanelTrackerUserProfilePropertyAppVersion: appVersion ? appVersion : @"",
           MixpanelTrackerUserProfilePropertyOSVersion: osVersion ? osVersion : @""
           };
}

@interface MixpanelTracker () {
  NSString* _token;
  NSString* _distinctID;
  NSDictionary* _userProfileProperties;
  NSDateFormatter* _dateFormatter;
  NSMutableArray* _log;
  dispatch_queue_t _logQueue;
  NSString* _logPath;
  NSUInteger _logPendingWrite;
  CFAbsoluteTime _lastLogWrite;
  CFAbsoluteTime _lastLogSend;
  BOOL _sending;
}
@end

@implementation MixpanelTracker

+ (MixpanelTracker*)sharedTracker {
  static MixpanelTracker* tracker = nil;
  static dispatch_once_t token = 0;
  dispatch_once(&token, ^{
    tracker = [[MixpanelTracker alloc] init];
  });
  return tracker;
}

+ (void)startWithToken:(NSString*)token {
  [[MixpanelTracker sharedTracker] startWithToken:token];
}

- (id)init {
  if ((self = [super init])) {
    _distinctID = _GetDefaultDistinctID();
    _userProfileProperties = _GetDefaultUserProfileProperties();
    _dateFormatter = [[NSDateFormatter alloc] init];
    _dateFormatter.dateFormat = @"yyyy'-'MM'-'dd'T'HH':'mm':'ss";
    _dateFormatter.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
    _dateFormatter.timeZone = [NSTimeZone timeZoneWithAbbreviation:@"GMT"];
    _log = [[NSMutableArray alloc] init];
    _logQueue = dispatch_queue_create(NULL, DISPATCH_QUEUE_SERIAL);
    _logPath = [[NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES) firstObject] stringByAppendingPathComponent:kLogFile];
    
    if ([[NSFileManager defaultManager] fileExistsAtPath:_logPath]) {
      NSArray* log = nil;
      NSError* error = nil;
      NSData* data = [NSData dataWithContentsOfFile:_logPath options:0 error:&error];
      if (data) {
        log = [NSPropertyListSerialization propertyListWithData:data options:NSPropertyListImmutable format:NULL error:&error];
      }
      if (log) {
        [_log addObjectsFromArray:log];
#if DEBUG
        NSLog(@"Loaded Mixpanel log with %lu entries", (unsigned long)_log.count);
#endif
      } else {
        NSLog(@"Failed reading Mixpanel log from \"%@\": %@", _logPath, error);
      }
    } else {
#if DEBUG
      NSLog(@"Creating new Mixpanel log");
#endif
      NSDictionary* entry = @{
                              kLogEntry_Kind: kLogEntry_Kind_ProfileCreation,
                              kLogEntry_Timestamp: [NSNumber numberWithDouble:CFAbsoluteTimeGetCurrent()]
                              };
      [_log addObject:entry];
      _logPendingWrite += 1;
    }
  }
  return self;
}

- (void)startWithToken:(NSString*)token {
  _token = [token copy];
  [self recordEventWithName:MixpanelTrackerEventNameLaunch properties:nil];
  [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(_willResignActive:) name:NSApplicationWillResignActiveNotification object:nil];
  [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(_willTerminate:) name:NSApplicationWillTerminateNotification object:nil];
}

- (void)_willResignActive:(NSNotification*)notification {
  dispatch_sync(_logQueue, ^{
    [self _flushLog:NO];
  });
}

- (void)_willTerminate:(NSNotification*)notification {
  [self recordEventWithName:MixpanelTrackerEventNameQuit properties:nil];
  [self writeToDiskIfNeeded];
  [self sendToServerIfNeeded:NO];
}

- (NSURLRequest*)_urlRequestForAPI:(NSString*)api withPayload:(id)payload usePost:(BOOL)usePost {
  NSData* data = [NSJSONSerialization dataWithJSONObject:payload options:0 error:NULL];
  NSMutableURLRequest* request;
  if (usePost) {
    size_t length;
    char* buffer = NewBase64Encode(data.bytes, data.length, false, &length);
    NSString* url = [NSString stringWithFormat:@"http://%@/%@/", kAPIHostname, api];
    request = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:url]];
    [request setHTTPMethod:@"POST"];
    [request setValue:@"application/x-www-form-urlencoded" forHTTPHeaderField:@"Content-Type"];
    NSMutableData* body = [NSMutableData dataWithBytes:"data=" length:5];
    [body appendBytes:buffer length:length];
#if DEBUG
    [body appendBytes:"&verbose=1" length:10];
#endif
    [request setHTTPBody:body];
    [request setValue:[[NSNumber numberWithUnsignedInteger:body.length] stringValue] forHTTPHeaderField:@"Content-Length"];
    free(buffer);
  } else {
    size_t length;
    char* buffer = NewBase64Encode(data.bytes, data.length, false, &length);
    NSString* string = [[NSString alloc] initWithBytes:buffer length:length encoding:NSASCIIStringEncoding];
    NSString* url = [NSString stringWithFormat:@"http://%@/%@/?data=%@", kAPIHostname, api, string];
#if DEBUG
    url = [url stringByAppendingString:@"&verbose=1"];
#endif
    request = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:url]];
    free(buffer);
  }
  [request setCachePolicy:NSURLRequestReloadIgnoringLocalCacheData];
  [request setTimeoutInterval:kAPITimeOut];
  return request;
}

- (BOOL)_checkAPI:(NSString*)api payload:(NSDictionary*)payload response:(NSURLResponse*)response data:(NSData*)data error:(NSError*)error {
#if !DEBUG
  if ((data.length != 1) || (*(char*)data.bytes != '1')) {
    NSLog(@"Failed calling Mixpanel API '%@': %@", api, error ? error : response);
    return NO;
  }
#else
  NSDictionary* result = data ? [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL] : nil;
  if (![result isKindOfClass:[NSDictionary class]] || ([[result objectForKey:@"status"] integerValue] != 1)) {
    NSLog(@"Failed calling Mixpanel API '%@': %@", api, error ? error : [result objectForKey:@"status"]);
    return NO;
  }
  NSData* json = [NSJSONSerialization dataWithJSONObject:payload options:NSJSONWritingPrettyPrinted error:NULL];
  NSLog(@"Successfully called Mixpanel API '%@' with payload: %@", api, [[NSString alloc] initWithData:json encoding:NSUTF8StringEncoding]);
#endif
  return YES;
}

- (void)_callAPI:(NSString*)api withPayload:(id)payload usePost:(BOOL)usePost async:(BOOL)async completionBlock:(void (^)(BOOL success))block {
  NSURLRequest* request = [self _urlRequestForAPI:api withPayload:payload usePost:usePost];
  if (async) {
    [NSURLConnection sendAsynchronousRequest:request queue:[NSOperationQueue mainQueue] completionHandler:^(NSURLResponse* response, NSData* data, NSError* error) {
      BOOL success = [self _checkAPI:api payload:payload response:response data:data error:error];
      if (block) {
        block(success);
      }
    }];
  } else {
    NSError* error = nil;
    NSURLResponse* response = nil;
    NSData* data = [NSURLConnection sendSynchronousRequest:request returningResponse:&response error:&error];
    BOOL success = [self _checkAPI:api payload:payload response:response data:data error:error];
    if (block) {
      block(success);
    }
  }
}

- (void)sendEventWithName:(NSString*)name properties:(NSDictionary*)properties completionBlock:(void (^)(BOOL success))block {
  NSMutableDictionary* extendedProperties = [NSMutableDictionary dictionaryWithDictionary:properties];
  [extendedProperties setObject:_token forKey:@"token"];
  [extendedProperties setObject:[NSNumber numberWithInteger:(CFAbsoluteTimeGetCurrent() + kCFAbsoluteTimeIntervalSince1970)] forKey:@"time"];
  [extendedProperties setObject:_distinctID forKey:@"distinct_id"];
  NSDictionary* payload = @{
                            @"event": name,
                            @"properties": extendedProperties
                            };
  [self _callAPI:@"track" withPayload:payload usePost:NO async:YES completionBlock:block];
}

- (void)updateUserProfileWithOperation:(NSString*)operation value:(id)value updateLastSeen:(BOOL)update completionBlock:(void (^)(BOOL success))block {
  NSDictionary* payload = @{
                            @"$token": _token,
                            @"$distinct_id": _distinctID,
                            @"$time": [NSNumber numberWithInteger:(1000.0 * (CFAbsoluteTimeGetCurrent() + kCFAbsoluteTimeIntervalSince1970))],
                            @"$ignore_time": [NSNumber numberWithBool:!update],
                            operation: value
                            };
  [self _callAPI:@"engage" withPayload:payload usePost:NO async:YES completionBlock:block];
}

// Assume called from log queue
- (void)_removeLogEntries:(NSSet*)entries {
  NSMutableArray* log = [[NSMutableArray alloc] initWithCapacity:_log.count];
  for (NSDictionary* entry in _log) {
    if (![entries containsObject:entry]) {
      [log addObject:entry];
    }
  }
  _log = log;
  [self _writeLog];
}

// Assume called from log queue
- (void)_sendLog:(BOOL)async {
  if (_sending == NO) {
    NSMutableArray* eventPayload = [[NSMutableArray alloc] init];
    NSMutableSet* eventEntries = [[NSMutableSet alloc] init];
    NSMutableArray* updatePayload = [[NSMutableArray alloc] init];
    NSMutableSet* updateEntries = [[NSMutableSet alloc] init];
    for (NSDictionary* entry in _log) {
      NSString* kind = [entry objectForKey:kLogEntry_Kind];
      if ([kind isEqualToString:kLogEntry_Kind_Event] && (updateEntries.count < kAPIMaxBatchSize)) {
        NSMutableDictionary* properties = [NSMutableDictionary dictionaryWithDictionary:[entry objectForKey:kLogEntry_EventProperties]];
        [properties setObject:_token forKey:@"token"];
        [properties setObject:[NSNumber numberWithInteger:([[entry objectForKey:kLogEntry_Timestamp] doubleValue] + kCFAbsoluteTimeIntervalSince1970)] forKey:@"time"];
        [properties setObject:_distinctID forKey:@"distinct_id"];
        [eventPayload addObject:@{
                                  @"event": [entry objectForKey:kLogEntry_EventName],
                                  @"properties": properties
                                  }];
        [eventEntries addObject:entry];
      } else if ([kind isEqualToString:kLogEntry_Kind_ProfileCreation] && (updateEntries.count < kAPIMaxBatchSize)) {
        NSString* now = [_dateFormatter stringFromDate:[NSDate date]];
        NSMutableDictionary* properties = [NSMutableDictionary dictionaryWithDictionary:_userProfileProperties];
        [properties setObject:now forKey:MixpanelTrackerUserProfilePropertyCreated];
        [updatePayload addObject:@{
                                   @"$token": _token,
                                   @"$distinct_id": _distinctID,
                                   @"$time": [NSNumber numberWithInteger:(1000.0 * ([[entry objectForKey:kLogEntry_Timestamp] doubleValue] + kCFAbsoluteTimeIntervalSince1970))],
                                   @"$ignore_time": @NO,
                                   @"$set_once": properties
                                   }];
        [updateEntries addObject:entry];
      } else if ([kind isEqualToString:kLogEntry_Kind_ProfileUpdate] && (updateEntries.count < kAPIMaxBatchSize - 1)) {
        if ([[entry objectForKey:kLogEntry_ProfileUpdateAddedProperties] count]) {
          [updatePayload addObject:@{
                                     @"$token": _token,
                                     @"$distinct_id": _distinctID,
                                     @"$time": [NSNumber numberWithInteger:(1000.0 * ([[entry objectForKey:kLogEntry_Timestamp] doubleValue] + kCFAbsoluteTimeIntervalSince1970))],
                                     @"$ignore_time": @NO,
                                     @"$set": [entry objectForKey:kLogEntry_ProfileUpdateAddedProperties]
                                     }];
        }
        if ([[entry objectForKey:kLogEntry_ProfileUpdateRemovedProperties] count]) {
          [updatePayload addObject:@{
                                     @"$token": _token,
                                     @"$distinct_id": _distinctID,
                                     @"$time": [NSNumber numberWithInteger:(1000.0 * ([[entry objectForKey:kLogEntry_Timestamp] doubleValue] + kCFAbsoluteTimeIntervalSince1970))],
                                     @"$ignore_time": @NO,
                                     @"$unset": [entry objectForKey:kLogEntry_ProfileUpdateRemovedProperties]
                                     }];
        }
        [updateEntries addObject:entry];
      } if ([kind isEqualToString:kLogEntry_Kind_Purchase] && (updatePayload.count < kAPIMaxBatchSize)) {
        NSMutableDictionary* attributes = [NSMutableDictionary dictionaryWithDictionary:[entry objectForKey:kLogEntry_PurchaseAttributes]];
        [attributes setObject:[_dateFormatter stringFromDate:[NSDate dateWithTimeIntervalSinceReferenceDate:[[entry objectForKey:kLogEntry_Timestamp] doubleValue]]] forKey:@"$time"];
        [attributes setObject:[entry objectForKey:kLogEntry_PurchaseAmount] forKey:@"$amount"];
        [updatePayload addObject:@{
                                   @"$token": _token,
                                   @"$distinct_id": _distinctID,
                                   @"$time": [NSNumber numberWithInteger:(1000.0 * ([[entry objectForKey:kLogEntry_Timestamp] doubleValue] + kCFAbsoluteTimeIntervalSince1970))],
                                   @"$ignore_time": @NO,
                                   @"$append": @{
                                       @"$transactions": attributes
                                       }
                                   }];
        [updateEntries addObject:entry];
      }
    }
    
    _sending = YES;
    __block BOOL _eventPending = NO;
    __block BOOL _updatePending = NO;
    if (updatePayload.count) {
      _updatePending = YES;
      [self _callAPI:@"engage" withPayload:updatePayload usePost:YES async:async completionBlock:^(BOOL success) {
        if (success) {
          if (async) {
            dispatch_sync(_logQueue, ^{
              [self _removeLogEntries:updateEntries];
              _lastLogSend = CFAbsoluteTimeGetCurrent();
            });
          } else {
            [self _removeLogEntries:updateEntries];
            _lastLogSend = CFAbsoluteTimeGetCurrent();
          }
        }
        _updatePending = NO;
        if (_eventPending == NO) {
          _sending = NO;
        }
      }];
    }
    if (eventPayload.count) {
      _eventPending = YES;
      [self _callAPI:@"track" withPayload:eventPayload usePost:YES async:async completionBlock:^(BOOL success) {
        if (success) {
          if (async) {
            dispatch_sync(_logQueue, ^{
              [self _removeLogEntries:eventEntries];
              _lastLogSend = CFAbsoluteTimeGetCurrent();
            });
          } else {
            [self _removeLogEntries:eventEntries];
            _lastLogSend = CFAbsoluteTimeGetCurrent();
          }
        }
        _eventPending = NO;
        if (_updatePending == NO) {
          _sending = NO;
        }
      }];
    }
  }
}

// Assume called from log queue
- (void)_writeLog {
  __block NSData* data = nil;
  NSError* error = nil;
  data = [NSPropertyListSerialization dataWithPropertyList:_log format:NSPropertyListBinaryFormat_v1_0 options:0 error:&error];
  if (data) {
    if (![data writeToFile:_logPath options:NSDataWritingAtomic error:&error]) {
      NSLog(@"Failed writing Mixpanel log to \"%@\": %@", _logPath, error);
    }
    else {
      _logPendingWrite = 0;
      _lastLogWrite = CFAbsoluteTimeGetCurrent();
#if DEBUG
      NSLog(@"Saved Mixpanel log with %lu entries", (unsigned long)_log.count);
#endif
    }
  } else {
    NSLog(@"Failed serializing Mixpanel log: %@", error);
  }
}

// Assume called from log queue
- (void)_flushLog:(BOOL)force {
  if (force || (_logPendingWrite >= kLogMaxWritePending) || ((_logPendingWrite > 0) && (CFAbsoluteTimeGetCurrent() >= _lastLogWrite + kLogMaxWriteDelay))) {
    [self _writeLog];
  }
  if (force || (_log.count >= kLogMaxSendPending) || ((_log.count > 0) && (CFAbsoluteTimeGetCurrent() >= _lastLogSend + kLogMaxSendDelay))) {
    [self _sendLog:YES];
  }
}

// Assume called from log queue
- (void)_addLogEntry:(NSDictionary*)entry forceFlush:(BOOL)force {
  [_log addObject:entry];
  _logPendingWrite += 1;
  [self _flushLog:force];
}

- (void)recordEventWithName:(NSString*)name properties:(NSDictionary*)properties {
  NSDictionary* entry = @{
                          kLogEntry_Kind: kLogEntry_Kind_Event,
                          kLogEntry_Timestamp: [NSNumber numberWithDouble:CFAbsoluteTimeGetCurrent()],
                          kLogEntry_EventName: name,
                          kLogEntry_EventProperties: properties ? properties : @{}
                          };
  dispatch_sync(_logQueue, ^{
    [self _addLogEntry:entry forceFlush:NO];
#if DEBUG
    NSLog(@"Recorded Mixpanel event \"%@\" with properties: %@", name, properties);
#endif
  });
}

- (void)recordUserProfileCreation {
  NSDictionary* entry = @{
                          kLogEntry_Kind: kLogEntry_Kind_ProfileCreation,
                          kLogEntry_Timestamp: [NSNumber numberWithDouble:CFAbsoluteTimeGetCurrent()]
                          };
  dispatch_sync(_logQueue, ^{
    [self _addLogEntry:entry forceFlush:NO];
#if DEBUG
    NSLog(@"Recorded Mixpanel user profile creation");
#endif
  });
}

- (void)recordUserProfileUpdateWithAddedProperties:(NSDictionary*)addedProperties removedProperties:(NSArray*)removedProperties {
  NSDictionary* entry = @{
                          kLogEntry_Kind: kLogEntry_Kind_ProfileUpdate,
                          kLogEntry_Timestamp: [NSNumber numberWithDouble:CFAbsoluteTimeGetCurrent()],
                          kLogEntry_ProfileUpdateAddedProperties: addedProperties ? addedProperties : @{},
                          kLogEntry_ProfileUpdateRemovedProperties: removedProperties ? removedProperties : @[]
                          };
  dispatch_sync(_logQueue, ^{
    [self _addLogEntry:entry forceFlush:NO];
#if DEBUG
    if (addedProperties.count) {
      NSLog(@"Recorded Mixpanel user profile update with added properties: %@", addedProperties);
    }
    if (removedProperties.count) {
      NSLog(@"Recorded Mixpanel user profile update with removed properties: %@", removedProperties);
    }
#endif
  });
}

- (void)recordPurchaseWithAmount:(float)amount attributes:(NSDictionary*)attributes {
  NSDictionary* entry = @{
                          kLogEntry_Kind: kLogEntry_Kind_Purchase,
                          kLogEntry_Timestamp: [NSNumber numberWithDouble:CFAbsoluteTimeGetCurrent()],
                          kLogEntry_PurchaseAmount: [NSNumber numberWithFloat:amount],
                          kLogEntry_PurchaseAttributes: attributes ? attributes : @{}
                          };
  dispatch_sync(_logQueue, ^{
    [self _addLogEntry:entry forceFlush:YES];
#if DEBUG
    NSLog(@"Recorded Mixpanel purchase for \"%f\" with attributes: %@", amount, attributes);
#endif
  });
}

- (void)writeToDiskIfNeeded {
  dispatch_sync(_logQueue, ^{
    if (_logPendingWrite > 0) {
      [self _writeLog];
    }
  });
}

- (void)sendToServerIfNeeded:(BOOL)async {
  dispatch_sync(_logQueue, ^{
    if (_log.count && _CheckNetwork()) {
      [self _sendLog:async];
    }
  });
}

@end
