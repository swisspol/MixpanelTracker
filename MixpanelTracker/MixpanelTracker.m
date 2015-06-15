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

#import <IOKit/network/IOEthernetController.h>
#import <CommonCrypto/CommonDigest.h>
#import <sys/sysctl.h>

#import "MixpanelTracker.h"
#import "Base64.h"

// See https://mixpanel.com/help/reference/http

#define kAPIHostname @"api.mixpanel.com"
#define kAPITimeOut 5.0
#define kAPIMaxBatchSize 50

#if DEBUG
#define kLogMaxWriteDelay 10.0
#define kLogMaxWritePending 5
#define kLogMaxSendDelay 30.0
#define kLogMaxSendPending 10
#define kMinActivateEventInterval 30.0
#else
#define kLogMaxWriteDelay 60.0
#define kLogMaxWritePending 20
#define kLogMaxSendDelay 300.0
#define kLogMaxSendPending 50
#define kMinActivateEventInterval 3600.0
#endif

#define kLogEntry_Kind @"Kind"
#define kLogEntry_Timestamp @"Timestamp"

#define kLogEntry_Kind_Event @"Event"
#define kLogEntry_EventName @"Name"
#define kLogEntry_EventProperties @"Properties"

#define kLogEntry_Kind_ProfileUpdate @"ProfileUpdate"
#define kLogEntry_ProfileUpdateSetProperties @"SetProperties"
#define kLogEntry_ProfileUpdateUnsetProperties @"UnsetProperties"

#define kLogEntry_Kind_Purchase @"Purchase"
#define kLogEntry_PurchaseAmount @"Amount"
#define kLogEntry_PurchaseAttributes @"Attributes"

#define LOG_ERROR(...) NSLog(__VA_ARGS__)
#define LOG_VERBOSE(...) \
  do { \
    if (_verboseLogging) { \
      NSLog(__VA_ARGS__); \
    } \
  } while (0)

NSString* const MixpanelTrackerUserProfileOperationSet = @"$set";
NSString* const MixpanelTrackerUserProfileOperationSetOnce = @"$set_once";
NSString* const MixpanelTrackerUserProfileOperationAdd = @"$add";
NSString* const MixpanelTrackerUserProfileOperationAppend = @"$append";
NSString* const MixpanelTrackerUserProfileOperationUnion = @"$union";
NSString* const MixpanelTrackerUserProfileOperationUnset = @"$unset";
NSString* const MixpanelTrackerUserProfileOperationDelete = @"$delete";

NSString* const MixpanelTrackerUserProfilePropertyFirstName = @"$first_name";
NSString* const MixpanelTrackerUserProfilePropertyLastName = @"$last_name";
NSString* const MixpanelTrackerUserProfilePropertyName = @"$name";
NSString* const MixpanelTrackerUserProfilePropertyCreated = @"$created";
NSString* const MixpanelTrackerUserProfilePropertyEmail = @"$email";
NSString* const MixpanelTrackerUserProfilePropertyPhone = @"$phone";

static NSString* const MixpanelTrackerUserProfilePropertyComputerModel = @"Computer Model";
static NSString* const MixpanelTrackerUserProfilePropertyAppVersion = @"App Version";
static NSString* const MixpanelTrackerUserProfilePropertyAppBuild = @"App Build";
static NSString* const MixpanelTrackerUserProfilePropertyOSVersion = @"OS Version";

static NSString* const MixpanelTrackerEventNameLaunch = @"Launch";
static NSString* const MixpanelTrackerEventNameActivate = @"Activate";

static BOOL _verboseLogging = NO;

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

static NSString* _GetDefaultDistinctID() {
  NSData* data = _CopyPrimaryMACAddress();
  if (data) {
    unsigned char hash[CC_MD5_DIGEST_LENGTH];
    CC_MD5_CTX context;
    CC_MD5_Init(&context);
    CC_MD5_Update(&context, data.bytes, (CC_LONG)data.length);
    const char* userName = [NSUserName() UTF8String];
    CC_MD5_Update(&context, userName, (CC_LONG)strlen(userName));
    CC_MD5_Final(hash, &context);
    
    char buffer[2 * CC_MD5_DIGEST_LENGTH];
    for (NSUInteger i = 0; i < CC_MD5_DIGEST_LENGTH; ++i) {
      char byte = hash[i];
      unsigned char byteHi = (byte & 0xF0) >> 4;
      buffer[2 * i + 0] = byteHi >= 10 ? 'A' + byteHi - 10 : '0' + byteHi;
      unsigned char byteLo = byte & 0x0F;
      buffer[2 * i + 1] = byteLo >= 10 ? 'A' + byteLo - 10 : '0' + byteLo;
    }
    return [[NSString alloc] initWithBytes:buffer length:sizeof(buffer) encoding:NSASCIIStringEncoding];
  }
  return @"<default>";
}

static NSDictionary* _GetDefaultUserProfileProperties() {
  NSString* computerModel = nil;
  size_t size;
  if (sysctlbyname("hw.model", NULL, &size, NULL, 0) == 0) {
    char* machine = malloc(size);
    if (sysctlbyname("hw.model", machine, &size, NULL, 0) == 0) {
      computerModel = [NSString stringWithUTF8String:machine];
    }
    free(machine);
  }
  NSString* appVersion = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"];
  NSString* appBuild = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleVersion"];
  NSData* data = [NSData dataWithContentsOfFile:@"/System/Library/CoreServices/SystemVersion.plist"];
  NSDictionary* propertyList = [NSPropertyListSerialization propertyListFromData:data mutabilityOption:NSPropertyListImmutable format:NULL errorDescription:NULL];
  NSString* osVersion = [propertyList objectForKey:@"ProductVersion"];
  return @{
           MixpanelTrackerUserProfilePropertyComputerModel: computerModel ? computerModel : @"",
           MixpanelTrackerUserProfilePropertyAppVersion: appVersion ? appVersion : @"",
           MixpanelTrackerUserProfilePropertyAppBuild: appBuild ? appBuild : @"",
           MixpanelTrackerUserProfilePropertyOSVersion: osVersion ? osVersion : @""
           };
}

@interface MixpanelTracker () {
  NSString* _token;
  NSDateFormatter* _dateFormatter;
  
  NSMutableArray* _log;
  dispatch_queue_t _logQueue;
  NSString* _logPath;
  NSUInteger _logPendingWrite;
  CFAbsoluteTime _lastLogWrite;
  CFAbsoluteTime _lastLogSend;
  BOOL _enableFlushing;
  BOOL _sending;
  CFAbsoluteTime _lastActivationTime;
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
    _dateFormatter = [[NSDateFormatter alloc] init];
    _dateFormatter.dateFormat = @"yyyy'-'MM'-'dd'T'HH':'mm':'ss";
    _dateFormatter.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
    _dateFormatter.timeZone = [NSTimeZone timeZoneWithAbbreviation:@"GMT"];
    
    _log = [[NSMutableArray alloc] init];
    _logQueue = dispatch_queue_create(NULL, DISPATCH_QUEUE_SERIAL);
    NSString* logFile = [NSString stringWithFormat:@"%@-%@.plist", [self class], [[NSBundle mainBundle] bundleIdentifier]];
    _logPath = [[NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES) firstObject] stringByAppendingPathComponent:logFile];
    if ([[NSFileManager defaultManager] fileExistsAtPath:_logPath]) {
      NSArray* log = nil;
      NSError* error = nil;
      NSData* data = [NSData dataWithContentsOfFile:_logPath options:0 error:&error];
      if (data) {
        log = [NSPropertyListSerialization propertyListWithData:data options:NSPropertyListImmutable format:NULL error:&error];
      }
      if (log) {
        [_log addObjectsFromArray:log];
        LOG_VERBOSE(@"Loaded Mixpanel log with %lu entries", (unsigned long)_log.count);
      } else {
        LOG_ERROR(@"Failed reading Mixpanel log from \"%@\": %@", _logPath, error);
      }
    } else {
      LOG_VERBOSE(@"Creating new Mixpanel log");
    }
  }
  return self;
}

- (void)setVerboseLoggingEnabled:(BOOL)flag {
  _verboseLogging = flag;
}

- (BOOL)isVerboseLoggingEnabled {
  return _verboseLogging;
}

- (void)startWithToken:(NSString*)token {
  assert(_token == nil);
  _token = [token copy];  // Assume there can be no race-conditions in practice
  
  _lastActivationTime = CFAbsoluteTimeGetCurrent();
  [self recordUserProfileUpdateWithSetProperties:_GetDefaultUserProfileProperties() unsetProperties:nil];
  [self recordEventWithName:MixpanelTrackerEventNameLaunch properties:nil];
  dispatch_sync(_logQueue, ^{
    _enableFlushing = YES;
    [self _flushLog:YES];
  });
  
  [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(_didBecomeActive:) name:NSApplicationDidBecomeActiveNotification object:nil];
  [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(_willResignActive:) name:NSApplicationWillResignActiveNotification object:nil];
  [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(_willTerminate:) name:NSApplicationWillTerminateNotification object:nil];
}

- (void)_didBecomeActive:(NSNotification*)notification {
  CFAbsoluteTime time = CFAbsoluteTimeGetCurrent();
  if (time >= _lastActivationTime + kMinActivateEventInterval) {
    [self recordEventWithName:MixpanelTrackerEventNameActivate properties:nil];
    _lastActivationTime = time;
  }
}

- (void)_willResignActive:(NSNotification*)notification {
  dispatch_sync(_logQueue, ^{
    [self _flushLog:NO];
  });
}

- (void)_willTerminate:(NSNotification*)notification {
  [self writeToDiskIfNeeded];
  [self waitForAsyncCompletion];
  [self sendToServerIfNeeded];
}

+ (NSURLRequest*)urlRequestForAPI:(NSString*)api withPayload:(id)payload usePOST:(BOOL)usePOST {
  NSData* data = [NSJSONSerialization dataWithJSONObject:payload options:0 error:NULL];
  NSMutableURLRequest* request;
  if (usePOST) {
    size_t length;
    char* buffer = NewBase64Encode(data.bytes, data.length, false, &length);
    NSString* url = [NSString stringWithFormat:@"https://%@/%@/", kAPIHostname, api];
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
    NSString* url = [NSString stringWithFormat:@"https://%@/%@/?data=%@", kAPIHostname, api, string];
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

+ (BOOL)checkAPI:(NSString*)api payload:(NSDictionary*)payload response:(NSURLResponse*)response data:(NSData*)data error:(NSError*)error {
  if (!data && [error.domain isEqualToString:NSURLErrorDomain] && ((error.code == NSURLErrorNotConnectedToInternet) || (error.code == kCFURLErrorCannotFindHost))) {
    LOG_VERBOSE(@"Cannot communicate with Mixpanel API since not connected to Internet");
    return NO;
  }
#if DEBUG
  NSDictionary* result = data ? [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL] : nil;
  if (![result isKindOfClass:[NSDictionary class]] || ([[result objectForKey:@"status"] integerValue] != 1)) {
    LOG_ERROR(@"Failed calling Mixpanel API '%@': %@", api, error ? error : [result objectForKey:@"error"]);
    return NO;
  }
  NSData* json = [NSJSONSerialization dataWithJSONObject:payload options:NSJSONWritingPrettyPrinted error:NULL];
  LOG_VERBOSE(@"Successfully called Mixpanel API '%@' with payload: %@", api, [[NSString alloc] initWithData:json encoding:NSUTF8StringEncoding]);
#else
  if ((data.length != 1) || (*(char*)data.bytes != '1')) {
    LOG_ERROR(@"Failed calling Mixpanel API '%@': %@", api, error ? error : response);
    return NO;
  }
#endif
  return YES;
}

+ (void)callAPI:(NSString*)api withPayload:(id)payload usePOST:(BOOL)usePOST async:(BOOL)async completionBlock:(void (^)(BOOL success))block {
  static dispatch_once_t token = 0;
  static NSOperationQueue* operationQueue = nil;
  dispatch_once(&token, ^{
    operationQueue = [[NSOperationQueue alloc] init];
  });
  NSURLRequest* request = [self urlRequestForAPI:api withPayload:payload usePOST:usePOST];
  if (async) {
    [NSURLConnection sendAsynchronousRequest:request queue:operationQueue completionHandler:^(NSURLResponse* response, NSData* data, NSError* error) {
      block([self checkAPI:api payload:payload response:response data:data error:error]);
    }];
  } else {
    NSError* error = nil;
    NSURLResponse* response = nil;
    NSData* data = [NSURLConnection sendSynchronousRequest:request returningResponse:&response error:&error];
    block([self checkAPI:api payload:payload response:response data:data error:error]);
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
  [[NSProcessInfo processInfo] disableSuddenTermination];
  [[self class] callAPI:@"track" withPayload:payload usePOST:NO async:YES completionBlock:^(BOOL success) {
    if (block) {
      dispatch_async(dispatch_get_main_queue(), ^{
        block(success);
        [[NSProcessInfo processInfo] enableSuddenTermination];
      });
    } else {
      [[NSProcessInfo processInfo] enableSuddenTermination];
    }
  }];
}

- (void)updateUserProfileWithOperation:(NSString*)operation value:(id)value updateLastSeen:(BOOL)update completionBlock:(void (^)(BOOL success))block {
  NSDictionary* payload = @{
                            @"$token": _token,
                            @"$distinct_id": _distinctID,
                            @"$time": [NSNumber numberWithInteger:(1000.0 * (CFAbsoluteTimeGetCurrent() + kCFAbsoluteTimeIntervalSince1970))],
                            @"$ignore_time": [NSNumber numberWithBool:!update],
                            operation: value
                            };
  [[NSProcessInfo processInfo] disableSuddenTermination];
  [[self class] callAPI:@"engage" withPayload:payload usePOST:NO async:YES completionBlock:^(BOOL success) {
    if (block) {
      dispatch_async(dispatch_get_main_queue(), ^{
        block(success);
        [[NSProcessInfo processInfo] enableSuddenTermination];
      });
    } else {
      [[NSProcessInfo processInfo] enableSuddenTermination];
    }
  }];
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
      double timestamp = [[entry objectForKey:kLogEntry_Timestamp] doubleValue] + kCFAbsoluteTimeIntervalSince1970;
      NSString* kind = [entry objectForKey:kLogEntry_Kind];
      if ([kind isEqualToString:kLogEntry_Kind_Event] && (eventPayload.count < kAPIMaxBatchSize)) {
        NSMutableDictionary* properties = [NSMutableDictionary dictionaryWithDictionary:[entry objectForKey:kLogEntry_EventProperties]];
        [properties setObject:_token forKey:@"token"];
        [properties setObject:[NSNumber numberWithInteger:timestamp] forKey:@"time"];
        [properties setObject:_distinctID forKey:@"distinct_id"];
        [eventPayload addObject:@{
                                  @"event": [entry objectForKey:kLogEntry_EventName],
                                  @"properties": properties
                                  }];
        [eventEntries addObject:entry];
      } else if ([kind isEqualToString:kLogEntry_Kind_ProfileUpdate] && (updatePayload.count < kAPIMaxBatchSize - 2)) {
        NSString* now = [_dateFormatter stringFromDate:[NSDate date]];
        [updatePayload addObject:@{
                                   @"$token": _token,
                                   @"$distinct_id": _distinctID,
                                   @"$time": [NSNumber numberWithInteger:(1000.0 * timestamp)],
                                   @"$ignore_time": @NO,
                                   MixpanelTrackerUserProfileOperationSetOnce: @{MixpanelTrackerUserProfilePropertyCreated: now}
                                   }];
        if ([[entry objectForKey:kLogEntry_ProfileUpdateSetProperties] count]) {
          [updatePayload addObject:@{
                                     @"$token": _token,
                                     @"$distinct_id": _distinctID,
                                     @"$time": [NSNumber numberWithInteger:(1000.0 * timestamp)],
                                     @"$ignore_time": @NO,
                                     MixpanelTrackerUserProfileOperationSet: [entry objectForKey:kLogEntry_ProfileUpdateSetProperties]
                                     }];
        }
        if ([[entry objectForKey:kLogEntry_ProfileUpdateUnsetProperties] count]) {
          [updatePayload addObject:@{
                                     @"$token": _token,
                                     @"$distinct_id": _distinctID,
                                     @"$time": [NSNumber numberWithInteger:(1000.0 * timestamp)],
                                     @"$ignore_time": @NO,
                                     MixpanelTrackerUserProfileOperationUnset: [entry objectForKey:kLogEntry_ProfileUpdateUnsetProperties]
                                     }];
        }
        [updateEntries addObject:entry];
      } else if ([kind isEqualToString:kLogEntry_Kind_Purchase] && (updatePayload.count < kAPIMaxBatchSize)) {
        NSMutableDictionary* attributes = [NSMutableDictionary dictionaryWithDictionary:[entry objectForKey:kLogEntry_PurchaseAttributes]];
        [attributes setObject:[_dateFormatter stringFromDate:[NSDate dateWithTimeIntervalSinceReferenceDate:[[entry objectForKey:kLogEntry_Timestamp] doubleValue]]] forKey:@"$time"];
        [attributes setObject:[entry objectForKey:kLogEntry_PurchaseAmount] forKey:@"$amount"];
        [updatePayload addObject:@{
                                   @"$token": _token,
                                   @"$distinct_id": _distinctID,
                                   @"$time": [NSNumber numberWithInteger:(1000.0 * timestamp)],
                                   @"$ignore_time": @NO,
                                   MixpanelTrackerUserProfileOperationAppend: @{
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
      if (async) {
        [[NSProcessInfo processInfo] disableSuddenTermination];
      }
      [[self class] callAPI:@"engage" withPayload:updatePayload usePOST:YES async:async completionBlock:^(BOOL success) {
        void (^block)() = ^() {
          if (success) {
            [self _removeLogEntries:updateEntries];
            _lastLogSend = CFAbsoluteTimeGetCurrent();
          }
          _updatePending = NO;
          if (_eventPending == NO) {
            _sending = NO;
          }
        };
        if (async) {
          dispatch_sync(_logQueue, block);
          [[NSProcessInfo processInfo] enableSuddenTermination];
        } else {
          block();
        }
      }];
    }
    if (eventPayload.count) {
      _eventPending = YES;
      if (async) {
        [[NSProcessInfo processInfo] disableSuddenTermination];
      }
      [[self class] callAPI:@"track" withPayload:eventPayload usePOST:YES async:async completionBlock:^(BOOL success) {
        void (^block)() = ^() {
          if (success) {
            [self _removeLogEntries:eventEntries];
            _lastLogSend = CFAbsoluteTimeGetCurrent();
          }
          _eventPending = NO;
          if (_updatePending == NO) {
            _sending = NO;
          }
        };
        if (async) {
          dispatch_sync(_logQueue, block);
          [[NSProcessInfo processInfo] enableSuddenTermination];
        } else {
          block();
        }
      }];
    }
  } else {
    LOG_VERBOSE(@"Skipping sending Mixpanel log to servers since already in the processing of sending a previous version");
  }
}

// Assume called from log queue
- (void)_writeLog {
  __block NSData* data = nil;
  NSError* error = nil;
  data = [NSPropertyListSerialization dataWithPropertyList:_log format:NSPropertyListBinaryFormat_v1_0 options:0 error:&error];
  if (data) {
    if (![data writeToFile:_logPath options:NSDataWritingAtomic error:&error]) {
      LOG_ERROR(@"Failed writing Mixpanel log to \"%@\": %@", _logPath, error);
    }
    else {
      if (_logPendingWrite != 0) {
        [[NSProcessInfo processInfo] enableSuddenTermination];
      }
      _logPendingWrite = 0;
      _lastLogWrite = CFAbsoluteTimeGetCurrent();
      LOG_VERBOSE(@"Saved Mixpanel log with %lu entries", (unsigned long)_log.count);
    }
  } else {
    LOG_ERROR(@"Failed serializing Mixpanel log: %@", error);
  }
}

// Assume called from log queue
- (void)_flushLog:(BOOL)force {
  if (_enableFlushing) {
    if (force || (_logPendingWrite >= kLogMaxWritePending) || ((_logPendingWrite > 0) && (CFAbsoluteTimeGetCurrent() >= _lastLogWrite + kLogMaxWriteDelay))) {
      [self _writeLog];
    }
    if (force || (_log.count >= kLogMaxSendPending) || ((_log.count > 0) && (CFAbsoluteTimeGetCurrent() >= _lastLogSend + kLogMaxSendDelay))) {
      [self _sendLog:YES];
    }
  }
}

// Assume called from log queue
- (void)_addLogEntry:(NSDictionary*)entry forceFlush:(BOOL)force {
  if (_logPendingWrite == 0) {
    [[NSProcessInfo processInfo] disableSuddenTermination];
  }
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
    LOG_VERBOSE(@"Recorded Mixpanel event \"%@\" with properties: %@", name, properties);
  });
}

- (void)recordUserProfileUpdateWithSetProperties:(NSDictionary*)setProperties unsetProperties:(NSArray*)unsetProperties {
  NSDictionary* entry = @{
                          kLogEntry_Kind: kLogEntry_Kind_ProfileUpdate,
                          kLogEntry_Timestamp: [NSNumber numberWithDouble:CFAbsoluteTimeGetCurrent()],
                          kLogEntry_ProfileUpdateSetProperties: setProperties ? setProperties : @{},
                          kLogEntry_ProfileUpdateUnsetProperties: unsetProperties ? unsetProperties : @[]
                          };
  dispatch_sync(_logQueue, ^{
    [self _addLogEntry:entry forceFlush:NO];
    if (setProperties.count) {
      LOG_VERBOSE(@"Recorded Mixpanel user profile update with set properties: %@", setProperties);
    }
    if (unsetProperties.count) {
      LOG_VERBOSE(@"Recorded Mixpanel user profile update with unset properties: %@", unsetProperties);
    }
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
    LOG_VERBOSE(@"Recorded Mixpanel purchase for \"%f\" with attributes: %@", amount, attributes);
  });
}

- (void)writeToDiskIfNeeded {
  dispatch_sync(_logQueue, ^{
    if (_logPendingWrite > 0) {
      [self _writeLog];
    }
  });
}

- (void)sendToServerIfNeeded {
  dispatch_sync(_logQueue, ^{
    if (_log.count) {
      [self _sendLog:NO];
    }
  });
}

- (void)waitForAsyncCompletion {
  while (1) {
    __block BOOL sending;
    dispatch_sync(_logQueue, ^{
      sending = _sending;
    });
    if (!sending) {
      break;
    }
    usleep(50 * 1000);  // Wait 50 ms and try again
  }
}

@end
