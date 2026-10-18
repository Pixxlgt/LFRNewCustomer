#import <UIKit/UIKit.h>
#import <AdSupport/AdSupport.h>
#import <AppTrackingTransparency/AppTrackingTransparency.h>
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
#import <unistd.h>
#import <dlfcn.h>

static NSString *gIDFV = nil;
static NSString *gIDFA = nil;
static dispatch_once_t gInitOnce;

static NSUUID *fakeIDFV(){ return [[NSUUID alloc] initWithUUIDString:gIDFV]; }
static NSUUID *fakeIDFA(){ return [[NSUUID alloc] initWithUUIDString:gIDFA]; }

static void wipeDeviceKeychain(void) {
    NSArray *accounts = @[@"device_uuid",@"deviceId",@"device_id",@"appsflyerId",
        @"appsFlyerId",@"appsflyer_id",@"adjustDeviceId",@"adid",@"gps_adid",
        @"vendorId",@"idfv",@"IDFV",@"advertisingId",@"idfa",@"IDFA",
        @"installId",@"installationId"];
    NSArray *classes = @[(__bridge id)kSecClassGenericPassword,
                         (__bridge id)kSecClassInternetPassword];
    for (id cls in classes) for (NSString *a in accounts) {
        NSDictionary *q = @{(__bridge id)kSecClass:cls,(__bridge id)kSecAttrAccount:a};
        SecItemDelete((__bridge CFDictionaryRef)q);
    }
}

static void initIDsOnce(void) {
    dispatch_once(&gInitOnce, ^{
        NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
        NSString *mode = [d stringForKey:@"LFRRotateMode"] ?: @"launch";
        BOOL wipeKC = ([d objectForKey:@"LFRWipeKeychain"] == nil) || [d boolForKey:@"LFRWipeKeychain"];

        BOOL rotate = NO;
        if ([mode isEqualToString:@"launch"]) rotate = YES;
        else if ([mode isEqualToString:@"manual"]) {
            if ([d boolForKey:@"LFRRotateNow"]) { rotate = YES; [d setBool:NO forKey:@"LFRRotateNow"]; }
        } else {
            rotate = ([d stringForKey:@"LFRIDFV"] == nil);
        }

        if (rotate) {
            [d setObject:[[NSUUID UUID] UUIDString] forKey:@"LFRIDFV"];
            [d setObject:[[NSUUID UUID] UUIDString] forKey:@"LFRIDFA"];
            [d setObject:[NSDate date] forKey:@"LFRRotatedAt"];
            [d synchronize];
            if (wipeKC) wipeDeviceKeychain();
            NSLog(@"[LFR] rotated mode=%@", mode);
        }
        gIDFV = [d stringForKey:@"LFRIDFV"];
        gIDFA = [d stringForKey:@"LFRIDFA"];
        if (!gIDFV) { gIDFV = [[NSUUID UUID] UUIDString]; [d setObject:gIDFV forKey:@"LFRIDFV"]; }
        if (!gIDFA) { gIDFA = [[NSUUID UUID] UUIDString]; [d setObject:gIDFA forKey:@"LFRIDFA"]; }
    });
}

%hook UIDevice
- (NSUUID *)identifierForVendor { initIDsOnce(); return fakeIDFV(); }
%end

%hook ASIdentifierManager
- (NSUUID *)advertisingIdentifier { initIDsOnce(); return fakeIDFA(); }
- (BOOL)isAdvertisingTrackingEnabled { return YES; }
- (NSUUID *)advertisingIdentifierForVendor { initIDsOnce(); return fakeIDFA(); }
%end

%hook ATTrackingManager
+ (NSInteger)trackingAuthorizationStatus { return 3; }
%end

static BOOL isJBPath(NSString *p){
    static NSSet *set; static dispatch_once_t once;
    dispatch_once(&once, ^{
        set = [NSSet setWithArray:@[@"/Applications/Cydia.app",
            @"/Library/MobileSubstrate/MobileSubstrate.dylib",@"/bin/bash",
            @"/usr/sbin/sshd",@"/etc/apt",@"/private/var/lib/apt",
            @"/usr/bin/ssh",@"/var/jb"]];
    });
    return [set containsObject:p];
}

%hook NSFileManager
- (BOOL)fileExistsAtPath:(NSString *)path { if (isJBPath(path)) return NO; return %orig; }
- (BOOL)fileExistsAtPath:(NSString *)path isDirectory:(BOOL *)d {
    if (isJBPath(path)) { if (d) *d = NO; return NO; } return %orig;
}
%end

static pid_t (*orig_fork)(void);
static pid_t my_fork(void){ return 0; }

static FILE* (*orig_fopen)(const char*,const char*);
static FILE* my_fopen(const char *p,const char *m){ if(p&&strstr(p,"frida")) return NULL; return orig_fopen(p,m); }

static int (*orig_ptrace)(int,pid_t,caddr_t,int);
static int my_ptrace(int r,pid_t p,caddr_t a,int d){ if(r==31) return 0; return orig_ptrace(r,p,a,d); }

%ctor {
    initIDsOnce();
    void *mh = dlsym(RTLD_DEFAULT, "MSHookFunction");
    if (mh) {
        ((void(*)(void*,void*,void**))mh)((void*)fork,(void*)my_fork,(void**)&orig_fork);
        ((void(*)(void*,void*,void**))mh)((void*)fopen,(void*)my_fopen,(void**)&orig_fopen);
        ((void(*)(void*,void*,void**))mh)((void*)ptrace,(void*)my_ptrace,(void**)&orig_ptrace);
    }
    NSLog(@"[LFR] loaded IDFV=%@", gIDFV);
}
