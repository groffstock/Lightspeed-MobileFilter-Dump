// ObjC class-dump of MobileFilter — 77 classes

@interface A0JWT : NSObject {
    id jwt;  // Swift-typed ivar
}
@property header;
@property body;
@property signature;
@property expiresAt;
@property expired;
+ (id)decodeWithJwt:(id)arg0 error:(id *)arg1;
- (id)header;
- (id)body;
- (id)signature;
- (id)expiresAt;
- (BOOL)expired;
- (id)init;
- (void).cxx_destruct;
@end

@interface Cryptor.Cryptor : Cryptor.StreamCryptor {
    id accumulator;  // Swift-typed ivar
}
@end

@interface Cryptor.Digest : _TtCs12_SwiftObject {
    id status;  // Swift-typed ivar
    id engine;  // Swift-typed ivar
}
@end

@interface Cryptor.HMAC : _TtCs12_SwiftObject {
    id status;  // Swift-typed ivar
    id context;  // Swift-typed ivar
    id algorithm;  // Swift-typed ivar
}
@end

@interface Cryptor.PBKDF : _TtCs12_SwiftObject {
}
@end

@interface Cryptor.Random : _TtCs12_SwiftObject {
}
@end

@interface Cryptor.StreamCryptor : _TtCs12_SwiftObject {
    id status;  // Swift-typed ivar
    id haveContext;  // Swift-typed ivar
    id context;  // Swift-typed ivar
}
@end

@interface CryptorECC.ECPrivateKey : _TtCs12_SwiftObject {
    id curveId;  // Swift-typed ivar
    id curve;  // Swift-typed ivar
    id pemString;  // Swift-typed ivar
    id nativeKey;  // Swift-typed ivar
    id pubKeyBytes;  // Swift-typed ivar
    id stripped;  // Swift-typed ivar
}
@end

@interface CryptorECC.ECPublicKey : _TtCs12_SwiftObject {
    id curveId;  // Swift-typed ivar
    id curve;  // Swift-typed ivar
    id nativeKey;  // Swift-typed ivar
    id pemString;  // Swift-typed ivar
}
@end

@interface CryptorRSA.CryptorRSA : _TtCs12_SwiftObject {
}
@end

@interface InsightSpeedtest : _TtCs12_SwiftObject {
}
@end

@interface InsightSpeedtest.DeviceInformation : _TtCs12_SwiftObject {
    id Version;  // Swift-typed ivar
    id DeviceId;  // Swift-typed ivar
    id DeviceType;  // Swift-typed ivar
    id UserHash;  // Swift-typed ivar
    id EntitlementKey;  // Swift-typed ivar
    id Platform;  // Swift-typed ivar
    id IP;  // Swift-typed ivar
    id Connected;  // Swift-typed ivar
    id SpeedTest;  // Swift-typed ivar
    id DisconnectedInterval;  // Swift-typed ivar
    id Location;  // Swift-typed ivar
}
@end

@interface InsightSpeedtest.DigitalEquity : _TtCs12_SwiftObject {
    id logger;  // Swift-typed ivar
    id session;  // Swift-typed ivar
    id equityPayload;  // Swift-typed ivar
    id equityCheckTimeInterval;  // Swift-typed ivar
    id equityCheckTimer;  // Swift-typed ivar
    id remoteConfigTimer;  // Swift-typed ivar
    id remoteCfg;  // Swift-typed ivar
    id networkMonitor;  // Swift-typed ivar
    id networkMonitorQueue;  // Swift-typed ivar
    id networkStatusKey;  // Swift-typed ivar
    id equityActive;  // Swift-typed ivar
    id deviceIP;  // Swift-typed ivar
    id newIpAddressDiscovered;  // Swift-typed ivar
    id persistentStore;  // Swift-typed ivar
    id nextValidSpeedTestTimestamp;  // Swift-typed ivar
    id softSpeedTestDeadline;  // Swift-typed ivar
    id lostConnectionTimestamp;  // Swift-typed ivar
    id gainedConnectionTimestamp;  // Swift-typed ivar
    id speedTestCfgFilePath;  // Swift-typed ivar
    id disconnectedLocation;  // Swift-typed ivar
}
@end

@interface InsightSpeedtest.DisconnectedInterval : _TtCs12_SwiftObject {
    id Start;  // Swift-typed ivar
    id End;  // Swift-typed ivar
    id Duration;  // Swift-typed ivar
}
@end

@interface InsightSpeedtest.LSJWT : _TtCs12_SwiftObject {
    id $defaultActor;  // Swift-typed ivar
    id keyFetcher;  // Swift-typed ivar
    id kDict;  // Swift-typed ivar
}
@end

@interface InsightSpeedtest.Location : _TtCs12_SwiftObject {
    id lat;  // Swift-typed ivar
    id lon;  // Swift-typed ivar
}
@end

@interface InsightSpeedtest.LocationHandler : NSObject {
    id locationManager;  // Swift-typed ivar
    id logger;  // Swift-typed ivar
}
- (void)locationManager:(id)arg0 didFailWithError:(id)arg1;
- (void)locationManager:(id)arg0 didUpdateLocations:(id)arg1;
- (void)locationManagerDidChangeAuthorization:(id)arg0;
- (void)locationManager:(id)arg0 didChangeAuthorizationStatus:(int)arg1;
- (id)init;
- (void).cxx_destruct;
@end

@interface InsightSpeedtest.RemoteConfig : NSObject {
    id endpointURL;  // Swift-typed ivar
    id active;  // Swift-typed ivar
    id checkinInterval;  // Swift-typed ivar
    id collectPII;  // Swift-typed ivar
    id digitalEquityActive;  // Swift-typed ivar
    id speedTestActive;  // Swift-typed ivar
    id locationDataActive;  // Swift-typed ivar
    id maxPayload;  // Swift-typed ivar
    id chunkSize;  // Swift-typed ivar
    id chunkCount;  // Swift-typed ivar
    id minCheck;  // Swift-typed ivar
    id maxCheck;  // Swift-typed ivar
    id method;  // Swift-typed ivar
    id digitalEquityURL;  // Swift-typed ivar
    id speedTestURL;  // Swift-typed ivar
}
- (id)copyWithZone:(void *)arg0;
- (id)init;
- (void).cxx_destruct;
@end

@interface InsightSpeedtest.Resolver : _TtCs12_SwiftObject {
    id state;  // Swift-typed ivar
}
@end

@interface InsightSpeedtest.SignalBattery : _TtCs12_SwiftObject {
    id state;  // Swift-typed ivar
    id level;  // Swift-typed ivar
    id dischargeTime;  // Swift-typed ivar
    id chargeTime;  // Swift-typed ivar
}
@end

@interface InsightSpeedtest.SignalManager : _TtCs12_SwiftObject {
    id $defaultActor;  // Swift-typed ivar
    id policyURL;  // Swift-typed ivar
    id reportURL;  // Swift-typed ivar
    id policy;  // Swift-typed ivar
    id customerID;  // Swift-typed ivar
    id agentVersion;  // Swift-typed ivar
    id userEmail;  // Swift-typed ivar
    id serial;  // Swift-typed ivar
    id lsjwt;  // Swift-typed ivar
    id licenses;  // Swift-typed ivar
    id lastSpeedTestForASN;  // Swift-typed ivar
    id lastDeviceReport;  // Swift-typed ivar
    id lastPolicyUpdate;  // Swift-typed ivar
    id lastNetworkupdate;  // Swift-typed ivar
    id tsConfig;  // Swift-typed ivar
    id speedTestCABundle;  // Swift-typed ivar
    id speedTestCfgFilePath;  // Swift-typed ivar
    id policyTimer;  // Swift-typed ivar
    id locationHandler;  // Swift-typed ivar
    id networkMonitor;  // Swift-typed ivar
    id uname;  // Swift-typed ivar
    id hostName;  // Swift-typed ivar
    id osVersion;  // Swift-typed ivar
    id speedStateCachePath;  // Swift-typed ivar
    id cacheFile;  // Swift-typed ivar
    id currentPath;  // Swift-typed ivar
    id ssid;  // Swift-typed ivar
    id signalStrength;  // Swift-typed ivar
    id logger;  // Swift-typed ivar
    id queue;  // Swift-typed ivar
    id scheduled;  // Swift-typed ivar
}
@end

@interface InsightSpeedtest.SpeedTestResults : _TtCs12_SwiftObject {
    id TransactionId;  // Swift-typed ivar
    id UploadSize;  // Swift-typed ivar
    id DownloadSize;  // Swift-typed ivar
    id UploadDuration;  // Swift-typed ivar
    id DownloadDuration;  // Swift-typed ivar
    id RanAt;  // Swift-typed ivar
    id Method;  // Swift-typed ivar
    id ChunkSize;  // Swift-typed ivar
    id UploadChunks;  // Swift-typed ivar
    id DownloadChunks;  // Swift-typed ivar
}
@end

@interface InsightSpeedtest.UserDefaultsPersistentStore : _TtCs12_SwiftObject {
    id UDKeyNextValidTimestamp;  // Swift-typed ivar
    id UDKeySoftSpeedTestDeadline;  // Swift-typed ivar
    id UDKeyDisconnectedTimestamp;  // Swift-typed ivar
    id UDKeyRecordedIPString;  // Swift-typed ivar
    id UDKeyLocationLatitude;  // Swift-typed ivar
    id UDKeyLocationLongitude;  // Swift-typed ivar
    id userDefaults;  // Swift-typed ivar
}
@end

@interface KituraContracts.Coder : _TtCs12_SwiftObject {
    id dateFormatter;  // Swift-typed ivar
}
@end

@interface KituraContracts.QueryDecoder : KituraContracts.Coder {
    id codingPath;  // Swift-typed ivar
    id userInfo;  // Swift-typed ivar
    id dictionary;  // Swift-typed ivar
    id dateDecodingStrategy;  // Swift-typed ivar
}
@end

@interface KituraContracts.QueryEncoder : KituraContracts.Coder {
    id dictionary;  // Swift-typed ivar
    id anyDictionary;  // Swift-typed ivar
    id codingPath;  // Swift-typed ivar
    id userInfo;  // Swift-typed ivar
    id dateEncodingStrategy;  // Swift-typed ivar
}
@end

@interface LoggerAPI.Log : _TtCs12_SwiftObject {
}
@end

@interface Logging.Lock : _TtCs12_SwiftObject {
    id mutex;  // Swift-typed ivar
}
@end

@interface Logging.ReadWriteLock : _TtCs12_SwiftObject {
    id rwlock;  // Swift-typed ivar
}
@end

@interface MobileFilter : _TtCs12_SwiftObject {
}
@end

@interface MobileFilter.ApiRouter : _TtCs12_SwiftObject {
    id _signalCoreDevicesApiBaseURL;  // Swift-typed ivar
    id _baseURL;  // Swift-typed ivar
    id _apiKey;  // Swift-typed ivar
    id _categorizationDeviceApiURL;  // Swift-typed ivar
    id _categorizationDeviceApiKey;  // Swift-typed ivar
    id _agentBackendApiURL;  // Swift-typed ivar
    id _licenseApiKey;  // Swift-typed ivar
    id _telemetryApiKey;  // Swift-typed ivar
    id _baseTrustedAppsURL;  // Swift-typed ivar
}
@end

@interface MobileFilter.AppDelegate : UIResponder {
    UIWindow * window;
}
@property window;
- (id)window;
- (void)setWindow:(id)arg0;
- (void)applicationWillResignActive:(id)arg0;
- (void)applicationDidEnterBackground:(id)arg0;
- (void)applicationWillEnterForeground:(id)arg0;
- (void)applicationDidBecomeActive:(id)arg0;
- (void)applicationWillTerminate:(id)arg0;
- (BOOL)application:(id)arg0 openURL:(id)arg1 options:(id)arg2;
- (id)init;
- (void).cxx_destruct;
@end

@interface MobileFilter.AppStats : _TtCs12_SwiftObject {
    id socketStats;  // Swift-typed ivar
    id browserStats;  // Swift-typed ivar
    id appStatsSemaphore;  // Swift-typed ivar
}
@end

@interface MobileFilter.BlockedPageViewController : UIViewController {
    id blockedURL;  // Swift-typed ivar
    void * logoIcon;
    void * logoText;
    void * schoolNameLabel;
    void * filterVersionLabel;
    void * deviceIDLabel;
    void * policyServerLabel;
    void * sorryLabel;
    void * domainNameLabel;
    void * categoryLabel;
    void * toggleRulesButton;
}
@property logoIcon;
@property logoText;
@property schoolNameLabel;
@property filterVersionLabel;
@property deviceIDLabel;
@property policyServerLabel;
@property sorryLabel;
@property domainNameLabel;
@property categoryLabel;
@property toggleRulesButton;
- (id)logoIcon;
- (void)setLogoIcon:(id)arg0;
- (id)logoText;
- (void)setLogoText:(id)arg0;
- (id)schoolNameLabel;
- (void)setSchoolNameLabel:(id)arg0;
- (id)filterVersionLabel;
- (void)setFilterVersionLabel:(id)arg0;
- (id)deviceIDLabel;
- (void)setDeviceIDLabel:(id)arg0;
- (id)policyServerLabel;
- (void)setPolicyServerLabel:(id)arg0;
- (id)sorryLabel;
- (void)setSorryLabel:(id)arg0;
- (id)domainNameLabel;
- (void)setDomainNameLabel:(id)arg0;
- (id)categoryLabel;
- (void)setCategoryLabel:(id)arg0;
- (id)toggleRulesButton;
- (void)setToggleRulesButton:(id)arg0;
- (void)viewDidLoad;
- (void)didReceiveMemoryWarning;
- (id)initWithNibName:(id)arg0 bundle:(id)arg1;
- (id)initWithCoder:(id)arg0;
- (void).cxx_destruct;
@end

@interface MobileFilter.FileBasedCache : _TtCs12_SwiftObject {
    id topCacheDirectory;  // Swift-typed ivar
    id appGroupURL;  // Swift-typed ivar
    id minimumPolicyURL;  // Swift-typed ivar
    id lastPolicy;  // Swift-typed ivar
    id lastPolicyDiskMTime;  // Swift-typed ivar
    id _fallbackPolicy;  // Swift-typed ivar
}
@end

@interface MobileFilter.FileDownloader : NSObject {
    id eTag;  // Swift-typed ivar
    id config;  // Swift-typed ivar
    id session;  // Swift-typed ivar
}
- (id)init;
- (void).cxx_destruct;
@end

@interface MobileFilter.FilterControlProvider : NEFilterControlProvider {
    id encoder;  // Swift-typed ivar
    id decoder;  // Swift-typed ivar
    id policy;  // Swift-typed ivar
    id policyFetchedDate;  // Swift-typed ivar
    id digitalEquity;  // Swift-typed ivar
    id signalManager;  // Swift-typed ivar
    id cfg;  // Swift-typed ivar
    id diConfigExpiredDate;  // Swift-typed ivar
    id relayIpTTL;  // Swift-typed ivar
    id relayIpTTLTimer;  // Swift-typed ivar
    id retryRelayTimeout;  // Swift-typed ivar
    id retryRelayTimer;  // Swift-typed ivar
    id retryRelayTimerTries;  // Swift-typed ivar
    id retryRelayTimerTriesMax;  // Swift-typed ivar
    id supervisorTimer;  // Swift-typed ivar
    id globalProxyTimer;  // Swift-typed ivar
    id apiRouter;  // Swift-typed ivar
    id rocketIPV4Socket;  // Swift-typed ivar
    id rocketConnectedSuccessfully;  // Swift-typed ivar
    id globalProxyTimerInterval;  // Swift-typed ivar
    id yourIpUrlAdd;  // Swift-typed ivar
    id userPolicyAdd;  // Swift-typed ivar
    id reportAdd;  // Swift-typed ivar
    id hostLookupAdd;  // Swift-typed ivar
    id appAnalyticAdd;  // Swift-typed ivar
    id NetworkReachabilityChanged;  // Swift-typed ivar
    id reachabilityManager;  // Swift-typed ivar
    id networkObserver;  // Swift-typed ivar
    id networkManager;  // Swift-typed ivar
    id hostContainerSemaphore;  // Swift-typed ivar
    id hostCallbackContainer;  // Swift-typed ivar
    id hostFailedCategorizationCount;  // Swift-typed ivar
    id hostsToFetchOnReconnect;  // Swift-typed ivar
    id verdictContainerSemaphore;  // Swift-typed ivar
    id verdictList;  // Swift-typed ivar
    id verdictLastLogged;  // Swift-typed ivar
    id lastVerdictFileScrubDate;  // Swift-typed ivar
    id trustedApps;  // Swift-typed ivar
    id _lastPolicyFetchAttemptSemaphore;  // Swift-typed ivar
    id _lastPolicyFetchAttempt;  // Swift-typed ivar
    id uname;  // Swift-typed ivar
    id policyFetchOnlyOneAtATimeSemaphore;  // Swift-typed ivar
    id lastPolicyUsername;  // Swift-typed ivar
    id appStats;  // Swift-typed ivar
    id appUsageTimerTimeout;  // Swift-typed ivar
    id appUsageTimer;  // Swift-typed ivar
    id licenseCheckTimer;  // Swift-typed ivar
    id telemetryTimer;  // Swift-typed ivar
    id pathMonitor;  // Swift-typed ivar
    id pathMonitorQueue;  // Swift-typed ivar
    id lastGateway;  // Swift-typed ivar
}
- (void)dealloc;
- (id)init;
- (void)timerFired;
- (void)appUsageTimerFired;
- (void)timerFiredCounting;
- (void)observeValueForKeyPath:(id)arg0 ofObject:(id)arg1 change:(id)arg2 context:(void *)arg3;
- (void)startFilterWithCompletionHandler:(id)arg0;
- (void)stopFilterWithReason:(long long)arg0 completionHandler:(id)arg1;
- (void)handleNewFlow:(id)arg0 completionHandler:(id)arg1;
- (void)handleRemediationForFlow:(id)arg0 completionHandler:(id)arg1;
- (void)wake;
- (void)sleepWithCompletionHandler:(id)arg0;
- (void)logTimerFired;
- (void)checkSocketConnection;
- (void)getProxySettings;
- (void).cxx_destruct;
@end

@interface MobileFilter.FilterDataProvider : NEFilterDataProvider {
    id policy;  // Swift-typed ivar
    id policyFetchedDate;  // Swift-typed ivar
    id proxySettingsFetchedDate;  // Swift-typed ivar
    id proxySettingsCacheTime;  // Swift-typed ivar
    id loggingURLs;  // Swift-typed ivar
    id semaphoreForLoggingURLs;  // Swift-typed ivar
    id remediationURLs;  // Swift-typed ivar
    id semaphoreForRemediationURLs;  // Swift-typed ivar
    id lookupURLs;  // Swift-typed ivar
    id semaphoreForLookupURLs;  // Swift-typed ivar
    id logInterval;  // Swift-typed ivar
    id cleanupLastSweep;  // Swift-typed ivar
    id ipString;  // Swift-typed ivar
    id ipRetrievalDate;  // Swift-typed ivar
    id uname;  // Swift-typed ivar
    id trustedApps;  // Swift-typed ivar
}
- (void)dealloc;
- (id)init;
- (void)observeValueForKeyPath:(id)arg0 ofObject:(id)arg1 change:(id)arg2 context:(void *)arg3;
- (void)startFilterWithCompletionHandler:(id)arg0;
- (void)stopFilterWithReason:(long long)arg0 completionHandler:(id)arg1;
- (id)handleNewFlow:(id)arg0;
- (id)handleRemediationForFlow:(id)arg0;
- (void).cxx_destruct;
@end

@interface MobileFilter.GlobalProxySettingsManager : _TtCs12_SwiftObject {
    id fileDownloader;  // Swift-typed ivar
    id proxyConnection;  // Swift-typed ivar
    id serialQueue;  // Swift-typed ivar
    id userDefaults;  // Swift-typed ivar
    id jwt;  // Swift-typed ivar
    id _jwtString;  // Swift-typed ivar
    id _setupStatus;  // Swift-typed ivar
    id _pacURL;  // Swift-typed ivar
    id _bouncerHostname;  // Swift-typed ivar
    id _bypassDomainsExact;  // Swift-typed ivar
    id _bypassDomainsWild;  // Swift-typed ivar
    id _rocketIdent;  // Swift-typed ivar
    id _rocketProxyIdent;  // Swift-typed ivar
    id _requiresReload;  // Swift-typed ivar
    id proxyAddress;  // Swift-typed ivar
    id _proxyAvailable;  // Swift-typed ivar
}
@end

@interface MobileFilter.JSONViewController : UIViewController {
    UITextView * textView;
    id textContent;  // Swift-typed ivar
}
@property textView;
- (id)textView;
- (void)setTextView:(id)arg0;
- (void)viewDidLoad;
- (void)viewWillAppear:(BOOL)arg0;
- (void)didReceiveMemoryWarning;
- (id)initWithNibName:(id)arg0 bundle:(id)arg1;
- (id)initWithCoder:(id)arg0;
- (void).cxx_destruct;
@end

@interface MobileFilter.NetworkManager : _TtCs12_SwiftObject {
    id policyPath;  // Swift-typed ivar
    id encoder;  // Swift-typed ivar
    id filterConfiguration;  // Swift-typed ivar
    id apiRouter;  // Swift-typed ivar
    id _currentUser;  // Swift-typed ivar
    id _customerID;  // Swift-typed ivar
    id udid;  // Swift-typed ivar
    id image;  // Swift-typed ivar
}
@end

@interface MobileFilter.ProxyConnection : _TtCs12_SwiftObject {
    id finishedCallback;  // Swift-typed ivar
    id nwConnection;  // Swift-typed ivar
}
@end

@interface MobileFilter.ReachabilityManager : _TtCs12_SwiftObject {
    id NetworkReachabilityChanged;  // Swift-typed ivar
    id reachability;  // Swift-typed ivar
    id queue;  // Swift-typed ivar
    id currentReachabilityFlags;  // Swift-typed ivar
    id isListening;  // Swift-typed ivar
}
@end

@interface MobileFilter.RepeatTimer : _TtCs12_SwiftObject {
    id timerState;  // Swift-typed ivar
    id timeInterval;  // Swift-typed ivar
    id eventHandler;  // Swift-typed ivar
    id $__lazy_storage_$_repeatTimer;  // Swift-typed ivar
}
@end

@interface MobileFilter.ReportPayload : _TtCs12_SwiftObject {
    id report;  // Swift-typed ivar
}
@end

@interface MobileFilter.ReviewLicensesViewController : UIViewController {
    UILabel * cancelReviewLicenses;
    UITapGestureRecognizer * cancelReviewer;
    void * licensesLabel;
}
@property cancelReviewLicenses;
@property cancelReviewer;
@property licensesLabel;
- (id)cancelReviewLicenses;
- (void)setCancelReviewLicenses:(id)arg0;
- (id)cancelReviewer;
- (void)setCancelReviewer:(id)arg0;
- (id)licensesLabel;
- (void)setLicensesLabel:(id)arg0;
- (void)viewDidLoad;
- (void)viewDidAppear:(BOOL)arg0;
- (void)cancelReviewerTappedWith_sender:(id)arg0;
- (id)initWithNibName:(id)arg0 bundle:(id)arg1;
- (id)initWithCoder:(id)arg0;
- (void).cxx_destruct;
@end

@interface MobileFilter.TrustedAppList : _TtCs12_SwiftObject {
    id fileDownloader;  // Swift-typed ivar
    id appGroupContainerURL;  // Swift-typed ivar
    id listID;  // Swift-typed ivar
    id fileContent;  // Swift-typed ivar
    id downloadFailed;  // Swift-typed ivar
    id _downloadURL;  // Swift-typed ivar
}
@end

@interface MobileFilter.TrustedApps : NSObject {
    id customerList;  // Swift-typed ivar
    id globalList;  // Swift-typed ivar
    id customerID;  // Swift-typed ivar
    id lastUpdated;  // Swift-typed ivar
}
- (id)init;
- (void).cxx_destruct;
@end

@interface MobileFilter.VerdictLogTableViewController : UITableViewController {
    id policySection;  // Swift-typed ivar
    id trustedAppsSection;  // Swift-typed ivar
    id configSection;  // Swift-typed ivar
    id verdictSection;  // Swift-typed ivar
    id domainSection;  // Swift-typed ivar
    id categorySection;  // Swift-typed ivar
    id verdictList;  // Swift-typed ivar
    id domainList;  // Swift-typed ivar
    id categoryList;  // Swift-typed ivar
    id trustedApps;  // Swift-typed ivar
}
- (void)viewDidLoad;
- (long long)numberOfSectionsInTableView:(id)arg0;
- (long long)tableView:(id)arg0 numberOfRowsInSection:(long long)arg1;
- (id)tableView:(id)arg0 cellForRowAtIndexPath:(id)arg1;
- (id)tableView:(id)arg0 titleForHeaderInSection:(long long)arg1;
- (void)dismissVC;
- (void)tableView:(id)arg0 didSelectRowAtIndexPath:(id)arg1;
- (void)prepareForSegue:(id)arg0 sender:(id)arg1;
- (id)initWithStyle:(long long)arg0;
- (id)initWithNibName:(id)arg0 bundle:(id)arg1;
- (id)initWithCoder:(id)arg0;
- (void).cxx_destruct;
@end

@interface MobileFilter.ViewController : UIViewController {
    void * backgroundImage;
    void * logoIcon;
    void * logoText;
    void * explanatoryLabel;
    void * schoolNameLabel;
    void * filterVersionLabel;
    void * deviceIDLabel;
    void * reviewLicensesLabel;
    void * policyServerLabel;
    void * policyDateLabel;
    void * usernameLabel;
    void * serverAddressLabel;
    void * statusIndicatorView;
    void * toggleRulesButton;
    UIPinchGestureRecognizer * pincher;
    UITapGestureRecognizer * tapper;
    UITapGestureRecognizer * reviewer;
    UITapGestureRecognizer * speedTester;
    UITapGestureRecognizer * showHidden;
    id networkManager;  // Swift-typed ivar
    id shortVersion;  // Swift-typed ivar
    id buildVersion;  // Swift-typed ivar
}
@property backgroundImage;
@property logoIcon;
@property logoText;
@property explanatoryLabel;
@property schoolNameLabel;
@property filterVersionLabel;
@property deviceIDLabel;
@property reviewLicensesLabel;
@property policyServerLabel;
@property policyDateLabel;
@property usernameLabel;
@property serverAddressLabel;
@property statusIndicatorView;
@property toggleRulesButton;
@property pincher;
@property tapper;
@property reviewer;
@property speedTester;
@property showHidden;
@property preferredStatusBarStyle;
- (id)backgroundImage;
- (void)setBackgroundImage:(id)arg0;
- (id)logoIcon;
- (void)setLogoIcon:(id)arg0;
- (id)logoText;
- (void)setLogoText:(id)arg0;
- (id)explanatoryLabel;
- (void)setExplanatoryLabel:(id)arg0;
- (id)schoolNameLabel;
- (void)setSchoolNameLabel:(id)arg0;
- (id)filterVersionLabel;
- (void)setFilterVersionLabel:(id)arg0;
- (id)deviceIDLabel;
- (void)setDeviceIDLabel:(id)arg0;
- (id)reviewLicensesLabel;
- (void)setReviewLicensesLabel:(id)arg0;
- (id)policyServerLabel;
- (void)setPolicyServerLabel:(id)arg0;
- (id)policyDateLabel;
- (void)setPolicyDateLabel:(id)arg0;
- (id)usernameLabel;
- (void)setUsernameLabel:(id)arg0;
- (id)serverAddressLabel;
- (void)setServerAddressLabel:(id)arg0;
- (id)statusIndicatorView;
- (void)setStatusIndicatorView:(id)arg0;
- (id)toggleRulesButton;
- (void)setToggleRulesButton:(id)arg0;
- (id)pincher;
- (void)setPincher:(id)arg0;
- (id)tapper;
- (void)setTapper:(id)arg0;
- (id)reviewer;
- (void)setReviewer:(id)arg0;
- (id)speedTester;
- (void)setSpeedTester:(id)arg0;
- (id)showHidden;
- (void)setShowHidden:(id)arg0;
- (long long)preferredStatusBarStyle;
- (void)viewDidLoad;
- (void)viewDidAppear:(BOOL)arg0;
- (void)reviwerTappedWith_sender:(id)arg0;
- (void)showHiddenLabelsWith_sender:(id)arg0;
- (void)launchLogTableWith_sender:(id)arg0;
- (void)launchSpeedTestWith_sender:(id)arg0;
- (id)initWithNibName:(id)arg0 bundle:(id)arg1;
- (id)initWithCoder:(id)arg0;
- (void).cxx_destruct;
@end

@interface Starscream.Compressor : _TtCs12_SwiftObject {
    id strm;  // Swift-typed ivar
    id buffer;  // Swift-typed ivar
    id deflateInitialized;  // Swift-typed ivar
    id windowBits;  // Swift-typed ivar
}
@end

@interface Starscream.Decompressor : _TtCs12_SwiftObject {
    id strm;  // Swift-typed ivar
    id buffer;  // Swift-typed ivar
    id inflateInitialized;  // Swift-typed ivar
    id windowBits;  // Swift-typed ivar
}
@end

@interface Starscream.FoundationStream : NSObject {
    id workQueue;  // Swift-typed ivar
    id inputStream;  // Swift-typed ivar
    id outputStream;  // Swift-typed ivar
    id delegate;  // Swift-typed ivar
    id BUFFER_MAX;  // Swift-typed ivar
    id enableSOCKSProxy;  // Swift-typed ivar
}
- (void)stream:(id)arg0 handleEvent:(unsigned long long)arg1;
- (id)init;
- (void).cxx_destruct;
@end

@interface Starscream.SSLCert : _TtCs12_SwiftObject {
    id certData;  // Swift-typed ivar
    id key;  // Swift-typed ivar
}
@end

@interface Starscream.SSLClientCertificate : _TtCs12_SwiftObject {
    id streamSSLCertificates;  // Swift-typed ivar
}
@end

@interface Starscream.SSLSecurity : _TtCs12_SwiftObject {
    id validatedDN;  // Swift-typed ivar
    id validateEntireChain;  // Swift-typed ivar
    id isReady;  // Swift-typed ivar
    id certificates;  // Swift-typed ivar
    id pubKeys;  // Swift-typed ivar
    id usePublicKeys;  // Swift-typed ivar
}
@end

@interface Starscream.WebSocket : NSObject {
    id callbackQueue;  // Swift-typed ivar
    id headerWSUpgradeName;  // Swift-typed ivar
    id headerWSUpgradeValue;  // Swift-typed ivar
    id headerWSHostName;  // Swift-typed ivar
    id headerWSConnectionName;  // Swift-typed ivar
    id headerWSConnectionValue;  // Swift-typed ivar
    id headerWSProtocolName;  // Swift-typed ivar
    id headerWSVersionName;  // Swift-typed ivar
    id headerWSVersionValue;  // Swift-typed ivar
    id headerWSExtensionName;  // Swift-typed ivar
    id headerWSKeyName;  // Swift-typed ivar
    id headerOriginName;  // Swift-typed ivar
    id headerWSAcceptName;  // Swift-typed ivar
    id BUFFER_MAX;  // Swift-typed ivar
    id FinMask;  // Swift-typed ivar
    id OpCodeMask;  // Swift-typed ivar
    id RSVMask;  // Swift-typed ivar
    id RSV1Mask;  // Swift-typed ivar
    id MaskMask;  // Swift-typed ivar
    id PayloadLenMask;  // Swift-typed ivar
    id MaxFrameSize;  // Swift-typed ivar
    id httpSwitchProtocolCode;  // Swift-typed ivar
    id supportedSSLSchemes;  // Swift-typed ivar
    id delegate;  // Swift-typed ivar
    id advancedDelegate;  // Swift-typed ivar
    id pongDelegate;  // Swift-typed ivar
    id onConnect;  // Swift-typed ivar
    id onDisconnect;  // Swift-typed ivar
    id onText;  // Swift-typed ivar
    id onData;  // Swift-typed ivar
    id onPong;  // Swift-typed ivar
    id onHttpResponseHeaders;  // Swift-typed ivar
    id disableSSLCertValidation;  // Swift-typed ivar
    id overrideTrustHostname;  // Swift-typed ivar
    id desiredTrustHostname;  // Swift-typed ivar
    id sslClientCertificate;  // Swift-typed ivar
    id enableCompression;  // Swift-typed ivar
    id security;  // Swift-typed ivar
    id enabledSSLCipherSuites;  // Swift-typed ivar
    id request;  // Swift-typed ivar
    id respondToPingWithPong;  // Swift-typed ivar
    id stream;  // Swift-typed ivar
    id connected;  // Swift-typed ivar
    id isConnecting;  // Swift-typed ivar
    id mutex;  // Swift-typed ivar
    id compressionState;  // Swift-typed ivar
    id writeQueue;  // Swift-typed ivar
    id readStack;  // Swift-typed ivar
    id inputQueue;  // Swift-typed ivar
    id fragBuffer;  // Swift-typed ivar
    id certValidated;  // Swift-typed ivar
    id didDisconnect;  // Swift-typed ivar
    id readyToWrite;  // Swift-typed ivar
    id headerSecKey;  // Swift-typed ivar
}
- (void)dealloc;
- (id)init;
- (void).cxx_destruct;
@end

@interface SwiftJWT : _TtCs12_SwiftObject {
    id header;  // Swift-typed ivar
    id claims;  // Swift-typed ivar
    id keyID;  // Swift-typed ivar
    id codingPath;  // Swift-typed ivar
    id userInfo;  // Swift-typed ivar
}
@end

@interface SwiftJWT : _TtCs12_SwiftObject {
    id claims;  // Swift-typed ivar
    id header;  // Swift-typed ivar
    id jwtSigner;  // Swift-typed ivar
    id keyIDToSigner;  // Swift-typed ivar
    id codingPath;  // Swift-typed ivar
    id userInfo;  // Swift-typed ivar
}
@end

@interface SwiftJWT.BlueECSigner : _TtCs12_SwiftObject {
    id name;  // Swift-typed ivar
    id key;  // Swift-typed ivar
    id curve;  // Swift-typed ivar
}
@end

@interface SwiftJWT.BlueECVerifier : _TtCs12_SwiftObject {
    id name;  // Swift-typed ivar
    id key;  // Swift-typed ivar
    id curve;  // Swift-typed ivar
}
@end

@interface SwiftJWT.BlueHMAC : _TtCs12_SwiftObject {
    id name;  // Swift-typed ivar
    id key;  // Swift-typed ivar
    id algorithm;  // Swift-typed ivar
}
@end

@interface SwiftJWT.BlueRSA : _TtCs12_SwiftObject {
    id name;  // Swift-typed ivar
    id key;  // Swift-typed ivar
    id keyType;  // Swift-typed ivar
    id algorithm;  // Swift-typed ivar
    id usePSS;  // Swift-typed ivar
}
@end

@interface SwiftJWT.ClaimsMicroProfile : _TtCs12_SwiftObject {
    id iss;  // Swift-typed ivar
    id sub;  // Swift-typed ivar
    id exp;  // Swift-typed ivar
    id iat;  // Swift-typed ivar
    id jti;  // Swift-typed ivar
    id upn;  // Swift-typed ivar
    id preferred_username;  // Swift-typed ivar
    id groups;  // Swift-typed ivar
}
@end

@interface SwiftJWT.ClaimsOpenID : _TtCs12_SwiftObject {
    id iss;  // Swift-typed ivar
    id sub;  // Swift-typed ivar
    id aud;  // Swift-typed ivar
    id exp;  // Swift-typed ivar
    id iat;  // Swift-typed ivar
    id auth_time;  // Swift-typed ivar
    id nonce;  // Swift-typed ivar
    id acr;  // Swift-typed ivar
    id amr;  // Swift-typed ivar
    id azp;  // Swift-typed ivar
    id name;  // Swift-typed ivar
    id given_name;  // Swift-typed ivar
    id family_name;  // Swift-typed ivar
    id middle_name;  // Swift-typed ivar
    id nickname;  // Swift-typed ivar
    id preferred_username;  // Swift-typed ivar
    id profile;  // Swift-typed ivar
    id picture;  // Swift-typed ivar
    id website;  // Swift-typed ivar
    id email;  // Swift-typed ivar
    id email_verified;  // Swift-typed ivar
    id gender;  // Swift-typed ivar
    id birthdate;  // Swift-typed ivar
    id zoneinfo;  // Swift-typed ivar
    id locale;  // Swift-typed ivar
    id phone_number;  // Swift-typed ivar
    id phone_number_verified;  // Swift-typed ivar
    id address;  // Swift-typed ivar
    id updated_at;  // Swift-typed ivar
}
@end

@interface SwiftJWT.ClaimsStandardJWT : _TtCs12_SwiftObject {
    id iss;  // Swift-typed ivar
    id sub;  // Swift-typed ivar
    id aud;  // Swift-typed ivar
    id exp;  // Swift-typed ivar
    id nbf;  // Swift-typed ivar
    id iat;  // Swift-typed ivar
    id jti;  // Swift-typed ivar
}
@end

@interface SwiftJWT.JWTDecoder : _TtCs12_SwiftObject {
    id keyIDToVerifier;  // Swift-typed ivar
    id jwtVerifier;  // Swift-typed ivar
}
@end

@interface SwiftJWT.JWTEncoder : _TtCs12_SwiftObject {
    id keyIDToSigner;  // Swift-typed ivar
    id jwtSigner;  // Swift-typed ivar
}
@end

@interface _TtCC10CryptorRSA10CryptorRSA10PrivateKey : _TtCC10CryptorRSA10CryptorRSA6RSAKey {
}
@end

@interface _TtCC10CryptorRSA10CryptorRSA10SignedData : _TtCC10CryptorRSA10CryptorRSA7RSAData {
}
@end

@interface _TtCC10CryptorRSA10CryptorRSA13EncryptedData : _TtCC10CryptorRSA10CryptorRSA7RSAData {
}
@end

@interface _TtCC10CryptorRSA10CryptorRSA13PlaintextData : _TtCC10CryptorRSA10CryptorRSA7RSAData {
}
@end

@interface _TtCC10CryptorRSA10CryptorRSA6RSAKey : _TtCs12_SwiftObject {
    id pemString;  // Swift-typed ivar
    id reference;  // Swift-typed ivar
    id type;  // Swift-typed ivar
}
@end

@interface _TtCC10CryptorRSA10CryptorRSA7RSAData : _TtCs12_SwiftObject {
    id data;  // Swift-typed ivar
    id type;  // Swift-typed ivar
}
@end

@interface _TtCC10CryptorRSA10CryptorRSA9PublicKey : _TtCC10CryptorRSA10CryptorRSA6RSAKey {
}
@end

@interface _TtCC10Starscream9WebSocket10WSResponse : _TtCs12_SwiftObject {
    id isFin;  // Swift-typed ivar
    id code;  // Swift-typed ivar
    id bytesLeft;  // Swift-typed ivar
    id frameCount;  // Swift-typed ivar
    id buffer;  // Swift-typed ivar
    id firstFrame;  // Swift-typed ivar
}
@end

@interface _TtCV7Logging6Logger7Storage : _TtCs12_SwiftObject {
    id label;  // Swift-typed ivar
    id handler;  // Swift-typed ivar
}
@end
