#import <UIKit/UIKit.h>
#import <QuartzCore/QuartzCore.h>
#import <objc/message.h>
#import "app_common.h"
#import "control_client.h"
#import "native_vpn.h"
#import "server_cell.h"
#import "ui_theme.h"
#import "crash_report.h"

enum {
    SenkoStatsState = 0,
    SenkoStatsServer,
    SenkoStatsUptime,
    SenkoStatsDown,
    SenkoStatsUp,
    SenkoStatsDownRate,
    SenkoStatsUpRate,
    SenkoStatsSessionRows
};

static NSString *SenkoStatsUptimeText(long seconds) {
    if (seconds < 0) return nil;
    long h = seconds / 3600;
    long m = (seconds % 3600) / 60;
    long s = seconds % 60;
    if (h > 0) return [NSString stringWithFormat:@"%ld:%02ld:%02ld", h, m, s];
    return [NSString stringWithFormat:@"%ld:%02ld", m, s];
}

/* the plan left on a subscription, as the panel reports it in its headers */
static NSString *SenkoStatsSubscriptionText(SenkoSub *sub) {
    NSMutableArray *parts = [NSMutableArray array];
    unsigned long long used = sub->upload + sub->download;
    if (sub->total)
        [parts addObject:[NSString stringWithFormat:SenkoLocalizedText(@"%@ of %@"),
                          SenkoFormatBytes(used), SenkoFormatBytes(sub->total)]];
    else if (used)
        [parts addObject:SenkoFormatBytes(used)];
    if (sub->expire) {
        NSDate *date = [NSDate dateWithTimeIntervalSince1970:(NSTimeInterval)sub->expire];
        if ([date timeIntervalSinceNow] <= 0.0) {
            [parts addObject:SenkoLocalizedText(@"expired")];
        } else {
            NSDateFormatter *fmt = [[[NSDateFormatter alloc] init] autorelease];
            fmt.dateFormat = SenkoLanguageIsRussian() ? @"dd.MM.yy" : @"yyyy-MM-dd";
            [parts addObject:[fmt stringFromDate:date]];
        }
    }
    return [parts count] ? [parts componentsJoinedByString:@" · "] : @"—";
}

@implementation StatsVC {
    UITableView *_tv;
    SenkoControl *_ctl;
    SenkoNativeVPN *_native;
    NSTimer *_timer;
    NSUInteger _generation;
    BOOL _polling;
    NSString *_state;
    NSString *_serverName;
    NSArray *_subs;
    long _uptime;
    CFTimeInterval _uptimeAt;
    BOOL _uptimeKnown;
    BOOL _trafficKnown;
    uint64_t _up;
    uint64_t _down;
    double _upRate;
    double _downRate;
    CFTimeInterval _sampleAt;
    BOOL _awg;
}

- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
    [_timer invalidate];
    _tv.dataSource = nil;
    _tv.delegate = nil;
    [_tv release];
    [_ctl release];
    [_native release];
    [_state release];
    [_serverName release];
    [_subs release];
    [super dealloc];
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = SenkoLocalizedText(@"Statistics");
    _ctl = [[SenkoControl alloc] initWithSocketPath:SENKO_SOCK];
    if ([SenkoNativeVPN available]) _native = [[SenkoNativeVPN alloc] init];
    _state = [@"idle" copy];
    if ([self respondsToSelector:@selector(setEdgesForExtendedLayout:)])
        ((void (*)(id, SEL, NSUInteger))objc_msgSend)(self, @selector(setEdgesForExtendedLayout:), 0);
    if ([self respondsToSelector:@selector(setAutomaticallyAdjustsScrollViewInsets:)])
        ((void (*)(id, SEL, BOOL))objc_msgSend)(self, @selector(setAutomaticallyAdjustsScrollViewInsets:), NO);
    self.navigationItem.leftBarButtonItem =
        [[[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemDone
                                                       target:self
                                                       action:@selector(donePressed)] autorelease];
    SenkoApplyScreenChrome(self.view);
    _tv = [[UITableView alloc] initWithFrame:SenkoViewBounds(self.view)
                                       style:UITableViewStyleGrouped];
    SenkoScrollViewUseManualInsets(_tv);
    _tv.dataSource = self;
    _tv.delegate = self;
    _tv.rowHeight = 52.0f;
    _tv.separatorStyle = UITableViewCellSeparatorStyleNone;
    SenkoClearTableBackground(_tv);
    if ([_tv respondsToSelector:@selector(setBackgroundView:)]) _tv.backgroundView = nil;
    _tv.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    [self.view addSubview:_tv];
    if (self.navigationController) StyleNavBarClassic(self.navigationController);
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(themeDidChange:)
                                                 name:SenkoThemeDidChangeNotification object:nil];
}

- (void)themeDidChange:(NSNotification *)n {
    (void)n;
    SenkoApplyScreenChrome(self.view);
    SenkoClearTableBackground(_tv);
    if (self.navigationController) StyleNavBarClassic(self.navigationController);
    [_tv reloadData];
}

- (void)viewDidLayoutSubviews {
    [super viewDidLayoutSubviews];
    CGRect b = SenkoViewBounds(self.view);
    _tv.frame = b;
    UIEdgeInsets safe = SenkoSafeAreaInsets(self.view);
    _tv.contentInset = UIEdgeInsetsMake(8.0f, 0.0f, safe.bottom + 16.0f, 0.0f);
    _tv.scrollIndicatorInsets = _tv.contentInset;
}

- (void)viewWillAppear:(BOOL)animated {
    SenkoCrashScreen("statistics");
    [super viewWillAppear:animated];
    [_ctl listCatalog:^(NSArray *servers, NSArray *subs, NSArray *order) {
        (void)order;
        [_subs release];
        _subs = [subs copy];
        for (SenkoServer *sv in servers) {
            if (!sv->selected) continue;
            NSString *name = SenkoServerDisplayName(sv->remark);
            [_serverName release];
            _serverName = [([name length] ? name : sv->host) copy];
            break;
        }
        [_tv reloadData];
    }];
}

- (void)viewDidAppear:(BOOL)animated {
    [super viewDidAppear:animated];
    [self poll];
    [_timer invalidate];
    _timer = [NSTimer scheduledTimerWithTimeInterval:1.0 target:self
                                            selector:@selector(poll)
                                            userInfo:nil repeats:YES];
}

/* the timer holds this controller, so it goes with the screen */
- (void)viewWillDisappear:(BOOL)animated {
    [super viewWillDisappear:animated];
    [_timer invalidate];
    _timer = nil;
    _generation++;
    _polling = NO;
}

- (void)donePressed {
    [self dismissViewControllerAnimated:YES completion:nil];
}

- (void)setStateText:(NSString *)state {
    [_state release];
    _state = [(state ? state : @"idle") copy];
}

- (void)applyTrafficKnown:(BOOL)known up:(uint64_t)up down:(uint64_t)down {
    CFTimeInterval now = CACurrentMediaTime();
    if (known && _trafficKnown && _sampleAt > 0.0 && now - _sampleAt > 0.2 &&
        up >= _up && down >= _down) {
        _upRate = (double)(up - _up) / (now - _sampleAt);
        _downRate = (double)(down - _down) / (now - _sampleAt);
    } else if (!known) {
        _upRate = _downRate = 0.0;
    }
    _trafficKnown = known;
    _up = up;
    _down = down;
    _sampleAt = known ? now : 0.0;
}

/* one status and one counter request per second at most: a poll still in
   flight when the timer fires again is not doubled up */
- (void)poll {
    if (_polling) return;
    _polling = YES;
    NSUInteger generation = ++_generation;
    /* a negative uptime is a backend that keeps no clock */
    void (^gotState)(NSString *, long) = ^(NSString *state, long uptime) {
        if (generation != _generation) return;
        [self setStateText:state];
        BOOL connected = [state isEqualToString:@"connected"];
        _uptimeKnown = connected && uptime >= 0;
        _uptime = uptime;
        _uptimeAt = CACurrentMediaTime();
        if (!connected) {
            _polling = NO;
            [self applyTrafficKnown:NO up:0 down:0];
            [_tv reloadData];
            return;
        }
        void (^received)(BOOL, uint64_t, uint64_t) = ^(BOOL known, uint64_t up, uint64_t down) {
            if (generation != _generation) return;
            _polling = NO;
            [self applyTrafficKnown:known up:up down:down];
            [_tv reloadData];
        };
        if (_native) [_native traffic:received];
        else [_ctl traffic:received];
    };
    if (_native) {
        [_native status:^(NSInteger status, NSDate *connectedDate) {
            NSString *state = status == 3 ? @"connected"
                : (status == 2 || status == 4) ? @"connecting" : @"idle";
            long uptime = connectedDate ? (long)(-[connectedDate timeIntervalSinceNow]) : 0;
            gotState(state, uptime);
        }];
        return;
    }
    [_ctl statusStateWithUptime:^(NSString *state, long uptime) {
        if ([state isEqualToString:@"connected"] || [state isEqualToString:@"connecting"]) {
            _awg = NO;
            gotState(state, uptime);
            return;
        }
/* the server backend idles while amneziawg runs the tunnel, so the profile's
   own status is the one to show then */
        [_ctl awgStatus:^(NSString *awg) {
            NSString *clean = [awg stringByTrimmingCharactersInSet:
                               [NSCharacterSet whitespaceAndNewlineCharacterSet]];
            _awg = [clean isEqualToString:@"connected"] || [clean isEqualToString:@"connecting"];
            gotState(_awg ? clean : (state ? state : @"idle"), -1);
        }];
    }];
}

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tv {
    (void)tv;
    return [_subs count] ? 2 : 1;
}

- (NSInteger)tableView:(UITableView *)tv numberOfRowsInSection:(NSInteger)s {
    (void)tv;
    return s == 0 ? SenkoStatsSessionRows : (NSInteger)[_subs count];
}

- (CGFloat)tableView:(UITableView *)tv heightForHeaderInSection:(NSInteger)s {
    (void)tv; (void)s;
    return 34.0f;
}

- (UIView *)tableView:(UITableView *)tv viewForHeaderInSection:(NSInteger)s {
    UIView *wrap = [[[UIView alloc] initWithFrame:
                     CGRectMake(0, 0, tv.bounds.size.width, 34.0f)] autorelease];
    wrap.backgroundColor = [UIColor clearColor];
    UILabel *label = [[[UILabel alloc] initWithFrame:
                       CGRectMake(20.0f, 8.0f, tv.bounds.size.width - 40.0f, 22.0f)] autorelease];
    label.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    label.backgroundColor = [UIColor clearColor];
    label.font = SenkoFontBody(14.0f, YES);
    label.textColor = kInkMuted;
    label.textAlignment = NSTextAlignmentCenter;
    label.text = SenkoLocalizedText(s == 0 ? @"Session" : @"Subscriptions");
    [wrap addSubview:label];
    return wrap;
}

- (NSString *)sessionValueForRow:(NSInteger)row {
    BOOL connected = [_state isEqualToString:@"connected"];
    switch (row) {
        case SenkoStatsState:
            if (connected) return SenkoLocalizedText(@"Connected");
            if ([_state isEqualToString:@"connecting"]) return SenkoLocalizedText(@"Connecting");
            return SenkoLocalizedText(@"Disconnected");
        case SenkoStatsServer:
            if (_awg) return @"AmneziaWG";
            return [_serverName length] ? _serverName : @"—";
        case SenkoStatsUptime: {
            if (!_uptimeKnown) return @"—";
            NSString *text = SenkoStatsUptimeText(
                _uptime + (long)(CACurrentMediaTime() - _uptimeAt));
            return text ? text : @"—";
        }
        case SenkoStatsDown:
            return _trafficKnown ? SenkoFormatBytes(_down) : @"—";
        case SenkoStatsUp:
            return _trafficKnown ? SenkoFormatBytes(_up) : @"—";
        case SenkoStatsDownRate:
            return _trafficKnown ? SenkoFormatRate(_downRate) : @"—";
        default:
            return _trafficKnown ? SenkoFormatRate(_upRate) : @"—";
    }
}

static NSString *const kSenkoStatsTitles[SenkoStatsSessionRows] = {
    @"Status", @"Server", @"Uptime", @"Downloaded", @"Uploaded",
    @"Download speed", @"Upload speed"
};

static NSString *const kSenkoStatsIcons[SenkoStatsSessionRows] = {
    @"glyph-shield.png", @"glyph-globe.png", @"glyph-clock.png",
    @"glyph-arrow-down.png", @"glyph-arrow-up.png",
    @"glyph-download.png", @"glyph-chart.png"
};

- (UITableViewCell *)tableView:(UITableView *)tv cellForRowAtIndexPath:(NSIndexPath *)ip {
    static NSString *cid = @"stat";
    UITableViewCell *cell = [tv dequeueReusableCellWithIdentifier:cid];
    if (!cell)
        cell = [[[UITableViewCell alloc] initWithStyle:UITableViewCellStyleValue1
                                       reuseIdentifier:cid] autorelease];
    cell.selectionStyle = UITableViewCellSelectionStyleNone;
    cell.textLabel.font = SenkoFontBody(16.0f, NO);
    cell.detailTextLabel.font = SenkoFontBody(15.0f, NO);
    cell.textLabel.textColor = kInk;
    cell.detailTextLabel.textColor = kInkMuted;
    cell.textLabel.backgroundColor = [UIColor clearColor];
    cell.detailTextLabel.backgroundColor = [UIColor clearColor];
    cell.textLabel.shadowColor = nil;
    cell.detailTextLabel.shadowColor = nil;
    SenkoStyleGroupCell(cell, ip, [self tableView:tv numberOfRowsInSection:ip.section]);
    if (ip.section == 0) {
        cell.textLabel.text = SenkoLocalizedText(kSenkoStatsTitles[ip.row]);
        cell.detailTextLabel.text = [self sessionValueForRow:ip.row];
        cell.imageView.image = TintedIconNamed(kSenkoStatsIcons[ip.row], 22.0f, kInk);
        return cell;
    }
    SenkoSub *sub = [_subs objectAtIndex:ip.row];
    NSString *name = [sub->name length] ? sub->name : SenkoLocalizedText(@"Subscription");
    cell.textLabel.text = [name stringByReplacingOccurrencesOfString:@"_" withString:@" "];
    cell.detailTextLabel.text = SenkoStatsSubscriptionText(sub);
    cell.imageView.image = TintedIconNamed(@"glyph-cloud.png", 22.0f, kInk);
    return cell;
}

- (void)tableView:(UITableView *)tv willDisplayCell:(UITableViewCell *)cell
 forRowAtIndexPath:(NSIndexPath *)ip {
    SenkoStyleGroupCell(cell, ip, [self tableView:tv numberOfRowsInSection:ip.section]);
}

@end
