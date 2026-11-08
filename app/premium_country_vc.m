#import "premium_country_vc.h"

#import "app_common.h"
#import "crash_report.h"
#import "ui_theme.h"

#include <objc/message.h>

@implementation PremiumCountryVC

- (id)initWithCountries:(NSArray *)countries current:(NSString *)current
               delegate:(id<PremiumCountryDelegate>)delegate {
    if ((self = [super init])) {
        _countries = [countries copy];
        _current = [current copy];
        _delegate = delegate;
    }
    return self;
}

- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
    _tv.dataSource = nil;
    _tv.delegate = nil;
    [_tv release];
    [_countries release];
    [_current release];
    [super dealloc];
}

/* ios 5 releases the view of an offscreen controller, so the retained table
   must go with it instead of pointing into a freed hierarchy */
- (void)viewDidUnload {
    _tv.dataSource = nil;
    _tv.delegate = nil;
    [_tv release];
    _tv = nil;
    [super viewDidUnload];
}

- (void)cancelPressed {
    SenkoDismissModal(self, nil);
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = SenkoLocalizedText(@"Premium country");
    if ([self respondsToSelector:@selector(setEdgesForExtendedLayout:)])
        ((void (*)(id, SEL, NSUInteger))objc_msgSend)(self, @selector(setEdgesForExtendedLayout:), 0);
    SenkoApplyScreenChrome(self.view);
    self.navigationItem.leftBarButtonItem = [[[UIBarButtonItem alloc]
        initWithBarButtonSystemItem:UIBarButtonSystemItemCancel
                           target:self
                           action:@selector(cancelPressed)] autorelease];
    _tv = [[UITableView alloc] initWithFrame:self.view.bounds style:UITableViewStyleGrouped];
    _tv.dataSource = self;
    _tv.delegate = self;
    _tv.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    SenkoClearTableBackground(_tv);
    if ([_tv respondsToSelector:@selector(setBackgroundView:)]) _tv.backgroundView = nil;
    [self.view addSubview:_tv];
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(themeDidChange:)
                                                 name:SenkoThemeDidChangeNotification
                                               object:nil];
}

- (void)viewWillAppear:(BOOL)animated {
    SenkoCrashScreen("premium-country");
    [super viewWillAppear:animated];
    if (self.navigationController) StyleNavBarClassic(self.navigationController);
}

- (void)themeDidChange:(NSNotification *)n {
    (void)n;
    SenkoApplyScreenChrome(self.view);
    SenkoClearTableBackground(_tv);
    if (self.navigationController) StyleNavBarClassic(self.navigationController);
    [_tv reloadData];
}

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tv { (void)tv; return 1; }

- (NSInteger)tableView:(UITableView *)tv numberOfRowsInSection:(NSInteger)s {
    (void)tv; (void)s;
    return (NSInteger)[_countries count];
}

- (UITableViewCell *)tableView:(UITableView *)tv cellForRowAtIndexPath:(NSIndexPath *)ip {
    static NSString *cid = @"country";
    UITableViewCell *cell = [tv dequeueReusableCellWithIdentifier:cid];
    if (!cell)
        cell = [[[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault
                                       reuseIdentifier:cid] autorelease];
    if (ip.row >= (NSInteger)[_countries count]) return cell;
    NSDictionary *country = [_countries objectAtIndex:ip.row];
    NSString *code = [country objectForKey:@"code"];
    cell.backgroundColor = kCellHi;
    cell.contentView.backgroundColor = [UIColor clearColor];
    cell.textLabel.backgroundColor = [UIColor clearColor];
    cell.textLabel.font = [UIFont systemFontOfSize:16.0f];
    cell.textLabel.textColor = kInk;
    cell.textLabel.text = [country objectForKey:@"name"];
    /* the flag comes from its own code: the gateway lists us-east and us-west
       as regions that both draw the us flag */
    NSString *flag = [country objectForKey:@"flag"];
    cell.imageView.image = [flag length]
        ? [UIImage imageNamed:[NSString stringWithFormat:@"flag-%@.png", [flag lowercaseString]]]
        : nil;
    cell.accessoryType = [code isEqualToString:_current]
        ? UITableViewCellAccessoryCheckmark : UITableViewCellAccessoryNone;
    return cell;
}

- (void)tableView:(UITableView *)tv didSelectRowAtIndexPath:(NSIndexPath *)ip {
    [tv deselectRowAtIndexPath:ip animated:YES];
    if (ip.row >= (NSInteger)[_countries count]) return;
    NSString *code = [[_countries objectAtIndex:ip.row] objectForKey:@"code"];
    SenkoDismissModal(self, nil);
    if (![code isEqualToString:_current])
        [_delegate premiumCountryVC:self didPickCode:code];
}

@end
