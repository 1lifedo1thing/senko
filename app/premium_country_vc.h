#ifndef SENKO_PREMIUM_COUNTRY_VC_H
#define SENKO_PREMIUM_COUNTRY_VC_H

#import <UIKit/UIKit.h>

@class PremiumCountryVC;

@protocol PremiumCountryDelegate <NSObject>
- (void)premiumCountryVC:(PremiumCountryVC *)vc didPickCode:(NSString *)code;
@end

/* the countries the gateway offers for amneziawg, one row each. the list and
   the choice belong to the main controller, which asks senkod for the profile */
@interface PremiumCountryVC : UIViewController <UITableViewDataSource, UITableViewDelegate> {
    UITableView *_tv;
    NSArray     *_countries; /* dictionaries with @"code" and @"name" */
    NSString    *_current;
    id<PremiumCountryDelegate> _delegate; /* assigned, the owner outlives the screen */
}

- (id)initWithCountries:(NSArray *)countries current:(NSString *)current
               delegate:(id<PremiumCountryDelegate>)delegate;

@end

#endif
