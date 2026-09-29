#ifndef SENKO_SERVER_CELL_H
#define SENKO_SERVER_CELL_H

#import <UIKit/UIKit.h>
#import <QuartzCore/QuartzCore.h>
#import "control_client.h"

/* the remark carries a country as a regional indicator pair. one decoder here
   keeps the row, the detail sheet, and the status line naming a server the
   same way */
NSString *SenkoServerFlagCode(NSString *remark);
NSString *SenkoServerDisplayName(NSString *remark);
/* the flag, or the senko placeholder for a server without one, cut to a
   rounded tile with a sheen, rendered once per size */
UIImage *SenkoServerBadgeImage(NSString *remark, CGFloat side);
/* the soft drop shadow the badge sits on; the view must not clip */
void SenkoStyleBadgeShadow(UIView *view, CGFloat radius);

/* the selection mark every pickable row ends with */
@interface SenkoRadioView : UIView {
    CAShapeLayer *_ring;
    CAShapeLayer *_dot;
    BOOL _checked;
}
- (void)setChecked:(BOOL)checked;
- (void)applyTheme;
@end

/* four bars that read a latency at a glance. level 0 draws them all dim */
@interface SenkoSignalBars : UIView {
    CALayer *_bars[4];
    int _level;
    UIColor *_tint;
}
- (void)setLatency:(NSNumber *)ms;
@end

@interface ServerCell : UITableViewCell {
    UIView *_plate;
    UILabel *_title;
    UILabel *_detail;
    UILabel *_transport;
    UILabel *_unsupported;
    UILabel *_ping;
    UIActivityIndicatorView *_pingActivity;
    UIButton *_pingButton;
    UIImageView *_serverIcon;
    SenkoSignalBars *_bars;
    SenkoRadioView *_radio;
    CAGradientLayer *_plateGrad;
    CALayer *_rule;
    CAShapeLayer *_corners;
    BOOL _groupFirst;
    BOOL _groupLast;
    CGSize _cornersSize;
}
- (void)configureWithServer:(SenkoServer *)server
                      picked:(BOOL)picked
                     pingVal:(NSNumber *)ping
                 displayName:(NSString *)displayName;
- (void)configureWithTitle:(NSString *)title
                     detail:(NSString *)detail
                     picked:(BOOL)picked
                     status:(NSString *)status;
- (void)setPingTarget:(id)target action:(SEL)action serverIndex:(int)serverIndex;
/* rows of one group read as a single card: only its ends are rounded and a
   hairline separates the rows between them */
- (void)setGroupFirst:(BOOL)first last:(BOOL)last;
@end

#endif
