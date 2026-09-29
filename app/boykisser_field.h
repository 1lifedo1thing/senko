#ifndef SENKO_BOYKISSER_FIELD_H
#define SENKO_BOYKISSER_FIELD_H

#import <UIKit/UIKit.h>

/* falling sprites: boykisser.png for that theme, any bundle png elsewhere */
@interface SenkoBoykisserField : UIView
- (id)initWithFrame:(CGRect)frame spriteName:(NSString *)name;
- (void)start;
- (void)stop;
/* pause off-screen to save cpu */
- (void)setPaused:(BOOL)paused;
- (BOOL)isRunning;
@end

#endif
