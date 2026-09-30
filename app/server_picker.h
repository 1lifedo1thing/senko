#ifndef SENKO_SERVER_PICKER_H
#define SENKO_SERVER_PICKER_H

#import <UIKit/UIKit.h>
#import "server_cell.h"
#import "home_view.h"

/* the picker reports intent only. the main controller keeps the catalog, the
   selection and the table data, so the list keeps one owner */
@protocol SenkoServerPickerDelegate <NSObject>
- (void)serverPickerClose;
- (void)serverPickerAdd;
- (void)serverPickerManageSubscriptions;
- (void)serverPickerSort;
- (void)serverPickerPing;
- (void)serverPickerChooseAuto;
/* 0 is every group, then one chip per group in list order */
- (void)serverPickerChooseChip:(NSInteger)index;
- (void)serverPickerQueryChanged:(NSString *)query;
@end

/* a full screen layer over the home screen, not a presented controller: the
   sheets, alerts and imports the list starts keep presenting from the one
   controller that already owns them */
@interface SenkoServerPicker : UIView <UITextFieldDelegate> {
@public
    UIButton       *closeButton;
    UIButton       *addButton;
    UIButton       *subscriptionButton;
    UILabel        *titleLabel;
    SenkoReliefControl *searchPlate;
    UIImageView    *searchIcon;
    UITextField    *searchField;
    UIButton       *sortButton;
    UIButton       *pingButton;
    UIScrollView   *chipBar;
    UITableView    *table;
    UIView         *autoHeader;
    SenkoReliefControl *autoRow;
    UIImageView    *autoIcon;
    UILabel        *autoTitle;
    UILabel        *autoSubtitle;
    SenkoRadioView *autoRadio;
    NSMutableArray *_chips;
    NSArray        *_chipTitles;
    NSInteger       _selectedChip;
    CGFloat         _keyboardInset;
    id<SenkoServerPickerDelegate> _delegate; /* assigned, the owner outlives the picker */
}
- (id)initWithFrame:(CGRect)frame
              table:(UITableView *)list
           delegate:(id<SenkoServerPickerDelegate>)delegate;
- (void)setChipTitles:(NSArray *)titles selected:(NSInteger)selected;
- (void)setAutoVisible:(BOOL)visible picked:(BOOL)picked subtitle:(NSString *)subtitle;
- (void)clearQuery;
- (void)applyTheme;
- (void)relocalize;
@end

#endif
