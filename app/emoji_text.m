#import <UIKit/UIKit.h>
#import <CoreText/CoreText.h>
#import <objc/runtime.h>
#import "emoji_text.h"
#include <stdint.h>
#include <stdlib.h>

static NSString * const kSenkoEmojiName = @"SenkoEmojiName";
static NSSet *gEmojiNames;
static NSDictionary *gEmojiNormalized;
static NSCache *gEmojiImages;
static NSCache *gEmojiNative;
static NSString *gEmojiDirectory;
static uint8_t gEmojiFirst[0x20000 / 8];

typedef struct {
    CGFloat side;
} SenkoEmojiRun;

static void SenkoEmojiRunFree(void *p) { free(p); }
static CGFloat SenkoEmojiRunAscent(void *p) { return ((SenkoEmojiRun *)p)->side * 0.82f; }
static CGFloat SenkoEmojiRunDescent(void *p) { return ((SenkoEmojiRun *)p)->side * 0.18f; }
static CGFloat SenkoEmojiRunWidth(void *p) { return ((SenkoEmojiRun *)p)->side; }

static void SenkoEmojiLoadNames(void) {
    if (gEmojiNames) return;
    gEmojiDirectory = [[[[NSBundle mainBundle] resourcePath]
        stringByAppendingPathComponent:@"emoji"] copy];
    NSArray *files = [[NSFileManager defaultManager]
        contentsOfDirectoryAtPath:gEmojiDirectory error:nil];
    NSMutableSet *names = [NSMutableSet setWithCapacity:[files count]];
    for (NSString *file in files) {
        if (![[file pathExtension] isEqualToString:@"png"]) continue;
        NSString *stem = [file stringByDeletingPathExtension];
        [names addObject:stem];
        unsigned int first = 0;
        if ([[NSScanner scannerWithString:stem] scanHexInt:&first] && first < 0x20000)
            gEmojiFirst[first >> 3] |= (uint8_t)(1u << (first & 7));
    }
    gEmojiNames = [names copy];
    NSMutableDictionary *normalized = [NSMutableDictionary dictionaryWithCapacity:[names count]];
    for (NSString *stem in [[names allObjects] sortedArrayUsingSelector:@selector(compare:)]) {
        NSString *key = [stem stringByReplacingOccurrencesOfString:@"-fe0f" withString:@""];
        if (![normalized objectForKey:key] || [key isEqualToString:stem])
            [normalized setObject:stem forKey:key];
    }
    gEmojiNormalized = [normalized copy];
    gEmojiImages = [[NSCache alloc] init];
    [gEmojiImages setCountLimit:128];
    [gEmojiImages setTotalCostLimit:2 * 1024 * 1024];
    gEmojiNative = [[NSCache alloc] init];
    [gEmojiNative setCountLimit:512];
}

static NSUInteger SenkoEmojiScalar(NSString *text, NSUInteger at, uint32_t *out) {
    unichar first = [text characterAtIndex:at];
    if (first >= 0xd800 && first <= 0xdbff && at + 1 < [text length]) {
        unichar next = [text characterAtIndex:at + 1];
        if (next >= 0xdc00 && next <= 0xdfff) {
            *out = 0x10000u + (((uint32_t)first - 0xd800u) << 10) +
                   ((uint32_t)next - 0xdc00u);
            return 2;
        }
    }
    *out = first;
    return 1;
}

/* match the longest asset so a joined family or a flag is one picture */
static NSString *SenkoEmojiMatch(NSString *text, NSUInteger at, NSUInteger *used) {
    *used = 0;
    if (at >= [text length]) return nil;
    uint32_t first = 0;
    SenkoEmojiScalar(text, at, &first);
    if (first >= 0x20000 ||
        !(gEmojiFirst[first >> 3] & (uint8_t)(1u << (first & 7)))) return nil;

    NSMutableString *name = [NSMutableString stringWithCapacity:80];
    NSMutableString *plain = [NSMutableString stringWithCapacity:80];
    NSString *found = nil;
    NSUInteger end = at;
    for (NSUInteger count = 0; count < 24 && end < [text length]; ++count) {
        uint32_t scalar = 0;
        NSUInteger width = SenkoEmojiScalar(text, end, &scalar);
        if (count > 0 && scalar < 0x80u && scalar != '#' && scalar != '*' &&
            (scalar < '0' || scalar > '9')) break;
        end += width;
        if ([name length]) [name appendString:@"-"];
        [name appendFormat:@"%x", scalar];
        if (scalar != 0xfe0fu && scalar != 0xfe0eu) {
            if ([plain length]) [plain appendString:@"-"];
            [plain appendFormat:@"%x", scalar];
        }
        NSString *candidate = [gEmojiNames containsObject:name] ? name :
            ([gEmojiNames containsObject:plain] ? plain : [gEmojiNormalized objectForKey:plain]);
        if (candidate) {
            found = [NSString stringWithString:candidate];
            *used = end - at;
        }
        if (scalar == '\n') break;
    }
    return found;
}

static UIImage *SenkoEmojiImage(NSString *name) {
    UIImage *image = [gEmojiImages objectForKey:name];
    if (image) return image;
    NSString *path = [gEmojiDirectory stringByAppendingPathComponent:
                      [name stringByAppendingPathExtension:@"png"]];
    image = [UIImage imageWithContentsOfFile:path];
    if (image) [gEmojiImages setObject:image forKey:name cost:72 * 72 * 4];
    return image;
}

/* a composite emoji is native only when CoreText shapes it as one glyph */
static BOOL SenkoEmojiNeedsImage(NSString *text, UIFont *font, NSString *name) {
    NSString *key = [NSString stringWithFormat:@"%@/%@", name, font.fontName];
    NSNumber *cached = [gEmojiNative objectForKey:key];
    if (cached) return [cached boolValue];

    BOOL needsImage = YES;
    CTFontRef ctFont = CTFontCreateWithName((CFStringRef)font.fontName,
                                           font.pointSize, NULL);
    if (ctFont) {
        NSAttributedString *styled = [[[NSAttributedString alloc]
            initWithString:text attributes:[NSDictionary dictionaryWithObject:(id)ctFont
                                            forKey:(id)kCTFontAttributeName]] autorelease];
        CTLineRef line = CTLineCreateWithAttributedString((CFAttributedStringRef)styled);
        if (line) {
            CFArrayRef runs = CTLineGetGlyphRuns(line);
            if (CFArrayGetCount(runs) == 1) {
                CTRunRef run = (CTRunRef)CFArrayGetValueAtIndex(runs, 0);
                if (CTRunGetGlyphCount(run) == 1) {
                    CGGlyph glyph = 0;
                    CTRunGetGlyphs(run, CFRangeMake(0, 1), &glyph);
                    CTFontRef runFont = (CTFontRef)[(NSDictionary *)CTRunGetAttributes(run)
                        objectForKey:(id)kCTFontAttributeName];
                    CFStringRef fontName = runFont ? CTFontCopyPostScriptName(runFont) : NULL;
                    needsImage = !glyph || !fontName ||
                        ([(NSString *)fontName rangeOfString:@"LastResort"].location != NSNotFound);
                    if (fontName) CFRelease(fontName);
                }
            }
            CFRelease(line);
        }
        CFRelease(ctFont);
    }
    [gEmojiNative setObject:[NSNumber numberWithBool:needsImage] forKey:key];
    return needsImage;
}

static NSAttributedString *SenkoEmojiText(NSString *text, UIFont *font,
                                         UIColor *color, BOOL *hasEmoji) {
    *hasEmoji = NO;
    if (![text length] || !font || ![gEmojiNames count]) return nil;
    NSMutableString *visible = [NSMutableString stringWithCapacity:[text length]];
    NSMutableArray *runs = [NSMutableArray array];
    for (NSUInteger at = 0; at < [text length];) {
        NSUInteger used = 0;
        NSString *name = SenkoEmojiMatch(text, at, &used);
        if (name && used && SenkoEmojiNeedsImage(
                [text substringWithRange:NSMakeRange(at, used)], font, name)) {
            [runs addObject:[NSDictionary dictionaryWithObjectsAndKeys:
                name, @"name", [NSNumber numberWithUnsignedInteger:[visible length]], @"at", nil]];
            [visible appendString:@"\ufffc"];
            at += used;
            *hasEmoji = YES;
        } else {
            NSUInteger width = 1;
            uint32_t scalar = 0;
            width = SenkoEmojiScalar(text, at, &scalar);
            (void)scalar;
            [visible appendString:[text substringWithRange:NSMakeRange(at, width)]];
            at += width;
        }
    }
    if (!*hasEmoji) return nil;

    CTFontRef ctFont = CTFontCreateWithName((CFStringRef)font.fontName,
                                           font.pointSize, NULL);
    if (!ctFont) return nil;
    NSDictionary *base = [NSDictionary dictionaryWithObjectsAndKeys:
        (id)ctFont, (id)kCTFontAttributeName,
        (id)color.CGColor, (id)kCTForegroundColorAttributeName, nil];
    NSMutableAttributedString *styled = [[[NSMutableAttributedString alloc]
        initWithString:visible attributes:base] autorelease];
    CFRelease(ctFont);
    for (NSDictionary *run in runs) {
        NSUInteger at = [[run objectForKey:@"at"] unsignedIntegerValue];
        SenkoEmojiRun *size = (SenkoEmojiRun *)calloc(1, sizeof *size);
        if (!size) return nil;
        size->side = font.pointSize * 1.05f;
        CTRunDelegateCallbacks callbacks = { kCTRunDelegateVersion1,
            SenkoEmojiRunFree, SenkoEmojiRunAscent,
            SenkoEmojiRunDescent, SenkoEmojiRunWidth };
        CTRunDelegateRef delegate = CTRunDelegateCreate(&callbacks, size);
        if (!delegate) { free(size); return nil; }
        NSRange one = NSMakeRange(at, 1);
        [styled addAttribute:(id)kCTRunDelegateAttributeName value:(id)delegate range:one];
        [styled addAttribute:kSenkoEmojiName value:[run objectForKey:@"name"] range:one];
        [styled addAttribute:(id)kCTForegroundColorAttributeName
                      value:(id)[UIColor clearColor].CGColor range:one];
        CFRelease(delegate);
    }
    return styled;
}

@interface UILabel (SenkoEmojiText)
- (void)senko_drawEmojiTextInRect:(CGRect)rect;
@end

@implementation UILabel (SenkoEmojiText)

- (void)senko_drawEmojiTextInRect:(CGRect)rect {
    if (![self.text length] || rect.size.width < 1.0f || rect.size.height < 1.0f) {
        [self senko_drawEmojiTextInRect:rect];
        return;
    }
    SenkoEmojiLoadNames();
    UIFont *font = self.font;
    BOOL hasEmoji = NO;
    NSAttributedString *styled = SenkoEmojiText(self.text, font,
                                                self.textColor, &hasEmoji);
    if (!hasEmoji || !styled) {
        [self senko_drawEmojiTextInRect:rect];
        return;
    }

    if (self.adjustsFontSizeToFitWidth && self.numberOfLines == 1) {
        CTLineRef whole = CTLineCreateWithAttributedString((CFAttributedStringRef)styled);
        CGFloat width = whole ? (CGFloat)CTLineGetTypographicBounds(whole, NULL, NULL, NULL) : 0;
        if (whole) CFRelease(whole);
        if (width > rect.size.width) {
            CGFloat size = MAX(10.0f, floorf(font.pointSize * rect.size.width / width));
            if (size < font.pointSize) {
                UIFont *smaller = [UIFont fontWithName:font.fontName size:size];
                if (smaller) {
                    font = smaller;
                    styled = SenkoEmojiText(self.text, font, self.textColor, &hasEmoji);
                }
            }
        }
    }

    CTTypesetterRef typesetter = CTTypesetterCreateWithAttributedString((CFAttributedStringRef)styled);
    if (!typesetter) { [self senko_drawEmojiTextInRect:rect]; return; }
    CTLineRef lines[64];
    NSUInteger count = 0, at = 0, length = [styled length];
    NSUInteger limit = self.numberOfLines > 0 ? MIN((NSUInteger)self.numberOfLines, 64u) : 64u;
    CGFloat lineHeight = MAX(font.lineHeight, font.pointSize * 1.12f);
    while (at < length && count < limit &&
           (count == 0 || (CGFloat)(count + 1) * lineHeight <= rect.size.height + 0.5f)) {
        CFIndex take = (self.numberOfLines == 1 || count + 1 == limit)
            ? (CFIndex)(length - at)
            : CTTypesetterSuggestLineBreak(typesetter, (CFIndex)at, rect.size.width);
        if (take < 1) take = 1;
        if ((NSUInteger)take > length - at) take = (CFIndex)(length - at);
        CTLineRef line = CTTypesetterCreateLine(typesetter, CFRangeMake((CFIndex)at, take));
        if (!line) break;
        CGFloat width = (CGFloat)CTLineGetTypographicBounds(line, NULL, NULL, NULL);
        if (width > rect.size.width || (count + 1 == limit && at + (NSUInteger)take < length)) {
            NSDictionary *tokenStyle = [NSDictionary dictionaryWithObjectsAndKeys:
                [styled attribute:(id)kCTFontAttributeName atIndex:0 effectiveRange:NULL],
                (id)kCTFontAttributeName,
                (id)self.textColor.CGColor, (id)kCTForegroundColorAttributeName, nil];
            CTLineRef token = CTLineCreateWithAttributedString((CFAttributedStringRef)
                [[[NSAttributedString alloc] initWithString:@"…"
                    attributes:tokenStyle] autorelease]);
            CTLineRef shortLine = token ? CTLineCreateTruncatedLine(line, rect.size.width,
                                                        kCTLineTruncationEnd, token) : NULL;
            if (shortLine) { CFRelease(line); line = shortLine; }
            if (token) CFRelease(token);
        }
        lines[count++] = line;
        at += (NSUInteger)take;
    }
    CFRelease(typesetter);
    if (!count) { [self senko_drawEmojiTextInRect:rect]; return; }

    CGFloat top = MAX(0.0f, floorf((rect.size.height - count * lineHeight) * 0.5f));
    CGContextRef ctx = UIGraphicsGetCurrentContext();
    if (!ctx) { for (NSUInteger i = 0; i < count; ++i) CFRelease(lines[i]); return; }
    CGContextSaveGState(ctx);
    CGContextClipToRect(ctx, rect);
    CGContextTranslateCTM(ctx, 0.0f, rect.origin.y + rect.size.height);
    CGContextScaleCTM(ctx, 1.0f, -1.0f);
    CGFloat ascent = CTFontGetAscent((CTFontRef)[styled attribute:(id)kCTFontAttributeName
                                                         atIndex:0 effectiveRange:NULL]);
    for (NSUInteger i = 0; i < count; ++i) {
        CGFloat width = (CGFloat)CTLineGetTypographicBounds(lines[i], NULL, NULL, NULL);
        CGFloat x = rect.origin.x;
        if (self.textAlignment == NSTextAlignmentCenter) x += MAX(0.0f, (rect.size.width - width) * 0.5f);
        else if (self.textAlignment == NSTextAlignmentRight) x += MAX(0.0f, rect.size.width - width);
        CGFloat baseline = rect.size.height - top - i * lineHeight - ascent;
        CGContextSetTextPosition(ctx, x, baseline);
        CTLineDraw(lines[i], ctx);
    }
    CGContextRestoreGState(ctx);

    CGContextSaveGState(ctx);
    CGContextClipToRect(ctx, rect);
    for (NSUInteger i = 0; i < count; ++i) {
        CGFloat width = (CGFloat)CTLineGetTypographicBounds(lines[i], NULL, NULL, NULL);
        CGFloat x = rect.origin.x;
        if (self.textAlignment == NSTextAlignmentCenter) x += MAX(0.0f, (rect.size.width - width) * 0.5f);
        else if (self.textAlignment == NSTextAlignmentRight) x += MAX(0.0f, rect.size.width - width);
        for (id run in (NSArray *)CTLineGetGlyphRuns(lines[i])) {
            NSDictionary *attrs = (NSDictionary *)CTRunGetAttributes((CTRunRef)run);
            NSString *name = [attrs objectForKey:kSenkoEmojiName];
            if (!name) continue;
            UIImage *image = SenkoEmojiImage(name);
            if (!image) continue;
            CFRange range = CTRunGetStringRange((CTRunRef)run);
            CGFloat offset = CTLineGetOffsetForStringIndex(lines[i], range.location, NULL);
            CGFloat side = font.pointSize * 1.05f;
            CGRect imageRect = CGRectMake(x + offset,
                rect.origin.y + top + i * lineHeight + (lineHeight - side) * 0.5f,
                side, side);
            [image drawInRect:imageRect];
        }
        CFRelease(lines[i]);
    }
    CGContextRestoreGState(ctx);
}

@end

@interface UITextField (SenkoEmojiText)
- (void)senko_drawEmojiFieldTextInRect:(CGRect)rect;
@end

@implementation UITextField (SenkoEmojiText)

- (void)senko_drawEmojiFieldTextInRect:(CGRect)rect {
    if (!self.isFirstResponder && [self.text length] &&
        rect.size.width > 0.0f && rect.size.height > 0.0f) {
        SenkoEmojiLoadNames();
        BOOL hasEmoji = NO;
        SenkoEmojiText(self.text, self.font, self.textColor, &hasEmoji);
        if (hasEmoji) {
            UILabel *label = [[[UILabel alloc] initWithFrame:rect] autorelease];
            label.backgroundColor = [UIColor clearColor];
            label.text = self.text;
            label.font = self.font;
            label.textColor = self.textColor;
            label.textAlignment = self.textAlignment;
            label.numberOfLines = 1;
            [label drawTextInRect:rect];
            return;
        }
    }
    [self senko_drawEmojiFieldTextInRect:rect];
}

@end

/* ios 12 and newer keep their native emoji renderer */
void SenkoEmojiTextInstall(void) {
    static BOOL installed = NO;
    if (installed) return;
    if ([[[UIDevice currentDevice] systemVersion] integerValue] >= 12) return;
    Method old = class_getInstanceMethod([UILabel class], @selector(drawTextInRect:));
    Method replacement = class_getInstanceMethod([UILabel class], @selector(senko_drawEmojiTextInRect:));
    if (old && replacement) {
        method_exchangeImplementations(old, replacement);
        installed = YES;
    }
    old = class_getInstanceMethod([UITextField class], @selector(drawTextInRect:));
    replacement = class_getInstanceMethod([UITextField class],
                                          @selector(senko_drawEmojiFieldTextInRect:));
    if (old && replacement) method_exchangeImplementations(old, replacement);
}
