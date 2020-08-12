#if !defined(__has_feature) || !__has_feature(objc_arc)
#error "This file requires ARC support."
#endif

#import "AnLiveVideoView.h"
#import "AnLiveLocalVideoView.h"

#import <GLKit/GLKit.h>

#import "RTCI420Frame.h"
#import "RTCVideoRenderer.h"
#import "AnLiveOpenGLVideoRenderer.h"

// RTCDisplayLinkTimer wraps a CADisplayLink and is set to fire every two screen
// refreshes, which should be 30fps. We wrap the display link in order to avoid
// a retain cycle since CADisplayLink takes a strong reference onto its target.
// The timer is paused by default.
@interface AnLiveDisplayLinkTimer : NSObject

@property(nonatomic) BOOL isPaused;

- (instancetype)initWithTimerHandler:(void (^)(void))timerHandler;
- (void)invalidate;

@end

@implementation AnLiveDisplayLinkTimer {
    CADisplayLink* _displayLink;
    void (^_timerHandler)(void);
}

- (instancetype)initWithTimerHandler:(void (^)(void))timerHandler {
    NSParameterAssert(timerHandler);
    if (self = [super init]) {
        _timerHandler = timerHandler;
        _displayLink =
        [CADisplayLink displayLinkWithTarget:self
                                    selector:@selector(displayLinkDidFire:)];
        _displayLink.paused = YES;
        // Set to half of screen refresh, which should be 30fps.
        [_displayLink setFrameInterval:2];
        [_displayLink addToRunLoop:[NSRunLoop currentRunLoop]
                           forMode:NSRunLoopCommonModes];
    }
    return self;
}

- (void)dealloc {
    [self invalidate];
}

- (BOOL)isPaused {
    return _displayLink.paused;
}

- (void)setIsPaused:(BOOL)isPaused {
    _displayLink.paused = isPaused;
}

- (void)invalidate {
    [_displayLink invalidate];
}

- (void)displayLinkDidFire:(CADisplayLink*)displayLink {
    _timerHandler();
}

@end

@interface AnLiveVideoView () <GLKViewDelegate, RTCVideoRenderer>
// |i420Frame| is set when we receive a frame from a worker thread and is read
// from the display link callback so atomicity is required.
@property(atomic, strong) RTCI420Frame* i420Frame;
@property(nonatomic, readonly) GLKView* glkView;
@property(nonatomic, readonly) AnLiveOpenGLVideoRenderer* glRenderer;
@property(nonatomic, readwrite) float videoWidth;
@property(nonatomic, readwrite) float videoHeight;
@end

@implementation AnLiveVideoView {
    AnLiveDisplayLinkTimer* _timer;
    GLKView* _glkView;
    AnLiveOpenGLVideoRenderer* _glRenderer;
}

- (instancetype)initWithFrame:(CGRect)frame {
    if (self = [super initWithFrame:frame]) {
        EAGLContext* glContext = [[EAGLContext alloc] initWithAPI:kEAGLRenderingAPIOpenGLES2];
        if([self isKindOfClass:[AnLiveLocalVideoView class]])
        {
            _glRenderer = [[AnLiveOpenGLVideoRenderer alloc] initWithContext:glContext isMirror:YES];
        }
        else
        {
            _glRenderer = [[AnLiveOpenGLVideoRenderer alloc] initWithContext:glContext isMirror:NO];
        }
        // GLKView manages a framebuffer for us.
        _glkView = [[GLKView alloc] initWithFrame:CGRectZero
                                          context:glContext];
        _glkView.drawableColorFormat = GLKViewDrawableColorFormatRGBA8888;
        _glkView.drawableDepthFormat = GLKViewDrawableDepthFormatNone;
        _glkView.drawableStencilFormat = GLKViewDrawableStencilFormatNone;
        _glkView.drawableMultisample = GLKViewDrawableMultisampleNone;
        _glkView.delegate = self;
        _glkView.layer.masksToBounds = YES;
        [self addSubview:_glkView];
        
        // Listen to application state in order to clean up OpenGL before app goes
        // away.
        NSNotificationCenter* notificationCenter =
        [NSNotificationCenter defaultCenter];
        [notificationCenter addObserver:self
                               selector:@selector(willResignActive)
                                   name:UIApplicationWillResignActiveNotification
                                 object:nil];
        [notificationCenter addObserver:self
                               selector:@selector(didBecomeActive)
                                   name:UIApplicationDidBecomeActiveNotification
                                 object:nil];
        
        // Frames are received on a separate thread, so we poll for current frame
        // using a refresh rate proportional to screen refresh frequency. This
        // occurs on the main thread.
        __weak AnLiveVideoView* weakSelf = self;
        _timer = [[AnLiveDisplayLinkTimer alloc] initWithTimerHandler:^{
            AnLiveVideoView* strongSelf = weakSelf;
            // Don't render if frame hasn't changed.
            if (strongSelf.glRenderer.lastDrawnFrame == strongSelf.i420Frame) {
                return;
            }
            // This tells the GLKView that it's dirty, which will then call the
            // GLKViewDelegate method implemented below.
            [strongSelf.glkView setNeedsDisplay];
        }];
        [self setupGL];
    }
    return self;
}

- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
    UIApplicationState appState =
    [UIApplication sharedApplication].applicationState;
    if (appState == UIApplicationStateActive) {
        [self teardownGL];
    }
    [_timer invalidate];
}

#pragma mark - UIView

- (void)layoutSubviews {
    [super layoutSubviews];
    _glkView.frame = self.bounds;
}

#pragma mark - GLKViewDelegate

// This method is called when the GLKView's content is dirty and needs to be
// redrawn. This occurs on main thread.
- (void)glkView:(GLKView*)view drawInRect:(CGRect)rect {
    // The renderer will draw the frame to the framebuffer corresponding to the
    // one used by |view|.
    [_glRenderer drawFrame:self.i420Frame];
}

#pragma mark - RTCVideoRenderer

// These methods may be called on non-main thread.
- (void)setSize:(CGSize)size {
    BOOL isLocal = [self isKindOfClass:[AnLiveLocalVideoView class]];
    BOOL isFirstTime = NO;
    if(!self.videoHeight && !self.videoWidth)
    {
        isFirstTime = YES;
    }
    if(isFirstTime || (self.videoWidth != size.width || self.videoHeight != size.height))
    {
        self.videoWidth = size.width;
        self.videoHeight = size.height;
        if(_delegate && [_delegate respondsToSelector:@selector(onVideoSizeChanged:height:isLocal:isFirstTime:)])
        {
            [_delegate onVideoSizeChanged:size.width height:size.height isLocal:isLocal isFirstTime:isFirstTime];
        }
    }
}

- (void)renderFrame:(RTCI420Frame*)frame {
    self.i420Frame = frame;
}

- (void) clearView
{
    [self renderFrame:nil];
}

#pragma mark - Private

- (void)setupGL {
    self.i420Frame = nil;
    [_glRenderer setupGL];
    _timer.isPaused = NO;
}

- (void)teardownGL {
    self.i420Frame = nil;
    _timer.isPaused = YES;
    [_glkView deleteDrawable];
    [_glRenderer teardownGL];
}

- (void)didBecomeActive {
    [self setupGL];
}

- (void)willResignActive {
    [self teardownGL];
}

@end
