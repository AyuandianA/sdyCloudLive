#import <Foundation/Foundation.h>
#if TARGET_OS_IPHONE
#import <GLKit/GLKit.h>
#else
#import <AppKit/NSOpenGL.h>
#endif

@class RTCI420Frame;

// RTCOpenGLVideoRenderer issues appropriate OpenGL commands to draw a frame to
// the currently bound framebuffer. Supports OpenGL 3.2 and OpenGLES 2.0. OpenGL
// framebuffer creation and management should be handled elsewhere using the
// same context used to initialize this class.
@interface AnLiveOpenGLVideoRenderer : NSObject

// The last successfully drawn frame. Used to avoid drawing frames unnecessarily
// hence saving battery life by reducing load.
@property(nonatomic, readonly) RTCI420Frame* lastDrawnFrame;
@property BOOL isMirror;

#if TARGET_OS_IPHONE
- (instancetype)initWithContext:(EAGLContext*)context isMirror:(BOOL)isMirror;
#else
- (instancetype)initWithContext:(NSOpenGLContext*)context isMirror:(BOOL)isMirror;
#endif

// Draws |frame| onto the currently bound OpenGL framebuffer. |setupGL| must be
// called before this function will succeed.
- (BOOL)drawFrame:(RTCI420Frame*)frame;

// The following methods are used to manage OpenGL resources. On iOS
// applications should release resources when placed in background for use in
// the foreground application. In fact, attempting to call OpenGLES commands
// while in background will result in application termination.

// Sets up the OpenGL state needed for rendering.
- (void)setupGL;
// Tears down the OpenGL state created by |setupGL|.
- (void)teardownGL;

#ifndef DOXYGEN_SHOULD_SKIP_THIS
// Disallow init and don't add to documentation
- (id)init __attribute__((
                          unavailable("init is not a supported initializer for this class.")));
#endif /* DOXYGEN_SHOULD_SKIP_THIS */

@end
