#import <OpenGLES/gltypes.h>
#import <Foundation/Foundation.h>

typedef struct {
    GLfloat x;			/**< The X-componenent of the vector. */
    GLfloat y;			/**< The Y-componenent of the vector. */
    GLfloat z;			/**< The Z-componenent of the vector. */
} AnLiveGLVector;


AnLiveGLVector AnLiveGLVectorMake(GLfloat x, GLfloat y, GLfloat z) {
    AnLiveGLVector v;
    v.x = x;
    v.y = y;
    v.z = z;
    return v;
}

GLfloat AnLiveGLVectorLength(AnLiveGLVector v) {
    GLfloat x = v.x;
    GLfloat y = v.y;
    GLfloat z = v.z;
    return sqrtf((x * x) + (y * y) + (z * z));
}

AnLiveGLVector AnLiveGLVectorNormalize(AnLiveGLVector v) {
    GLfloat len = AnLiveGLVectorLength(v);
    if (len == 0.0) return v;
    
    AnLiveGLVector normal;
    normal.x = v.x / len;
    normal.y = v.y / len;
    normal.z = v.z / len;
    return normal;
}

AnLiveGLVector AnLiveGLVectorCross(AnLiveGLVector v1, AnLiveGLVector v2) {
    AnLiveGLVector result;
    result.x = v1.y * v2.z - v1.z * v2.y;
    result.y = v1.z * v2.x - v1.x * v2.z;
    result.z = v1.x * v2.y - v1.y * v2.x;
    return result;
}

AnLiveGLVector AnLiveGLDifference(AnLiveGLVector minuend, AnLiveGLVector subtrahend) {
    AnLiveGLVector difference;
    difference.x = minuend.x - subtrahend.x;
    difference.y = minuend.y - subtrahend.y;
    difference.z = minuend.z - subtrahend.z;
    return difference;
}

AnLiveGLVector AnLiveGLVectorNegate(AnLiveGLVector v) {
    AnLiveGLVector result;
    result.x = -v.x;
    result.y = -v.y;
    result.z = -v.z;
    return result;
}

@interface AnLiveGLMatrix : NSObject <NSCopying>

+(id) matrix;

-(GLfloat*) getMatrix;

-(void) populateToLookAt: (AnLiveGLVector) targetLocation
               withEyeAt: (AnLiveGLVector) eyeLocation
                  withUp: (AnLiveGLVector) upDirection;

@end