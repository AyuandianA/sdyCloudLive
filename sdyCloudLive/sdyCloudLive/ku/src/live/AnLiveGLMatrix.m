#import "AnLiveGLMatrix.h"

@interface AnLiveGLMatrix (){

}
@end


@implementation AnLiveGLMatrix {
    GLfloat glArray[16];
}

-(GLfloat*) getMatrix {
    return glArray;
}

-(id) initParent {
    return [super init];
}

-(id) init {
    if((self = [self initParent])) {
        memset(glArray, 0, 16 * sizeof(GLfloat));
    }
    return self;
}

+(id) matrix {
    return [[self alloc] init];
}

-(void) populateToLookAt: (AnLiveGLVector) targetLocation
               withEyeAt: (AnLiveGLVector) eyeLocation
                  withUp: (AnLiveGLVector) upDirection
{    
    AnLiveGLVector fwdDir = AnLiveGLDifference(targetLocation, eyeLocation);
    [AnLiveGLMatrix populate: glArray toPointTowards: fwdDir withUp: upDirection];
    [AnLiveGLMatrix transpose: glArray];
    [AnLiveGLMatrix translate: glArray by: AnLiveGLVectorNegate(eyeLocation)];
}

- (AnLiveGLVector)getVectorDifference:(AnLiveGLVector)minuend subtrahend:(AnLiveGLVector)subtrahend
{
    AnLiveGLVector difference;
    difference.x = minuend.x - subtrahend.x;
    difference.y = minuend.y - subtrahend.y;
    difference.z = minuend.z - subtrahend.z;
    return difference;
}

+(void) populate: (GLfloat*) aGLMatrix toPointTowards: (AnLiveGLVector) fwdDirection withUp: (AnLiveGLVector) upDirection {
    /*
     |  rx  ux  -fx  0 |
     M = |  ry  uy  -fy  0 |
     |  rz  uz  -fz  0 |
     |  0   0    0   1 |
     
     where f is the normalized Forward vector (the direction being pointed to)
     and u is the normalized Up vector in the rotated frame
     and r is the normalized Right vector in the rotated frame
     */
    AnLiveGLVector f, u, r;
    
    f = AnLiveGLVectorNormalize(fwdDirection);
    r = AnLiveGLVectorNormalize(AnLiveGLVectorCross(f, upDirection));
    u = AnLiveGLVectorCross(r, f);			// already normalized since f & r are orthonormal
    
    aGLMatrix[0]  = r.x;
    aGLMatrix[1]  = r.y;
    aGLMatrix[2]  = r.z;
    aGLMatrix[3] = 0.0;
    
    aGLMatrix[4]  = u.x;
    aGLMatrix[5]  = u.y;
    aGLMatrix[6]  = u.z;
    aGLMatrix[7] = 0.0;
    
    aGLMatrix[8]  = -f.x;
    aGLMatrix[9]  = -f.y;
    aGLMatrix[10] = -f.z;
    aGLMatrix[11] = 0.0;
    
    aGLMatrix[12]  = 0.0;
    aGLMatrix[13]  = 0.0;
    aGLMatrix[14] = 0.0;
    aGLMatrix[15] = 1.0;
}

+(void) transpose: (GLfloat*) aGLMatrix {
    [self swap: 1 with: 4 inMatrix: aGLMatrix];
    [self swap: 2 with: 8 inMatrix: aGLMatrix];
    [self swap: 3 with: 12 inMatrix: aGLMatrix];
    [self swap: 6 with: 9 inMatrix: aGLMatrix];
    [self swap: 7 with: 13 inMatrix: aGLMatrix];
    [self swap: 11 with: 14 inMatrix: aGLMatrix];
}

+(void) swap: (GLuint) idx1 with: (GLuint) idx2 inMatrix: (GLfloat*) aGLMatrix {
    GLfloat tmp = aGLMatrix[idx1];
    aGLMatrix[idx1] = aGLMatrix[idx2];
    aGLMatrix[idx2] = tmp;
}

+(void) translate: (GLfloat*) aGLMatrix by: (AnLiveGLVector) aVector {
    GLfloat* m = aGLMatrix;					// Make a simple alias
    
    m[12] = aVector.x * m[0] + aVector.y * m[4] + aVector.z * m[8] + m[12];
    m[13] = aVector.x * m[1] + aVector.y * m[5] + aVector.z * m[9] + m[13];
    m[14] = aVector.x * m[2] + aVector.y * m[6] + aVector.z * m[10] + m[14];
    m[15] = aVector.x * m[3] + aVector.y * m[7] + aVector.z * m[11] + m[15];
}

@end