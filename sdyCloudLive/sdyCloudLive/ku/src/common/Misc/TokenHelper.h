/* 
  TokenHelper.h
  Arrownock

  Created by Bill Wang on 4/14/14.
  Copyright (c) 2014 Arrownock Co.,Ltd. All rights reserved.
*/

#import <Foundation/Foundation.h>

@interface ANTokenHelper: NSObject

+ (NSString *) getToken:(NSString *)id appKey:(NSString *)appKey odd:(int)odd prefix:(NSString *)prefix;
@end