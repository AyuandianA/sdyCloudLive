//
//  LWHfindFriendsViewController.h
//  sdyCloudLive
//
//  Created by genghui on 2020/8/3.
//  Copyright © 2020 sdy. All rights reserved.
//

#import "BaseViewController.h"

NS_ASSUME_NONNULL_BEGIN
typedef void(^findFriendIDBlock)(void);
@interface LWHfindFriendsViewController : BaseViewController
@property(nonatomic,copy) findFriendIDBlock  findFriendID;

@end

NS_ASSUME_NONNULL_END
