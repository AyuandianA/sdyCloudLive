//
//  LWHChatDetaliTableViewCell.m
//  sdyCloudLive
//
//  Created by genghui on 2020/8/1.
//  Copyright © 2020 sdy. All rights reserved.
//

#import "LWHChatDetaliTableViewCell.h"
#import "AnIMMessage.h"
#import "Header.h"
@implementation LWHChatDetaliTableViewCell

//初始化数据
-(void)chuShiHua
{
//    self.tapSubViewSection(@"1", self.section);
    self.textLabel.textColor = [UIColor blackColor];
}

-(void)changeDataWithModel:(id)model andSection:(NSIndexPath *)section
{
    self.section = section;
    AnIMMessage *nninm = model;
//    NSLog(@"%d \n%@ \n%@\n %@",nninm.type,nninm.message,nninm.customData[@"url"],nninm.fileType);
    self.textLabel.text = nninm.from;
    if (nninm.type == AnIMTextMessage) {
        self.detailTextLabel.text = nninm.message;
        self.imageView.image = [UIImage imageNamed:@""];
    }else if (nninm.type == AnIMBinaryMessage) {
        if ([nninm.fileType isEqualToString:@"image"]) {
            [self.imageView sd_setImageWithURL:[NSURL URLWithString:nninm.customData[@"url"]]];
            self.detailTextLabel.text = @"";
        }

    }
}

@end
