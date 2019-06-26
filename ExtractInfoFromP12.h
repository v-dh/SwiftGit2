//
//  ExtractInfoFromP12.h
//  SwiftGit2
//
//  Created by vdh on 26/06/2019.
//  Copyright © 2019 GitHub, Inc. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface ExtractInfoFromP12 : NSObject
+ (CFArrayRef) GetSSLinfoFromp12:(NSString*) fileNAme andPassword:(NSString*) password;
@end

NS_ASSUME_NONNULL_END
