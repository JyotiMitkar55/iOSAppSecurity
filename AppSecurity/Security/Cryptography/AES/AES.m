
#import "AES.h"

@implementation AES

+(NSData *)getAES128EncryptedStringForMessageData:(NSData *)messageData keyData:(NSData *)keyData{
    
	char *keyPtr = (char *)[keyData bytes];

	NSUInteger dataLength = [messageData length];
	size_t bufferSize = dataLength + kCCBlockSizeAES128;
	void *buffer = malloc(bufferSize);

	size_t numBytesEncrypted = 0;
	CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt,
										  kCCAlgorithmAES128,
										  kCCOptionPKCS7Padding|kCCOptionECBMode,
										  keyPtr,
										  kCCKeySizeAES128,
										  [self generateRandomIV:kCCBlockSizeAES128].bytes,
										  [messageData bytes],
										  dataLength,
										  buffer,
										  bufferSize,
										  &numBytesEncrypted);
	if (cryptStatus == kCCSuccess) {
		NSData *encryptedData = [NSData dataWithBytesNoCopy:buffer length:numBytesEncrypted];
		return encryptedData;
	}

	free(buffer);
	return nil;
}

+(NSData *)getAES128DecryptedStringForMessageData:(NSData *)messageData keyData:(NSData *)keyData{
    
    char *keyPtr = (char *)[keyData bytes];
    
    NSUInteger dataLength = [messageData length];
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    
    size_t numBytesEncrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt,
                                          kCCAlgorithmAES128,
                                          kCCOptionPKCS7Padding|kCCOptionECBMode,
                                          keyPtr,
                                          kCCKeySizeAES128,
                                          [self generateRandomIV:kCCBlockSizeAES128].bytes,
                                          [messageData bytes],
                                          dataLength,
                                          buffer,
                                          bufferSize,
                                          &numBytesEncrypted);
    if (cryptStatus == kCCSuccess) {
        NSData *encryptedData = [NSData dataWithBytesNoCopy:buffer length:numBytesEncrypted];
        return encryptedData;
    }
    
    free(buffer);
    return nil;
}

+(NSData *)hexDataFromString:(NSString *)key{
    
	NSUInteger size = key.length;
	NSUInteger dataSize = (size + 1) / 2;

	char finalBytes[dataSize];
	const char *keyBytes = [key UTF8String];

	int j = 0;
	int k = 0;

	if(size % 2 == 1){
		finalBytes[k++] = hexDigitFromChar(keyBytes[j++]);
	}

	while(j < size){
		char first = hexDigitFromChar(keyBytes[j++]);
		char second = hexDigitFromChar(keyBytes[j++]);
		finalBytes[k++] = ((first << 4) | second);
	}

	NSData *data = [[NSData alloc] initWithBytes:(const void *)finalBytes length:dataSize];
	return data;
}

+(NSString *)hexStringFromData:(NSData *)data{
    
	NSInteger size = data.length;
	const char *dataBytes = (const char *)data.bytes;
	const char hexDigits[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

	char hexData[(size * 2) + 1];
	int k = 0;
	int offset = 0;
	for(int i = 0;i < size + offset;i++){
		char c = dataBytes[i];
		hexData[k++] = hexDigits[(((unsigned char)c) >> 4) & 0xf];
		hexData[k++] = hexDigits[c & 0xf];
	}
	hexData[k++] = '\0';

	NSString *hexString = [NSString stringWithCString:hexData encoding:NSASCIIStringEncoding];
	return hexString;
}

char hexDigitFromChar(char c){
    
	char digit = 0;
	if(c >= '0' && c <= '9'){
		digit = c - '0';
	}else if(c >= 'A' && c <= 'F'){
		digit = (c - 'A') + 10;
	}else if(c >= 'a' && c <= 'f'){
		digit = (c - 'a') + 10;
	}
	return digit;
}

+(NSString *)encryptMessage:(NSString *)message withKey:(NSString *)key{

    NSData *keyData = [self hexDataFromString:key];
    NSData *messageData = [message dataUsingEncoding:NSUTF8StringEncoding];
    
    NSData *encryptedData = [self getAES128EncryptedStringForMessageData:messageData keyData:keyData];
    
    NSString *encryptedText = [self hexStringFromData:encryptedData];
    if(encryptedText.length <= 0){
        encryptedText = @"0";
    }
    return encryptedText;
}

+(id)decryptMessage:(NSString *)message withKey:(NSString *)key{
    
    NSData *keyData = [self hexDataFromString:key];
    NSData *messageData = [self hexDataFromString:message];
    NSData *decryptedData = [self getAES128DecryptedStringForMessageData:messageData keyData:keyData];
    
    return [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
}

+(NSData *)generateRandomIV:(size_t)length{
    NSMutableData *data = [NSMutableData dataWithLength:length];
    int output = SecRandomCopyBytes(kSecRandomDefault,length,data.mutableBytes);
    NSAssert(output == 0, @"error generating random bytes: %d",errno);
    return data;
}

@end
