//
// Created by yangyao on 2022/3/22.
//

#ifndef DIPLOMA_PROJECT_ENCRYPTION_H
#define DIPLOMA_PROJECT_ENCRYPTION_H

#include "../bitfile/bitfile.h"
#include "iostream"
#include <openssl/md5.h>
#include "cstring"
#include "../error/error.h"
#include "../version/app_info.h"
#include "../system.h"

#define ENCRYPT_CODE_LEN CHAR_BIT
#define ERRORCOUNT 3//输错密码的次数
#define ENCRYPED_OFFSET 17
#define UNENCRYPED_OFFSET 1
using namespace std;

bool is_encrypt(bit_file_t *bf, unsigned char md5[MD5_DIGEST_LENGTH]);

void encrypt_file(bit_file_t *bf, string &passwd);

void md5code(unsigned char outmd[], string &passwd);
bool is_encrypt(bit_file_t *bf);
void is_correct_passwd(bit_file_t *bf);
//获取加密的字节数，未加密为1字节，加密后为17字节
int get_offset(const char *file_name);
#endif //DIPLOMA_PROJECT_ENCRYPTION_H
