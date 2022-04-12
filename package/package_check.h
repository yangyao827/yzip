//
// Created by yangyao on 2022/4/3.
//

#ifndef DIPLOMA_PROJECT_PACKAGE_CHECK_H
#define DIPLOMA_PROJECT_PACKAGE_CHECK_H
#include <fstream>
#include <openssl/md5.h>
#include <string>
#include <cstring>
#include "../error/error.h"
#include "../system.h"
#include "../version/app_info.h"
#include "../encryption/encryption.h"
#define READ_BUF_SIZE 1024 * 16
//获取文件的MD5值
void get_file_md5(const std::string &file_name, unsigned char md5_value[MD5_DIGEST_LENGTH] );
//校验文件的md5与写入的md5值是否一致,bef为之前写入的md5,cur为现在的md5
bool check_md5(const unsigned char file_md5_bef[MD5_DIGEST_LENGTH],const unsigned char file_md5_cur[MD5_DIGEST_LENGTH]);
//获取文件中写入的md5
void get_md5_from_file(const std::string &file_name, unsigned char md5_value[MD5_DIGEST_LENGTH] );
//检测压缩包是否完整，是返回true,反之返回false
bool check_file_md5(const char *file_name);
void get_md5_from_file(const char*file_name, unsigned char md5_value[MD5_DIGEST_LENGTH]);
void get_file_md5(const char *file_name, unsigned char md5_value[MD5_DIGEST_LENGTH]);
//向文件中写入文件md5值
void write_md5(const char * file_name,unsigned char md5[MD5_DIGEST_LENGTH]);
//在压缩文件中预留md5的位置
void file_md5_init(bit_file_t *bf);
//校验文件，并且输出错误以及正确信息
void check_file(const char *file_name,bool flag);
//调整文件指针，使其指向数据部分，并返回当前文件指针位置
off_t adjust_file_ptr(bit_file_t *bf);
#endif //DIPLOMA_PROJECT_PACKAGE_CHECK_H
