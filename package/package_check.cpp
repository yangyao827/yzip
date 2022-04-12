//
// Created by yangyao on 2022/4/3.
//
#include "package_check.h"

//void get_file_md5(const std::string &file_name, unsigned char md5_value[MD5_DIGEST_LENGTH]) {
//    memset(md5_value, 0, sizeof(md5_value) * MD5_DIGEST_LENGTH);
//    std::ifstream file(file_name.c_str(), std::ifstream::binary);
//    if (!file) {
//        error_msg(EXIT_FAILURE, PROGRAM_NAME, _("%s: %s"), file_name.data(), strerror(errno));
//    }
//    MD5_CTX md5Context;
//    MD5_Init(&md5Context);
//    char buf[1024 * 16];
//    while (file.good()) {
//        file.read(buf, sizeof(buf));
//        MD5_Update(&md5Context, buf, file.gcount());
//    }
//    unsigned char result[MD5_DIGEST_LENGTH];
//    MD5_Final(md5_value, &md5Context);
//    file.close();
//}

void get_file_md5(const char *file_name, unsigned char md5_value[MD5_DIGEST_LENGTH]) {
    std::ifstream file(file_name, std::ifstream::binary);
    if (!file) {
        error_msg(EXIT_FAILURE, PROGRAM_NAME, _("%s: %s"), file_name, strerror(errno));
    }
    MD5_CTX md5Context;
    MD5_Init(&md5Context);
    char buf[READ_BUF_SIZE];
    file.seekg(get_offset(file_name) + MD5_DIGEST_LENGTH);
    while (file.good()) {
        file.read(buf, sizeof(buf));
        MD5_Update(&md5Context, buf, file.gcount());
    }
    unsigned char result[MD5_DIGEST_LENGTH];
    MD5_Final(md5_value, &md5Context);
    file.close();
}

bool
check_md5(const unsigned char file_md5_bef[MD5_DIGEST_LENGTH], const unsigned char file_md5_cur[MD5_DIGEST_LENGTH]) {
    for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
        if (file_md5_bef[i] != file_md5_cur[i]) {
            return false;
        }
    }
    return true;
}

//void get_md5_from_file(const std::string &file_name, unsigned char md5_value[MD5_DIGEST_LENGTH]) {
//    memset(md5_value, 0, sizeof(md5_value) * MD5_DIGEST_LENGTH);
//    unsigned char passwd[MD5_DIGEST_LENGTH];
//    bit_file_t *bf;
//    BitFileOpen(file_name.data(), BF_READ);
//    is_encrypt(bf, passwd);
//    for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
//        md5_value[i] = BitFileGetChar(bf);
//    }
//    BitFileClose(bf);
//}

void get_md5_from_file(const char *file_name, unsigned char md5_value[MD5_DIGEST_LENGTH]) {
    //memset(md5_value, 0, sizeof(md5_value) * MD5_DIGEST_LENGTH);
    unsigned char passwd[MD5_DIGEST_LENGTH];
    bit_file_t *bf;
    bf = BitFileOpen(file_name, BF_READ);
    is_encrypt(bf, passwd);
    for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
        md5_value[i] = BitFileGetChar(bf);
    }
    BitFileClose(bf);
}

bool check_file_md5(const char *file_name) {
    unsigned char file_md5[MD5_DIGEST_LENGTH];//计算文件的md5
    unsigned char read_file_md5[MD5_DIGEST_LENGTH];//文件中写入的原md5
    memset(file_md5, 0, sizeof(file_md5));
    memset(read_file_md5, 0, sizeof(read_file_md5));
    get_file_md5(file_name, file_md5);
    get_md5_from_file(file_name, read_file_md5);
    if (check_md5(read_file_md5, file_md5)) {
        return true;
    }
    return false;
}

void check_file(const char *file_name, bool flag) {//flag用来控制是否输出无错误信息
    if (check_file_md5(file_name)) {
        if (flag) {
            printf("No errors were found in: %s\n", file_name);
            exit(1);
        }
    } else {
        printf("At least one error has been found in: %s\n", file_name);
        exit(0);
    }
}

void write_md5(const char *file_name, unsigned char md5[MD5_DIGEST_LENGTH]) {
    FILE *file;
    file = fopen(file_name, "r+");
    fseek(file, get_offset(file_name), 0);
    fwrite(md5, MD5_DIGEST_LENGTH, 1, file);
    fclose(file);
}

void file_md5_init(bit_file_t *bf) {
    for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
        BitFilePutChar(0, bf);
    }
}

off_t adjust_file_ptr(bit_file_t *bf){
   fseek(get_bitfile_fp(bf),MD5_DIGEST_LENGTH,SEEK_CUR);
    return ftell(get_bitfile_fp(bf));
}