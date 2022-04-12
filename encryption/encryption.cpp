//
// Created by yangyao on 2022/3/22.
//

#include "encryption.h"

//判断是不是正确的密码
bool md5_compare(unsigned char correct_passwd[MD5_DIGEST_LENGTH], unsigned char passwd[MD5_DIGEST_LENGTH]) {
    for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
        if (correct_passwd[i] != passwd[i]) {
            return false;
        }
    }
    return true;
}

//输入密码进行判断
void is_correct_passwd(bit_file_t *bf) {
    unsigned char correct_passwd[MD5_DIGEST_LENGTH];//正确的密码序列
    unsigned char passwd[MD5_DIGEST_LENGTH];//输入的密码序列
    string passwd_str{};
    if (is_encrypt(bf, correct_passwd)) {//如果加密了
        printf("This file is encrypted, please enter your password:\n");
        system("stty -echo");
        for (int i = 0; i < ERRORCOUNT; ++i) {/*最多试3次退出*/
            cin >> passwd_str;
            md5code(passwd, passwd_str);//获取输入密码的md5
            if (md5_compare(correct_passwd, passwd)) {//密码正确
                system("stty echo");
                return;
            } else {
                if (i < 2)
                    printf("Incorrect password, please try again:\n");
            }
        }
        system("stty echo");
        error_msg(EXIT_FAILURE, PROGRAM_NAME, _("You've entered the wrong password too many times"), nullptr);
    }
}


//获取字符串的MD5
void md5code(unsigned char outmd[MD5_DIGEST_LENGTH], string &passwd) {
    //memset(outmd, 0, sizeof(outmd));
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, passwd.data(), passwd.size());
    MD5_Final(outmd, &ctx);
}

//判断是否加密了,并且提取出加密后的密码
bool is_encrypt(bit_file_t *bf, unsigned char md5[MD5_DIGEST_LENGTH]) {
    //memset(md5, 0, sizeof(md5));
    unsigned int flag;//判断是否加密，如果开头16位全1，就为加密，否则为未加密。
    int max_code = (1 << ENCRYPT_CODE_LEN);
    flag = GetCodeWord(bf, ENCRYPT_CODE_LEN);
    if (flag== (max_code - 1)) {
        for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
            md5[i] = BitFileGetChar(bf);
        }
        return true;
    }
    return false;
}
//判断是否加密了
bool is_encrypt(const char *file_name) {
    unsigned int flag;//判断是否加密，如果开头16位全1，就为加密，否则为未加密。
    int max_code = (1 << ENCRYPT_CODE_LEN);
    FILE *file;
    file= fopen(file_name,"r");
    flag = fgetc(file);
    if (flag== (max_code - 1)) {
        fclose(file);
        return true;
    }
    fclose(file);
    return false;
}
//加密压缩文件，前9bit为标志，后面为md5后的密码
void encrypt_file(bit_file_t *bf, string &passwd) {
    unsigned int flag = (2 << ENCRYPT_CODE_LEN) - 1;
    PutCodeWord(bf, flag, ENCRYPT_CODE_LEN);
    unsigned char outmd[MD5_DIGEST_LENGTH];
    md5code(outmd, passwd);
    for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
        BitFilePutChar(outmd[i], bf);
    }
}

int get_offset(const char * file_name){
    if(is_encrypt(file_name)){
        return ENCRYPED_OFFSET;
    }
    return UNENCRYPED_OFFSET;
}