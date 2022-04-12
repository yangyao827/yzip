//
// Created by yangyao on 2022/3/18.
//

#include "lzw.h"

using namespace std;
//编码字典初始化
void dict_init_c(std::unordered_map<std::string, unsigned int> &dict) {
    for (unsigned int i = 0; i < FIRST_CODE; ++i) {
        string str(1, char(i));
        dict.insert({str, i});
    }
}
//解码字典初始化
void dict_init_d(std::unordered_map<unsigned int, std::string> &dict) {
    for (unsigned int i = 0; i < FIRST_CODE; ++i) {
        string str(1, char(i));
        dict.insert({i, str});
    }
}
//输出字符串中的每一个字符
void put_chars(bit_file_t *bf, const string& str) {
    for (auto it: str) {
        BitFilePutChar(it, bf);
    }
}
//编码压缩
void lzw_encoding(FILE *fp_in, const char *out_file, string passwd){
    bit_file_t *bf_in, *bf_out;//创建文件对象
    bf_in = BitFileOpen(fp_in, BF_READ);
    bf_out = BitFileOpen(out_file, BF_WRITE);
    //判断文件是否加密
    if (passwd != "") {/*加密*/
        encrypt_file(bf_out, passwd);
    } else {
        PutCodeWord(bf_out, 0, ENCRYPT_CODE_LEN);//写入未加密的标志
    }
    file_md5_init(bf_out);//预留文件校验值的位置
    unordered_map<string, unsigned int> dict;
    string code_str{};//编码字符串
    unsigned char outmd[MD5_DIGEST_LENGTH];//校验文件的md5
    memset(outmd, 0, sizeof(outmd));
    unsigned int cur_code, next_code, pre_code;//读取的字符和下一个编码
    unsigned char cur_code_len = MIN_CODE_LEN;
    next_code = FIRST_CODE;//下一个编码从256开始
    dict_init_c(dict);//初始化字典
    pre_code = BitFileGetChar(bf_in);//读取第一个字符
    code_str = (char) pre_code;
    while ((cur_code = BitFileGetChar(bf_in)) != EOF) {
        string cur_str(1, cur_code);
        if (dict.find(code_str + cur_str) != dict.end()) {/*编码字符串在字典中*/
            code_str = code_str + cur_str;
            pre_code = dict[code_str];
        } else {/*编码不在字典中*/
            if (next_code < MAX_CODES) {//如果字典还没有满
                dict.insert({code_str + cur_str, next_code});
                next_code++;
            }
            //如果编码是当前编码长度所编码的最大值（全1）,把该值作为需要加长编码长度的标志写进去
            if ((dict[code_str] >= CURRENT_MAX_CODES(cur_code_len)) && (cur_code_len < MAX_CODE_LEN)) {
                PutCodeWord(bf_out, CURRENT_MAX_CODES(cur_code_len), cur_code_len);
                cur_code_len++;
            }
            PutCodeWord(bf_out, dict[code_str], cur_code_len);
            pre_code = cur_code;
            code_str = (char) cur_code;
        }
    }
    PutCodeWord(bf_out, pre_code, cur_code_len);
    //BitFileClose(bf_in);
    BitFileClose(bf_out);
    get_file_md5(out_file, outmd);//获取压缩文件的md5校验值
    //把md5写入文件
    write_md5(out_file, outmd);
    memset(outmd, 0, sizeof(outmd));
    get_md5_from_file(out_file, outmd);
}
//解码解压
void lzw_decoding(const char *in_file,FILE *fp_out) {
    bit_file_t *bf_in, *bf_out;//创建文件对象
    bf_in = BitFileOpen(in_file, BF_READ);
    bf_out = BitFileOpen(fp_out, BF_WRITE);
    is_correct_passwd(bf_in);//判断加密
    check_file(in_file, false);//校验压缩包完整性
    adjust_file_ptr(bf_in);//调整文件指针指向数据部分
    unordered_map<unsigned int, string> dict;
    dict_init_d(dict);//初始化字典
    unsigned int pre_code, cur_code, next_code = FIRST_CODE;//读取的字符和下一个编码
    unsigned char cur_code_len = MIN_CODE_LEN;
    pre_code = GetCodeWord(bf_in, cur_code_len);
    BitFilePutChar(pre_code, bf_out);
    string pre_str(1, char(pre_code)), cur_str;//前一个编码的字符和现在的字符
    while ((cur_code = GetCodeWord(bf_in, cur_code_len)) != EOF) {
        //如果当前读取的编码是当前编码长度的最大表示（全1），则表示下一个读取的编码长度需要加一
        if ((cur_code == CURRENT_MAX_CODES(cur_code_len)) && (cur_code_len < MAX_CODE_LEN)) {
            cur_code_len++;
            cur_code = GetCodeWord(bf_in, cur_code_len);
        }
        if (cur_code >= next_code) {/*不在字典里面*/
            cur_str = pre_str + pre_str[0];/*这种情况用pre_str+pre_str[0]编码即可*/
            put_chars(bf_out, cur_str);
            if (next_code < MAX_CODES) {//字典没有满
                dict.insert({next_code, cur_str});
                next_code++;
            }
        } else {//在字典中
            cur_str = dict[cur_code];
            put_chars(bf_out, cur_str);
            if (next_code < MAX_CODES) {
                dict.insert({next_code, pre_str + cur_str[0]});
                next_code++;
            }
        }
        pre_code = cur_code;
        pre_str = cur_str;
    }
    BitFileClose(bf_in);
    //BitFileClose(bf_out);
}
//解压头部信息
void lzw_decoding_for_list(const char *pkg_file_in,FILE * fp_tmp_out){
    bit_file_t *bf_in, *bf_out;//创建文件对象
    bf_in = BitFileOpen(pkg_file_in, BF_READ);
    bf_out = BitFileOpen(fp_tmp_out, BF_WRITE);
    is_correct_passwd(bf_in);//判断加密，加密后无法查看文件内容
    check_file(pkg_file_in, false);//校验压缩包完整性
    off_t data_offset=adjust_file_ptr(bf_in);//调整文件指针指向数据部分,并保存位置
    unordered_map<unsigned int, string> dict;
    dict_init_d(dict);//初始化字典
    unsigned int pre_code, cur_code, next_code = FIRST_CODE;//读取的字符和下一个编码
    unsigned char cur_code_len = MIN_CODE_LEN;
    unsigned int file_count= 999;//获取文件个数（16bit）
    fseek(get_bitfile_fp(bf_in),data_offset,SEEK_SET);//调整文件指针指向数据部分
    pre_code = GetCodeWord(bf_in, cur_code_len);//读取第一个字符
    BitFilePutChar(pre_code, bf_out);
    string pre_str(1, char(pre_code)), cur_str;//前一个编码的字符和现在的字符
    size_t byte_count=FILE_COUNT_LEN+file_count*HEAD_SIZE;//文件头部所占字节数
    size_t count=0;//计数写了多少个字节了
    while ((cur_code = GetCodeWord(bf_in, cur_code_len)) != EOF) {
        //如果当前读取的编码是当前编码长度的最大表示（全1），则表示下一个读取的编码长度需要加一
        if ((cur_code == CURRENT_MAX_CODES(cur_code_len)) && (cur_code_len < MAX_CODE_LEN)) {
            cur_code_len++;
            cur_code = GetCodeWord(bf_in, cur_code_len);
        }
        if (cur_code >= next_code) {/*不在字典里面*/
            cur_str = pre_str + pre_str[0];/*这种情况用pre_str+pre_str[0]编码即可*/
            put_chars(bf_out, cur_str);
            /////////////////////////
            count+=cur_str.size();
            if(count==2){//文件长度已经写入完毕
                fflush(fp_tmp_out);
                data_offset= ftell(fp_tmp_out);//保留文件指针位置
                fseek(fp_tmp_out,0,SEEK_SET);//指针移动到文件头部
                file_count=GetCodeWord(bf_out, 16);
                byte_count=FILE_COUNT_LEN+file_count*HEAD_SIZE;//更新文件头部所占字节数
                fseek(fp_tmp_out,data_offset,SEEK_SET);//指针移动到数据部分
            }
            if(count>=byte_count){//头部信息提取完毕
                fflush(fp_tmp_out);
                break;//返回
            }
            ///////////////////////
            if (next_code < MAX_CODES) {//字典没有满
                dict.insert({next_code, cur_str});
                next_code++;
            }
        } else {//在字典中
            cur_str = dict[cur_code];
            put_chars(bf_out, cur_str);
            /////////////////////////
            count+=cur_str.size();
            if(count==2){//文件长度已经写入完毕
                fflush(fp_tmp_out);
                data_offset= ftell(fp_tmp_out);//保留文件指针位置
                fseek(fp_tmp_out,0,SEEK_SET);//指针移动到文件头部
                file_count=GetCodeWord(bf_out, 16);
                byte_count=FILE_COUNT_LEN+file_count*HEAD_SIZE;//更新文件头部所占字节数
                fseek(fp_tmp_out,data_offset,SEEK_SET);//指针移动到数据部分
            }
            if(count>=byte_count){//头部信息提取完毕
                fflush(fp_tmp_out);
                break;//返回
            }
            ///////////////////////
            if (next_code < MAX_CODES) {
                dict.insert({next_code, pre_str + cur_str[0]});
                next_code++;
            }
        }
        pre_code = cur_code;
        pre_str = cur_str;
    }
    BitFileClose(bf_in);
}