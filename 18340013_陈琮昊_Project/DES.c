#include <stdio.h>

char Sec_Key[8] = "uziyyds!";          //密钥
char Plain[100] = "WONGSANZIT";        //明文
char ans[100];                         //存放结果

int M[64];                             //存放明文对应的二进制串
int M_IP[64];                          //IP置换后的结果
int K[64];                             //存放密钥对应的二进制串
int ReducedK[56];                      //56位密钥
int Cipher[64];                        //密文
int L[17][32], R[17][32];              //L,R(64位)
int C[17][28], D[17][28];              //C,D(56位)
int SubKey[17][48];                    //子密钥

int real_len;                          //明文实际长度
int len;                               //明文填充后的长度

//IP置换规则表
const int IP[64] = {
        58,50,42,34,26,18,10,2,
        60,52,44,36,28,20,12,4,
        62,54,46,38,30,22,14,6,
        64,56,48,40,32,24,16,8,
        57,49,41,33,25,17,9,1,
        59,51,43,35,27,19,11,3,
        61,53,45,37,29,21,13,5,
        63,55,47,39,31,23,15,7
};

//64->56位密钥表
const int PC_KEY[56] = {
        57,49,41,33,25,17,9,
        1,58,50,42,34,26,18,
        10,2,59,51,43,35,27,
        19,11,3,60,52,44,36,
        63,55,47,39,31,23,15,
        7,62,54,46,38,30,22,
        14,6,61,53,45,37,29,
        21,13,5,28,20,12,4
};

//56->48位密钥表
const int PC_SUBKEY[48] = {
        14,17,11,24,1,5,
        3,28,15,6,21,10,
        23,19,12,4,26,8,
        16,7,27,20,13,2,
        41,52,31,37,47,55,
        30,40,51,45,33,48,
        44,49,39,56,34,53,
        46,42,50,36,29,32
};

//E位选择表
const int E[48] = {
		32,1,2,3,4,5,4,5,6,7,8,9,
        8,9,10,11,12,13,12,13,14,15,16,17,
        16,17,18,19,20,21,20,21,22,23,24,25,
        24,25,26,27,28,29,28,29,30,31,32,1
};

//S盒功能表
const int S[8][4][16] = {
		14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,
        0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
        4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,
        15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13,
        
        15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,
        3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
        0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,
        13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9,
        
        10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,
        13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
        13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,
        1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12,
        
        7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,
        13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
        10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,
        3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14,
        
        2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,
        14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
        4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,
        11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3,
        
        12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,
        10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
        9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,
        4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13,
        
        4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,
        13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
        1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,
        6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12,
        
        13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,
        1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
        7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,
        2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11
};

//P盒置换表
const int P[32] = {
		16,7,20,21,
		29,12,28,17,
		1,15,23,26,
		5,18,31,10,
		2,8,24,14,
		32,27,3,9,
		19,13,30,6,
		22,11,4,25
};

//IP逆置换表
const int IPinv[64] = {
	40,8,48,16,56,24,64,32,
    39,7,47,15,55,23,63,31,
    38,6,46,14,54,22,62,30,
    37,5,45,13,53,21,61,29,
    36,4,44,12,52,20,60,28,
    35,3,43,11,51,19,59,27,
    34,2,42,10,50,18,58,26,
    33,1,41,9,49,17,57,25
};

//函数声明，每个函数代表的意义已注释在每个函数定义附近
void ShowKey();
void DES(int mode);
void PlainProcess(char* s);
void SecKeyProcess();
void Reduced_CD();
void fill(char* s);
void IPchange();
void Cir_LeftShift(int a[][28], int k);
void getSubKey(int k);
void XOR(int *result, int *p1, int *p2, int len);
void diff(int *R, int k, int mode);
void Schange(int *R, int *Eresult);
void Pchange(int *R);
void IPinvChange(int *Cipher, int *R, int *L);

//主函数
int main(){
    ShowKey();
    printf("\nMessage:%s\n", Plain);
    DES(1);
    printf("Encoding:%s\n", ans);
    DES(2);
    printf("Decoding:%s\n", ans);
}

//获得子密钥并打印
void ShowKey(){
    SecKeyProcess();
    Reduced_CD();
    // 这一部分注释的内容是打印子密钥K1-K16
    // for(int i = 1; i < 17; i++){
    // 	printf("K%d:", i);
    // 	if(i < 10){
    //     	printf(" ");
    //     }
    // 	for(int j = 0; j < 48; j++){
    // 		printf("%d", SubKey[i][j]);
    // 		if((j+1)%4 == 0){
    //             printf(" ");
    //         }
    // 	}
    // 	printf("\n");
    // }
}

//核心部分，mode=1代表加密，mode=2代表解密
void DES(int mode){	
    if(mode == 1){ 
        fill(Plain);	                              //填充至8的整数倍 
        int groups = len/8;                            //按64位分组
        for(int k = 0; k < groups; k++){
            PlainProcess(Plain+8*k);	              //将明文M转化为二进制串 
            IPchange();                               //首先进行IP置换
			for(int i = 1; i < 17; i++){
				int temp[32];
				for(int j = 0; j < 32; j++){	
					L[i][j] = R[i-1][j];              //L[i]=R[i-1] 
					temp[j] = R[i-1][j];
				}				
				diff(temp, i, mode);                  //加密和解密的唯一区别就在这一步，详见diff函数定义
				XOR(R[i], L[i-1], temp, 32);	
			}			
			IPinvChange(Cipher, R[16], L[16]);        //逆置换得到密文
			// 这一部分注释的内容是密文，不过还是二进制串的形式
			/*for(int i = 0; i < 64; i++){
				printf("%d", Cipher[i]);
				if((i+1)%8 == 0)	printf("\n");
			}
			printf("\n");*/
			
			for(int i = 0; i < 8; i++){		          
				int ascii = 0;
				for(int j = 7; j >= 0; j--){
					ascii *= 2;
					ascii += Cipher[8 * i + j];
				}
				//printf("%d ", ascii);
				ans[8 * k + i] = ascii;
			}
        }
        ans[len] = '\0';                            //将密文的ASCII转为字符串并存入ans      
        //printf("%s\n", ans);
    }
    //解密过程绝大部分和加密过程类似
    else if(mode == 2){
    	int groups = len/8;    	
    	for(int k = 0; k < groups; k++){
            PlainProcess(ans+8*k);
            IPchange();			
			for(int i = 1; i < 17; i++){
				int temp[32];
				for(int j = 0; j < 32; j++){
					L[i][j] = R[i-1][j];
					temp[j] = R[i-1][j];
				}				
				diff(temp, i, mode);
				XOR(R[i], L[i-1], temp, 32);
			}			
			IPinvChange(Cipher, R[16], L[16]);
			// 这一部分是密文解密后的结果，为二进制串形式
			// for(int i = 0; i < 64; i++){
			// 	printf("%d", Cipher[i]);
			// 	if((i+1)%8 == 0)	printf("\n");
			// }
			// printf("\n");
			
			/* 注意：在加密的时候进行了填充，但在这里解密时不需要把填充的部分输出；
            只需讨论是否进行到最后一个分组，因为只有最后一组内的字符有可能包含填充内容。 */
			int lastgroup = (k == groups-1 ? real_len%8 : 8);
			// 如果是最后一组，则要返回原字符串最后一组对应的字节数；如果不是则返回8（每组字节数）
			for(int i = 0; i < lastgroup; i++){
				int ascii = 0;
				for(int j = 7; j >= 0; j--){
					ascii *= 2;
					ascii += Cipher[8 * i + j];
				}
				//printf("%d ", ascii);
				ans[8 * k + i] = ascii;
			}
        }
        ans[real_len] = '\0';                        //将解密后的结果由ASCII转为字符串并存入ans  
        //printf("%s\n", ans);
    }
}

//填充至长度为8的倍数
void fill(char* s){
    len = 0;
    while(s[len] != '\0'){
        len++;
    }
	real_len = len;
    int fill = 8-(len%8);
	for(int i = 0; i < fill; i++){
		s[len+i] = fill;
	}
	len += fill;
	s[len] = '\0';
    // printf("%d",len);
}

//处理明文（按64位分组）
void PlainProcess(char* s){
    for(int i = 0; i < 64; i++){
        M[i] = (s[i/8] >> (i%8)) & 1;
        // printf("%d", M[i]);
        // if((i+1)%8 == 0)	printf("\n");
    }
    printf("\n");
}

//密钥64->56
void SecKeyProcess(){
    //处理密钥（按64位分组）
    for(int i = 0; i < 64; i++){
        K[i] = (Sec_Key[i/8] >> (i%8)) & 1;
    }
    for(int i = 0; i < 56; i++){
        ReducedK[i] = K[PC_KEY[i]-1];
    }
}

//56位密钥获得C[0],D[0]
void Reduced_CD(){
    for(int i = 0; i < 28; i++){
        C[0][i] = ReducedK[i];
        D[0][i] = ReducedK[i+28];
    }
    for(int i = 1; i < 17; i++){
        Cir_LeftShift(C, i);
        Cir_LeftShift(D, i);
        getSubKey(i);
    }
}

//循环左移
void Cir_LeftShift(int a[][28], int k){
    if(k == 1 || k == 2 || k == 9 || k == 16){
        a[k][27] = a[k-1][0];
        for(int i = 0; i < 27; i++){
            a[k][i] = a[k-1][i+1];
        }
    }
    else{
        a[k][26] = a[k-1][0];
        a[k][27] = a[k-1][1];
        for(int i = 0; i < 26; i++){
            a[k][i] = a[k-1][i+2];
        }
    }
}

//生成子密钥K1-K16
void getSubKey(int k){
    int i;
    for(i = 0; i < 24; i++){
        SubKey[k][i] = C[k][PC_SUBKEY[i]-1];
    }
    for( ; i < 48; i++){
        SubKey[k][i] = D[k][PC_SUBKEY[i]-1-28];
    }
}

//IP置换：将64位数据重新组合，并分为L[0],R[0]两部分
void IPchange(){
    for(int i = 0; i < 64; i++){
        M_IP[i] = M[IP[i]-1];
    }
    for(int i = 0; i < 32; i++){
        L[0][i] = M_IP[i];
        R[0][i] = M_IP[i+32];
    }
}

void XOR(int *result, int *p1, int *p2, int len){
	for(int i = 0; i < len; i++){
		result[i] = p1[i]^p2[i];
	}
}

//E扩展置换
//加密和解密在这一步有所不同,一个是K1-K16,另一个是K16-K1
void diff(int *R, int k, int mode){
	int Eresult[48];	
	for(int i = 0; i < 48; i++){
		Eresult[i] = R[E[i]-1];
	}	
	if(mode == 1){
		XOR(Eresult, Eresult, SubKey[k], 48);
	}
	else if(mode == 2){
		XOR(Eresult, Eresult, SubKey[17-k], 48);
	}	
	Schange(R, Eresult);	
	Pchange(R);
}

//S盒代替，得到8个4位分组结果
void Schange(int *R, int *Eresult){
	for(int i = 0; i < 8; i++){
		int num1 = Eresult[0+6*i]*2 + Eresult[5+6*i];
		int num2 = Eresult[1+6*i]*8 + Eresult[2+6*i]*4 + Eresult[3+6*i]*2 + Eresult[4+6*i];
		int SNum = S[i][num1][num2];
		for(int j = 0; i < 4; i++){
			R[4*i+j] = SNum%2;
			SNum /= 2;
		}
	}
}

//P盒置换
void Pchange(int *R){
	int result[32];	
	for(int i = 0; i < 32; i++){
		result[i] = R[i];
	}	
	for(int i = 0; i < 32; i++){
		R[i] = result[P[i]-1];
	}
}

//IP逆置换
void IPinvChange(int *Cipher, int *R, int *L){
	for(int i = 0; i < 64; i++){
		int index = IPinv[i]-1;		
		if(index < 32){
			Cipher[i] = R[index];
		}
		else{
			Cipher[i] = L[index-32];
		}
	}
}