#include <iostream>
#include <cstdlib>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <curses.h>
#include <ctime>
#include <string>
#include <cassert>

#define MAX (256+1)

class Key{
	private:
		std::string subkey[16];
		std::string key_bin;
		void rm_parity(std::string&);
		std::pair <std::string, std::string> divide_to_28(std::string);
		void leftshift(std::string&, int);
		std::string tobinary_64bit(std::string);
		std::string tobinary_8bit(int);
		std::string key_production(std::pair <std::string, std::string>&);
		void serial_key_production(std::pair <std::string, std::string>);
	public:
		std::string key;
		Key(std::string&);
		std::string get_subkey(int);
		void produce_subkey();
};

class Encrypt{
	private:
		std::string ciphertext;
		std::string plain_64bit;
		std::pair <std::string, std::string> plain_32_32bit;
		std::string cipher_64bit;
		std::pair <std::string, std::string> cipher_32_32bit;
		char op_xor(char, char);
		void initial_per(std::string&);
		std::pair <std::string, std::string> divide_to_32(std::string);
		std::string f(std::string, std::string&);
		void Expand(std::string&);
		std::string tobinary_8bit(int);
		std::string tobinary_64bit(const std::string&);
		std::string tobinary_4bit(int);
		void XOR(std::string&, std::string&, std::string);
		void final_per(std::string&);
	public:
		std::string plaintext;
		Encrypt(std::string&);
		~Encrypt(){};
		void encrypt(Key);
		std::string decrypt(Key);
		std::string get_ciphertext();
		std::string get_cipher_64bit();
		std::string toascii(std::string);
		void set_cipher(std::string);
};

class BigInteger{
public:
    BigInteger();
    BigInteger(const int&);
    BigInteger(const std::string&);
    BigInteger(const BigInteger&);
    ~BigInteger();

    bool operator<(const BigInteger&) const;
    bool operator>(const BigInteger&) const;
    bool operator==(const BigInteger&) const;
    bool operator!=(const BigInteger&) const;
    bool operator>=(const BigInteger&) const;
    bool operator<=(const BigInteger&) const;

    bool operator<(const int&) const;
    bool operator>(const int&) const;
    bool operator==(const int&) const;
    bool operator!=(const int&) const;
    bool operator>=(const int&) const;
    bool operator<=(const int&) const;

    const BigInteger operator+(const BigInteger&) const;
    const BigInteger operator-(const BigInteger&) const;
    const BigInteger operator*(const BigInteger&) const;
    const BigInteger operator/(const BigInteger&) const;
    const BigInteger operator%(const BigInteger&) const;

    BigInteger& operator-=(const BigInteger&);
    BigInteger& operator+=(const BigInteger&);
    BigInteger& operator*=(const BigInteger&);
    BigInteger& operator/=(const BigInteger&);
    BigInteger& operator%=(const BigInteger&);

    BigInteger& operator=(const BigInteger&);
    BigInteger& operator=(const int&);

    BigInteger operator+(int);
    BigInteger operator*(int);

    BigInteger& operator*=(int);
    BigInteger& operator+=(int);
    BigInteger& operator++(int);
    BigInteger& operator/=(int);

    int getlength() const;
    bool iseven() const;
    bool isodd() const;
    bool iszero() const;

    friend std::ostream& operator<<(std::ostream&, const BigInteger&);
private:
    int *digit;
};

const static int shiftleft[16] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

const static int cka[56] = {56, 48, 40, 32, 24, 16, 8 ,
							0 , 57, 49, 41, 33, 25, 17,
							9 , 1 , 58, 50, 42, 34, 26,
							18, 10, 2 , 59, 51, 43, 35,
							62, 54, 46, 38, 30, 22, 14,
							6 , 61, 53, 45, 38, 29, 21,
							13, 5 , 60, 52, 44, 36, 28,
							20, 12, 4 , 27, 19, 11, 3 };

const static int ckb[48] = {13, 16, 10, 23, 0 , 4 ,
							2 , 27, 14, 5 ,20 , 9 ,
							22, 18, 11, 3 ,25 , 7 ,
							15, 6 , 26, 19, 12, 1 ,
							40, 51, 30, 36, 46, 54,
							29, 39, 50, 44, 32, 47,
							43, 48, 38, 55, 33, 52,
							45, 41, 49, 35, 28, 31};

Key::Key(std::string& s)
{
	key = s;
}

void Key::rm_parity(std::string& s)
{
	std::string temp;
	for(int i = 0; i < 56; i++)
		temp.push_back(s[cka[i]]);
	s.clear();
	s = temp;
}

std::pair <std::string, std::string> Key::divide_to_28(std::string s)
{
	rm_parity(s);
	std::string L(s.begin(), s.begin()+28), R(s.begin()+28, s.begin()+56);
	return make_pair(L, R);
}

void Key::leftshift(std::string& s, int turn)
{
	std::string temp;
	for(int i = 0; i < turn; i++){
		temp.push_back(s[0]);
		s.erase(s.begin());
	}
	s += temp;
}

std::string Key::tobinary_8bit(int x)
{
	std::string result(8, '0');
	int sum = 0;
	for(int i = 6; i >= 0; i--){
		result[i] = (x % 2) + '0';
		x /= 2;
		if((result[i] - '0') % 2 == 0)
			sum++;
	}

	result[7] = (sum % 2 == 0)? '1': '0';
	return result;
}

std::string Key::tobinary_64bit(std::string s)
{
	std::string result;
	for(int i = 0; i < 8; i++)
		result += (tobinary_8bit((int)(s[i])));
	for(int i = s.size(); i < 8; i++)
		result += "00000000";
	return result;
}

std::string Key::key_production(std::pair <std::string, std::string>& s)
{
	std::string temp(s.first+s.second), result;
	for(int i = 0; i < 48; i++)
		result.push_back(temp[ckb[i]]);
	return result;
}

void Key::serial_key_production(std::pair <std::string, std::string> s)
{
	for(int i = 0; i < 16; i++){
		leftshift(s.first, shiftleft[i]);
		leftshift(s.second, shiftleft[i]);
		subkey[i] = key_production(s);
	}
}

std::string Key::get_subkey(int i)
{
	return subkey[i];
}

void Key::produce_subkey()
{
	key_bin = tobinary_64bit(key);
	std::pair <std::string, std::string> initial28 = divide_to_28(key_bin);
	serial_key_production(initial28);
}

const static int ip[64] = { 57, 49, 41, 33, 25, 17, 9 , 1 ,
  							59, 51, 43, 35, 27, 19, 11, 3 ,
  							61, 53, 45, 37, 29, 21, 13, 5 ,
  							63, 55, 47, 39, 31, 23, 15, 7 ,
  							56, 48, 40, 32, 24, 16, 8 , 0 ,
  							58, 50, 42, 34, 26, 18, 10, 2 ,
  							60, 52, 44, 36, 28, 20, 12, 4 ,
  							62, 54, 46, 38, 30, 22, 14, 6 };

const static int ExpandChange[48] = {31, 0 , 1 , 2 , 3 , 4 ,
									 3 , 4 , 5 , 6 , 7 , 8 ,
									 7 , 8 , 9 , 10, 11, 12,
									 11, 12, 13, 14, 15, 16,
									 15, 16, 17, 18, 19, 20,
									 19, 20, 21, 22, 23, 24,
									 23, 24, 25, 26, 27, 28,
									 27, 28, 29, 30, 31, 0 };

const static int PressChange[32] = {15, 6, 19, 20,
									28, 11, 27, 16,
									0, 14, 22, 25,
									4, 17, 30, 9,
									1, 7, 23, 13,
									31, 26, 2, 8,
									18, 13, 30, 6,
									21, 10, 3, 24};

const static int fp[64] = {39, 7, 47, 15, 55, 23, 63, 31,
						   38, 6, 46, 14, 54, 22, 62, 30,
						   37, 5, 45, 13, 53, 21, 61, 29,
						   36, 4, 44, 12, 52, 20, 60, 28,
						   35, 3, 43, 11, 51, 19, 59, 27,
						   34, 2, 42, 10, 50, 18, 58, 26,
						   33, 1, 41, 9 , 49, 17, 57, 25,
						   32, 0, 40, 8 , 48, 16, 56, 24};

const static int sb[8][4][16] = {{{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
							   	  {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
							   	  {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
							   	  {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}},
							   	 {{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
							   	  {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
							      {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
							      {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}},
								 {{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
							      {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
							      {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
							      {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}},
							     {{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
							      {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
							      {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
							      {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}},
							     {{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
							   	  {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
							      {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
							      {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}},
							     {{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
							   	  {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
							      {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
							      {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}},
							     {{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
							      {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
							      {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
							      {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}},
							     {{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
							   	  {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
							      {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
							      {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}}};

const static int primesmall[] = {11, 17, 29, 37, 41, 59, 67, 71, 79, 97, 101, 107, 127, 137, 149, 163, 179, 191, 197, 223, 227, 239, 251, 269, 277, 281, 307, 311, 331, 347, 367, 379, 397, 419, 431, 439, 457, 461, 479, 487, 499, 521, 541, 557, 569, 587, 599, 613, 617, 631, 641, 659, 673, 701, 719, 727, 739, 751, 757, 769, 787, 809, 821, 827, 853, 857, 877, 881, 907, 929, 937, 967, 991, 1009, 1019, 1031, 1049, 1061, 1087, 1091, 1117, 1151, 1163, 1181, 1213, 1229, 1249, 1277, 1289, 1297, 1301, 1319, 1361, 1399, 1423, 1427, 1447, 1451, 1471, 1481, 1487, 1523, 1543, 1549, 1567, 1579, 1597, 1607, 1619, 1657, 1663, 1667, 1693, 1697, 1721, 1733, 1741, 1777, 1783, 1787, 1801, 1823, 1847, 1861, 1867, 1871, 1877, 1901, 1931, 1949, 1973, 1987, 1993, 1997, 2011, 2027, 2053, 2063, 2081, 2087, 2111, 2129, 2137, 2141, 2153, 2203, 2237, 2267, 2281, 2293, 2309, 2333, 2339, 2347, 2371, 2377, 2381, 2389, 2411, 2437, 2459, 2467, 2473, 2503, 2521, 2531, 2539, 2549, 2579, 2591, 2609, 2617, 2647, 2657, 2671, 2683, 2687, 2707, 2711, 2729, 2741, 2749, 2767, 2789, 2797, 2801, 2819, 2833, 2851, 2857, 2879, 2897, 2953, 2969, 2999, 3011, 3019, 3037, 3061, 3079, 3109, 3119, 3163, 3167, 3181, 3187, 3203, 3217, 3251, 3257, 3299, 3319, 3329, 3343, 3359, 3371, 3389, 3407, 3433, 3449, 3457, 3461, 3467, 3491, 3511, 3527, 3539, 3557, 3571, 3581, 3607, 3613, 3631, 3659, 3671, 3691, 3697, 3719, 3727, 3761, 3767, 3793, 3821, 3847, 3851, 3877, 3907, 3917, 3929, 3943, 3989, 4001, 4019, 4049, 4073, 4091, 4127, 4153, 4157, 4201, 4211, 4217, 4229, 4241, 4253, 4259, 4271, 4283, 4327, 4337, 4349, 4357, 4391, 4421, 4441, 4447, 4481, 4507, 4513, 4517, 4547, 4561, 4583, 4591, 4621, 4637, 4649, 4673, 4721, 4729, 4751, 4783, 4787, 4799, 4813, 4861, 4871, 4903, 4931, 4951, 4967, 4987, 4999, 5009, 5021, 5039, 5051, 5077, 5099, 5147, 5167, 5189, 5227, 5231, 5261, 5273, 5279, 5297, 5323, 5347, 5381, 5407, 5413, 5417, 5431, 5437, 5441, 5471, 5477, 5501, 5519, 5527, 5557, 5569, 5623, 5639, 5647, 5651, 5657, 5683, 5689, 5711, 5737, 5741, 5779, 5801, 5821, 5839, 5849, 5857, 5867, 5879, 5897, 5923, 5981, 6007, 6029, 6037, 6043, 6067, 6089, 6113, 6131, 6143, 6163, 6197, 6211, 6217, 6247, 6257, 6269, 6299, 6311, 6337, 6353, 6359, 6389, 6421, 6449, 6469, 6521, 6547, 6551, 6563, 6569, 6577, 6599, 6637, 6653, 6659, 6673, 6689, 6701, 6733, 6761, 6779, 6791, 6823, 6827, 6857, 6869, 6899, 6907, 6947, 6959, 6967, 6991, 6997, 7013, 7039, 7057, 7069, 7103, 7121, 7127, 7151, 7177, 7187, 7207, 7211, 7229, 7237, 7243, 7283, 7297, 7307, 7321, 7331, 7349, 7393, 7411, 7451, 7457, 7477, 7487, 7499, 7517, 7537, 7547, 7559, 7573, 7589, 7603, 7639, 7669, 7681, 7687, 7699, 7717, 7723, 7741, 7753, 7757, 7789, 7817, 7867, 7873, 7877, 7901, 7919, 7927, 7933, 7949, 7993, 8009, 8039, 8053, 8081, 8087, 8111, 8147, 8161, 8167, 8209, 8219, 8231, 8263, 8269, 8287, 8291, 8311, 8353, 8363, 8387, 8419, 8429, 8443, 8461, 8501, 8513, 8521, 8537, 8563, 8573, 8597, 8623, 8627, 8641, 8663, 8677, 8689, 8707, 8731, 8737, 8779, 8803, 8819, 8831, 8837, 8861, 8887, 8923, 8929, 8963, 8969, 8999, 9007, 9011, 9029, 9041, 9059, 9091, 9103, 9127, 9133, 9151, 9157, 9173, 9181, 9199, 9221, 9239, 9277, 9281, 9311, 9319, 9337, 9341, 9371, 9391, 9413, 9419, 9431, 9437, 9461, 9491, 9511, 9533, 9547, 9587, 9601, 9613, 9619, 9629, 9643, 9677, 9689, 9719, 9733, 9739, 9767, 9781, 9787, 9803, 9811, 9829, 9851, 9857, 9883, 9901, 9923, 9929, 9941, 9967, 10007, 10037, 10061, 10067, 10091, 10099, 10133, 10139, 10151, 10159, 10177, 10211, 10243, 10267, 10271, 10289, 10301, 10313, 10331, 10357, 10391, 10427, 10453, 10457, 10477, 10499, 397597169};
const static std::string primebig[] = {"74687", "322193", "5051341", "11938853", "245333213", "397597169", "130272314657", "1273135176871"};

Encrypt::Encrypt(std::string& s)
{
	plaintext = s;
	plain_64bit = tobinary_64bit(plaintext);
	plain_32_32bit = divide_to_32(plain_64bit);
}

char Encrypt::op_xor(char x, char y)
{
	if(x == y)
		return '0';
	else return '1';
}

void Encrypt::initial_per(std::string& s)
{
	std::string result;
	for(int i = 0; i < 64; i++)
		result.push_back(s[ip[i]]);
	s = result;
}

std::pair <std::string, std::string> Encrypt::divide_to_32(std::string s)
{
	initial_per(s);
	std::string L(s.begin(), s.begin()+32), R(s.begin()+32, s.begin()+64);
	return make_pair(L, R);
}

std::string Encrypt::f(std::string R, std::string& k)
{
	std::string temp, result_t, result;
	Expand(R);
	for(int i = 0; i < 48; i++)
		temp.push_back(op_xor(R[i], k[i]));
	for(int i = 0; i < 8; i++){
		std::string s1;
		int row = (temp[i*6]-'0')*2 + (temp[i*6+5]-'0');
		int col = (temp[i*6+1]-'0')*8 + (temp[i*6+2]-'0')*4 + (temp[i*6+3]-'0')*2 + (temp[i*6+4]-'0');
		result_t += tobinary_4bit(sb[i][row][col]);
	}
	for(int i = 0; i < 32; i++)
		result.push_back(result_t[PressChange[i]]);
	return result;
}

void Encrypt::Expand(std::string& s)
{
	std::string temp;
	for(int i = 0; i < 48; i++)
		temp.push_back(s[ExpandChange[i]]);
	s.clear();
	s = temp;
}

std::string Encrypt::tobinary_8bit(int x)
{
	std::string result(8, '0');
	for(int i = 7; i >= 0; i--){
		result[i] = (x % 2) + '0';
		x /= 2;
	}
	return result;
}

std::string Encrypt::tobinary_64bit(const std::string& s){
	std::string result;
	for(int i = 0; i < s.size(); i++)
		result += (tobinary_8bit((int)(s[i])));
	for(int i = s.size(); i < 8; i++)
		result += "00000000";
	return result;
}

std::string Encrypt::tobinary_4bit(int x)
{
	std::string result(4, '0');
	for(int i = 3; i >= 0; i--){
		result[i] = (x % 2) + '0';
		x /= 2;
	}
	return result;
}

void Encrypt::XOR(std::string& L, std::string& R, std::string k)
{
	std::string temp, fe(f(R, k));
	for(int i = 0; i < 32; i++)
		temp.push_back(op_xor(L[i], fe[i]));
	L.clear();
	L = R;
	R.clear();
	R = temp;
}

void Encrypt::final_per(std::string& s)
{
	std::string result;
	for(int i = 0; i < 64; i++)
		result.push_back(s[fp[i]]);
	s.clear();
	s = result;
}

std::string Encrypt::toascii(std::string bin)
{
	std::string ascii;
	int sum = 0;
	for(int i = 0; i < 64; i++){
		sum = sum*2 + (bin[i] - '0');
		if(i % 8 == 7){
			ascii.push_back(char(sum));
			sum = 0;
		}
	}
	return ascii;
}

void Encrypt::encrypt(Key k)
{
	std::string L(plain_32_32bit.first), R(plain_32_32bit.second);
	for(int i = 0; i < 16; i++)
		XOR(L, R, k.get_subkey(i));
	std::string result(R);
	result += L;
	final_per(result);
	cipher_64bit = result;
	ciphertext = toascii(cipher_64bit);
	cipher_32_32bit = divide_to_32(cipher_64bit);
}

std::string Encrypt::decrypt(Key k)
{
	std::string L(cipher_32_32bit.second), R(cipher_32_32bit.first);
	for(int i = 15; i >= 0; i--)
		XOR(R, L, k.get_subkey(i));
	std::string result(L);
	result += R;
	final_per(result);
	return toascii(result);
}

void Encrypt::set_cipher(std::string in)
{
    cipher_32_32bit = divide_to_32(in);
}

std::string Encrypt::get_ciphertext()
{
	return ciphertext;
}

std::string Encrypt::get_cipher_64bit()
{
    return cipher_64bit;
}
///////////* constructor *////////////

BigInteger::BigInteger(){

	digit = new int[MAX];

	for(int i = 0; i < MAX; i++){
		digit[i] = 0;
	}

}

BigInteger::BigInteger(const int& x){

	digit = new int[MAX];
	int xp = x;

	for(int i = 0; i < MAX; i++){
		digit[i] = xp % 10;
		xp /= 10;
	}

}

BigInteger::BigInteger(const std::string& s){

	digit = new int[MAX];

	for(int i = s.size() - 1, j = 0; i >= 0; i--, j++){
		digit[j] = s[i] - '0';
	}
	for(int i = s.size(); i < MAX; i++){
		digit[i] = 0;
	}

}

BigInteger::BigInteger(const BigInteger& bint){

	digit = new int[MAX];

	for(int i = 0; i < MAX; i++){
		digit[i] = bint.digit[i];
	}

}

///////////* constructor *////////////

///////////* destructor *////////////

BigInteger::~BigInteger(){
	delete [] digit;
}

///////////* destructor *////////////

///////////* operation *////////////

const BigInteger BigInteger::operator-(const BigInteger& bint) const{
	BigInteger out;

	for(int i = 0; i < MAX; i++){
		out.digit[i] = digit[i] - bint.digit[i];
	}

	for(int i = 0; i < MAX; i++)
		if(out.digit[i] < 0){
			out.digit[i + 1]--;
			out.digit[i] += 10;
		}

	return out;
}

const BigInteger BigInteger::operator/(const BigInteger& bint) const
{
	BigInteger out, copythis(*this), copyin(bint);
	int move = copythis.getlength() - copyin.getlength();

	for(int i = 0; i < move; i++)
		copyin *= 10;

	for(int i = move; i >= 0; i--){
		while(copythis >= copyin){
			out.digit[i]++;
			copythis -= copyin;
		}
			copyin /= 10;
	}
	return out;
}

const BigInteger BigInteger::operator*(const BigInteger& bint) const
{
	BigInteger result;
	BigInteger out;
    BigInteger copy(*this);

	for(int i = MAX - 1; i >= 0; i--){
		result = copy * bint.digit[i];
		out = out * 10 + result;
	}

	return out;
}

const BigInteger BigInteger::operator+(const BigInteger& bint) const
{
	BigInteger out;

	for(int i = 0; i < MAX; i++){
		out.digit[i] = digit[i] + bint.digit[i];
	}

	for(int i = 0; i < MAX; i++)
		if(out.digit[i] > 9){
			out.digit[i + 1] ++;
			out.digit[i] -= 10;
		}

	return out;
}

const BigInteger BigInteger::operator%(const BigInteger& bint) const
{
	BigInteger out, copy(*this);

	out = (copy - (bint * (copy / bint)));

	return out;
}

BigInteger& BigInteger::operator+=(const BigInteger& bin)
{
	(*this) = (*this) + bin;
	return (*this);
}

BigInteger& BigInteger::operator-=(const BigInteger& bint)
{
	(*this) = (*this) - bint;
	return (*this);
}

BigInteger& BigInteger::operator*=(const BigInteger& bin)
{
	(*this) = (*this) * bin;
	return (*this);
}

BigInteger& BigInteger::operator/=(const BigInteger& bin)
{
	(*this) = (*this) / bin;
	return (*this);
}

BigInteger& BigInteger::operator%=(const BigInteger& bin)
{
	(*this) = (*this) % bin;
	return (*this);
}

BigInteger BigInteger::operator*(int x)
{
	int carryin = 0;
	int sum = 0;
	BigInteger out;

	for(int i = 0; i < MAX; i++){
		sum = digit[i] * x + carryin;
		out.digit[i] = sum % 10;
		carryin = sum / 10;
	}

	return out;
}

BigInteger BigInteger::operator+(int x)
{
	BigInteger out(*this);
	for(int i = 0; i < MAX && x != 0; i++){
		out.digit[i] += x % 10;
		x /= 10;
	}

	for(int i = 0; i < MAX; i++){
		if(out.digit[i] >= 10){
			out.digit[i] -= 10;
			out.digit[i+1]++;
		}
	}

	return out;
}

BigInteger& BigInteger::operator*=(int x)
{
	(*this) = (*this) * x;

	return (*this);
}

BigInteger& BigInteger::operator/=(int x)
{
	int rem = 0;
	int sum = 0;

	for(int i = MAX - 1; i >= 0; i--){
		sum = rem * 10 + digit[i];
		rem = sum % x;
		digit[i] = sum / x;
	}

	return (*this);
}

BigInteger& BigInteger::operator+=(int x)
{
	(*this) = (*this) + x;
	return (*this);
}

BigInteger& BigInteger::operator++(int)
{
	(*this) = (*this) + 1;
	return (*this);
}

///////////* operation *////////////

////////////* assign *////////////

BigInteger& BigInteger::operator=(const int& x)
{
	BigInteger bint(x);
	*this = bint;
	return (*this);
}

BigInteger& BigInteger::operator=(const BigInteger& bint)
{
	for(int i = 0; i < MAX; i++){
		digit[i] = bint.digit[i];
	}

	return (*this);
}

////////////* assign *////////////


///////////* comparison *////////////

bool BigInteger::operator==(const BigInteger& bint) const
{
	for(int i = 0; i < MAX; i++)
		if(digit[i] != bint.digit[i])
			return false;
	return true;
}

bool BigInteger::operator<(const BigInteger& bint) const{

	for(int i = MAX - 1; i >= 0; i--){
		if(digit[i] < bint.digit[i]){
			return true;
		}
		if(digit[i] > bint.digit[i]){
			return false;
		}
	}

	return false;
}

bool BigInteger::operator>(const BigInteger& bint) const{

	for(int i = MAX - 1; i >= 0; i--){
		if(digit[i] > bint.digit[i]){
			return true;
		}
		if(digit[i] < bint.digit[i]){
			return false;
		}
	}

	return false;
}

bool BigInteger::operator!=(const BigInteger& bint) const
{
	return !(*this == bint);
}

bool BigInteger::operator>=(const BigInteger& bint) const
{
	return ((*this) == bint) || ((*this) > bint);
}

bool BigInteger::operator<=(const BigInteger& bint) const
{
	return ((*this) == bint) || ((*this) < bint);
}

bool BigInteger::operator<(const int& x) const
{
	BigInteger bin(x);
	return (*this < bin);
}

bool BigInteger::operator>(const int& x) const
{
	BigInteger bin(x);
	return (*this > bin);
}

bool BigInteger::operator==(const int& x) const
{
	BigInteger bin(x);
	return (*this == bin);
}

bool BigInteger::operator!=(const int& x) const
{
	BigInteger bin(x);
	return (*this != bin);
}

bool BigInteger::operator<=(const int& x) const
{
	BigInteger bin(x);
	return (*this <= bin);
}

bool BigInteger::operator>=(const int& x) const
{
	BigInteger bin(x);
	return (*this >= bin);
}

///////////* comparison *////////////

///////////* standard out *////////////

std::ostream& operator<<(std::ostream& out, const BigInteger& bint)
{

	int length = bint.getlength();

	for(int i = length; i >= 0; i--)
		out << bint.digit[i];

	return out;
}

///////////* standard out *////////////

bool BigInteger::iszero() const
{
	for(int i = 0; i < MAX; i++){
		if(digit[i] != 0)
			return false;
	}
	return true;
}

bool BigInteger::iseven() const
{
	return (digit[0] % 2 == 0);
}

bool BigInteger::isodd() const
{
	return (digit[0] % 2 == 1);
}

int BigInteger::getlength() const
{
	int length = 0;
	for(int i = MAX - 1; i >= 0; i--)
		if(this->digit[i] != 0){
			length = i;
			break;
		}
	return length;
}

void swap(BigInteger& i, BigInteger& j)
{
	BigInteger temp(i);
	i = j;
	j = temp;
}

char tochar(BigInteger& bin)
{
    if(bin == 10)
        return '\n';
    for(int i = 32; i <= 126; i++)
        if(bin == i)
            return char(i);
}

BigInteger gcd(BigInteger i, BigInteger j)
{
	BigInteger temp;

	if(j > i)swap(i, j);

	while(j != 0){
		temp = j;
		j = i % j;
		i = temp;
	}
	return i;
}

void matrixmulti(BigInteger A[2][2], BigInteger B[2][2])
{
	BigInteger C[2][2];

	for(int i = 0; i < 2; i++)
		for(int j = 0; j < 2; j++)
			for(int k = 0; k < 2; k++)
				C[i][j] += A[i][k] * B[k][j];

	for(int i = 0; i < 2; i++)
		for(int j = 0; j < 2; j++)
			A[i][j] = C[i][j];
}

BigInteger inv(BigInteger i, BigInteger j)
{
	BigInteger temp, t1 = j;
	BigInteger matrix[2][2] = {{BigInteger(1), BigInteger(0)},
							   {BigInteger(0), BigInteger(1)}};
	BigInteger matrix_t[2][2] = {{BigInteger(1), BigInteger(1)},
								 {BigInteger(1), BigInteger(0)}};

	if(j > i) swap(i, j);
	while(j != 0){
		temp = j;
		matrix_t[0][0] = i / j;
		matrixmulti(matrix, matrix_t);
		j = i % j;
		i = temp;
	}
	//cout << matrix[0][0] << " " << matrix[0][1] << endl << matrix[1][0] << " " << matrix[1][1] << endl;
	return (matrix[0][0]*matrix[1][1] < matrix[0][1]*matrix[1][0])? matrix[0][1]: t1 - matrix[0][1];
}

BigInteger power(const BigInteger a, const BigInteger& k, const BigInteger& N)
{
	if(k == 0)
		return BigInteger(1);
	else if(k == 1)
		return a;

	BigInteger _k(k/2);
	bool remain = k.iseven();
	BigInteger a_k2(power(a, _k, N) % N);
	BigInteger a_k(a_k2*a_k2);

	if(!remain){
		a_k  = (a_k * a) % N;
		return a_k;
	}
	else return a_k;
}

using namespace std;
void drawmenu();
void menu();
void encode();
void drawencode();
void decode();
void encodeOption1(vector <int> &);
void encodeOption2(vector <int> &);
void encodeOption3(vector <int> &);
void decodeOption1(string &, bool &);
void decodeOption2(string &, bool &);
void decodeOption3(string &, bool &);

int main()
{
    initscr();
    resize_term(45,150);
    int maxX=150,maxY=45;
    nodelay(stdscr, TRUE);
    keypad(stdscr, TRUE);
    noecho();
    curs_set(1);
    move(30,69);
    menu();

    refresh();
}


void drawmenu()
{
    for(int i=45;i<=105;i++){
        mvaddch(10,i,'#');}
    for(int i=45;i<=105;i++){
        mvaddch(17,i,'#');}
    for(int i=10;i<18;i++){
        mvaddch(i,45,'#');}
    for(int i=10;i<18;i++){
        mvaddch(i,105,'#');}
    mvprintw(14,65,"Encryptor & Decryptor");
    mvprintw(16,58,"{Using z, x, up, and down to control}");
    mvprintw(20,44,"@ If open fail, please check the location and the name of the files!");
    mvprintw(22,44,"@ If format problem happens, please ckeck the form of letters in text_in.txt!");
    mvprintw(24,47,"(Remember the number of the letters in text_in is 1 to 400!)");
    mvprintw(26,44,"@ If decryption fail, check the key.txt. We only have Encode Option 1, ");
    mvprintw(28,46,"Encode Option 2, and Encode Option 3!");
    mvprintw(32,73,"encode");
    mvprintw(35,73,"decode");
    mvprintw(39,40,"## Always remember that you should put text_in.txt(sometimes also key.txt ");
    mvprintw(40,40,"    and code.txt) in the same file of this program before executing it! ##");

}

void menu()
{
    drawmenu();
    int key, mo=500;
    while (1){
        key =getch();
    if (key == KEY_UP)
        mo++;
    if (key == KEY_DOWN)
        mo--;
    if (mo%2 ==0){
            move(32,72);
            if(key=='z' || key=='Z')
            encode();
            }

    if (mo%2 ==1){
            move(35,72);
            if(key=='z' || key=='Z')
            decode();
            }
        }
}

void encode()
{
    bool ableEncode=1,openbool=1;
    int key=ERR , mo_encode = 399  ;
    drawencode();
    move (25,73);

    ifstream ifs("text_in.txt");
	string line;
    vector< int >record;
	if (ifs.is_open()){
		while(getline(ifs,line)){
            for (int i=0;i<line.length();i++)  {
                record.push_back(line[i]);
                    if (line[i]<32 || line[i]>126)
                        ableEncode = 0;
            }
            record.push_back(int('\n'));
        }

    if (record.size()>401 || record.size()==0)
        ableEncode=0;
      }

else
  openbool=0;//end 1st if

if(openbool==0){
        key = ERR;
        erase();
            mvprintw (24,51,"Open fail!  Press X to go back to menu");
        refresh();
        while (key!='x' && key!='X')
        {key=getch();}

            erase();
            drawmenu();
            return;
    }

else {

if (!ableEncode){
        key = ERR;
        erase();
        if (record.size()==0)
            mvprintw (24,51,"text_in is empty!  Press X to go back to menu");
        else
            mvprintw (24,51,"Format problem!  Press X to go back to menu");
        refresh();
        while (key!='x' && key!='X')
        {key=getch();}

            erase();
            drawmenu();
            return;
    }

else{
    while(1){
        key=getch();
        if (key==KEY_UP)
            mo_encode--;
        if (key==KEY_DOWN)
            mo_encode++;

        if (mo_encode%2 == 1){
            move(25,72);
            if (key=='z' || key=='Z'){
                encodeOption1(record);
                key = ERR;
                erase();
                mvprintw (24,51,"Encryption success!  Press X to go back to menu");
                refresh();
                while (key!='x' && key!='X')
                {key=getch();}

                erase();
                drawmenu();
                return;
            }
        }                                                                   //finish encode operation1

        if (mo_encode%2 == 0){
            move(30,72);
            if (key == 'z' || key == 'Z'){
                encodeOption2(record);
                key = ERR;
                erase();
                mvprintw (24, 51, "Encryption success!  Press X to go back to menu");
                refresh();
                while( key != 'x' && key != 'X')
                {key = getch();}

                erase();
                drawmenu();
                return;
                }
            }

        if (key=='x' || key=='X'){
            erase();
            drawmenu();
            return;  }

        }
    }
  }
    ifs.close();
}


void drawencode()
{
    erase();
    mvprintw(25,73,"encode option1");
    mvprintw(30,73,"encode option2");
    refresh();
}


void encodeOption1(vector <int> &record)
{
    ofstream ofs1("code.txt");
    ofstream ofs2("key.txt");
    string in, key_str;

    srand(time(NULL));
    for(int i = 0; i < 8; i++)
        key_str.push_back(rand() % 94 + 33);    //offer random key

    string temp;
    Key k(key_str);
    k.produce_subkey();
    int x;
    for(int i = 0; i < record.size(); i++){
        if(char(record[i]) != '\n')
            temp.push_back(char(record[i]));
        else{
            for(int j = 0; j < temp.size(); j++){
                in.push_back(temp[j]);
                if(j % 8 == 7){
                    Encrypt en(in);
                    en.encrypt(k);
                    ofs1 << en.get_cipher_64bit();
                    in.clear();
                }
            }
            if(!in.empty()){
                 Encrypt en(in);
                 en.encrypt(k);
                 ofs1 << en.get_cipher_64bit();
                 in.clear();
            }
            if(i != record.size())
                ofs1 << endl;
            temp.clear();
        }
    }
    ofs2 << "Encode Option 1\n" << key_str;
    ofs1.close();
    ofs2.close();
}

void encodeOption2(vector <int> &record){
    ofstream ofs1("code.txt");
    ofstream ofs2("key.txt");

    srand(time(NULL));
	int sizesmall = sizeof(primesmall)/sizeof(int);
	int sizebig = sizeof(primebig)/sizeof(string);
	int x, y;

	x = rand()%sizesmall;
	y = rand()%sizebig;

	BigInteger p(primesmall[x]), q(primebig[y]);
	BigInteger n(p*q), r((p-1)*(q-1)), e, d;

	for(BigInteger i = 2; i < r; i++)
		if(gcd(i, r) == 1){
			e = i;
            break;
        }

    d = inv(e, r);

    assert((e*d) % r == 1);

    BigInteger ib, cipher;
    for(int i = 0; i < record.size(); i++){
		ib = record[i];
		cipher = power(ib, e, n);
		ofs1 << cipher << " ";
    }

    ofs2 << "Encode Option 2\n" << '(' << n << ", " << d << ')' << endl;

    ofs1.close();
    ofs2.close();
}


void decode()//need to improved
{
    bool ableDecode=1,openbool=1;
    ifstream ifs1("key.txt");
    string line,getkey;
    string recordKey;
    int keyNumber;
	if (ifs1.is_open()){
            getline(ifs1,getkey);
		while(getline(ifs1,line)){
		    for (int i=0; i < line.size(); i++)
                recordKey.push_back(line[i]);
                         }

        if (recordKey.size()>400 || recordKey.size()==0 )
            ableDecode=0;
	}

    else
        openbool=0;//end 1st if else


if(openbool==0){
       int key = ERR;
        erase();
        mvprintw (24,51,"key.txt fails when opening!  Press X to go back to menu");
        refresh();
        while (key!='x' && key!='X')
        {key=getch();}

            erase();
            drawmenu();
            return;
    }

else {

    if (!ableDecode){
       int key = ERR;
        erase();
        if (recordKey.size()==0)
            mvprintw (24,51,"key.txt is short of something!  Press X to go back to menu");
        else
            mvprintw (24,51,"Format problem!  Press X to go back to menu");

        refresh();
        while (key!='x' && key!='X')
        {key=getch();}

            erase();
            drawmenu();
            return;
           }

    else{
            int key,keyNum=0;
            bool getDecode;
            if (getkey=="Encode Option 1")
                keyNum=1;
            if (getkey=="Encode Option 2")
                keyNum=2;
        switch(keyNum){
        case 1:

                decodeOption1(recordKey, getDecode);
                   key = ERR;
                    erase();
                    if (getDecode==true){
                        mvprintw (24,51,"Decryption success!  Press X to go back to menu");
                        refresh();
                            while (key!='x' && key!='X')
                            {key=getch();}
                    }
                    erase();
                    drawmenu();
                    return;
                    break;

        case 2:

                decodeOption2(recordKey, getDecode);
                    key = ERR;
                    erase();
                    if (getDecode==true){
                        mvprintw (24,51,"Decryption success!  Press X to go back to menu");
                        refresh();
                            while (key!='x' && key!='X')
                            {key=getch();}
                    }
                    erase();
                    drawmenu();
                    return;
                    break;

        default:
                key = ERR;
                erase();
                mvprintw (24,51,"Decryption fail!! Orz....  Press X to go back to menu");
                refresh();
                    while (key!='x' && key!='X')
                    {key=getch();}
                erase();
                drawmenu();
                return;
                break;
        }// finish switch
    }
  }

ifs1.close();
}

void decodeOption1(string &recordKey, bool &getDecode){
    ifstream ifs("code.txt");
    ofstream ofs("text_out.txt");
    bool openFail=false;
    getDecode=true;

    if ( recordKey.size() != 8 )
        getDecode = false;

    Key k(recordKey);
    k.produce_subkey();
    string line;
    vector <string> recordCode;
    int count = 0;

    if (ifs.is_open()){
            while (getline(ifs, line))
                recordCode.push_back(line);

                if (recordCode.size()==0)
                    getDecode=false;
            }
    else
    {openFail=true; getDecode=false;}
//************************************\\

if (openFail){
    int key = ERR;
    erase();
    mvprintw (24,51,"code.txt fails when opening!!  Press X to go back to menu");
    refresh();
    while (key!='x' && key!='X')
        {key=getch();}

    erase();
    drawmenu();
    return;
}

else {
    if (getDecode==false){
        int key = ERR;
            erase();
            mvprintw (24,51,"code.txt is short for something!  Press X to go back to menu");
            refresh();
            while (key!='x' && key!='X')
            {key=getch();}

            erase();
            drawmenu();
            return;
        }

    else{
            string s("0");
            Encrypt e(s);
            Key k(recordKey);
            k.produce_subkey();
            e.encrypt(k);
            for (int i = 0; i < recordCode.size(); i++){
                string temp;
                for(int j = 0; j < recordCode[i].size(); j++){
                    temp.push_back(recordCode[i][j]);
                    if(j % 64 == 63){
                        e.set_cipher(temp);
                        ofs << e.decrypt(k);
                        temp.clear();
                    }
                }
                if(i != recordCode.size())
                    ofs << endl;
            }
    }
}
    ifs.close();
    ofs.close();

}

void decodeOption2(string& recordKey, bool& getDecode){
    ifstream ifs("code.txt");
    ofstream ofs("text_out.txt");
    bool openFail=false;
    getDecode=true;
    vector <string> recordCode;
    string line;


    if (recordKey[0] != '(' || recordKey[recordKey.size()-1] != ')')
        getDecode = false;
//**********************************
    string token;
    recordKey.erase(recordKey.begin());
    recordKey.erase(recordKey.begin() + recordKey.size() - 1);
    if (recordKey.size() == 0)
        getDecode = false;

    stringstream ss;
    ss << recordKey;
    getline(ss, token, ',');
    //ss >> token;
    BigInteger n(token);
    ss >> token;
    BigInteger d(token);


//***********************************
    stringstream ssline;
    string str;
    if (ifs.is_open()){
        getline(ifs, line);
        ssline << line;
        while(ssline >> str)
            recordCode.push_back(str);

        if (recordCode.size()==0)
            getDecode=false;
       }
    else
        {openFail=true; getDecode=false;}
//********************************************\\

    if (openFail){
        int key = ERR;
        erase();
        mvprintw (24,51,"code.txt fails when opening!!  Press X to go back to menu");
        refresh();
        while (key!='x' && key!='X')
            {key=getch();}

        erase();
        drawmenu();
        return;
        }
    else{
        if (getDecode==false){
            int key = ERR;
            erase();
            mvprintw (24,51,"code.txt is short for something!  Press X to go back to menu");
            refresh();
                while (key!='x' && key!='X')
                {key=getch();}

            erase();
            drawmenu();
            return;
           }
        else{
                BigInteger plain;
                for(int i = 0; i < recordCode.size(); i++){
                    BigInteger cipher(recordCode[i]);
                    plain = power(cipher, d, n);
                    ofs << tochar(plain);
                }
        }
    }
ifs.close();
ofs.close();

}

