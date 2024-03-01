#include <vector>
#include <iostream>
#include <cstring>


// Sbox шифра TWINE
int sbox[] = {0x0C, 0x00, 0x0F, 0x0A, 0x02, 0x0B, 0x09, 0x05, 0x08, 0x03, 0x0D, 0x07, 0x01, 0x0E, 0x06, 0x04};

int shuf[] = {5, 0, 1, 4, 7, 12, 3, 8, 13, 6, 9, 2, 15, 10, 11, 14};
int shufinv[] = {1, 2, 11, 6, 3, 0, 9, 4, 7, 10, 13, 14, 5, 8, 15, 12};

// Раундовые константы
int roundconst[] = {
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x03, 0x06, 0x0c, 0x18, 0x30, 0x23, 0x05, 0x0a, 0x14, 0x28, 0x13, 0x26,
        0x0f, 0x1e, 0x3c, 0x3b, 0x35, 0x29, 0x11, 0x22, 0x07, 0x0e, 0x1c, 0x38, 0x33, 0x25, 0x09, 0x12, 0x24, 0x0b,
};

// Класс шифра
class twineCipher {
public:
    int rk[36][8]{};

    static int BlockSize();
    
    // Функция расшифрования 
    void Decrypt(std::vector<int> &dst,  std::vector<int> &src) {
        int x[16]; 

        for (int i = 0; i < std::size(src); i++) {
            x[2 * i] = src[i] >> 4;
            x[2 * i + 1] = src[i] & 0x0f;
        }

        for (int i = 35; i >= 1; i--) {
            for (int j = 0; j < 8; j++) {
                x[2 * j + 1] ^= sbox[x[2 * j] ^ this->rk[i][j]];
            }

            int xnext[16];
            for (int h = 0; h < 16; h++) {
                xnext[shufinv[h]] = x[h];
            }
            memcpy(x, xnext, sizeof(x));
        }

        // последний раунд
        int i = 0;
        for (int j = 0; j < 8; j++) {
            x[2 * j + 1] ^= sbox[x[2 * j] ^ this->rk[i][j]];
        }

        for (int i = 0; i < 8; i++) {
            dst.push_back(x[2 * i] << 4 | x[2 * i + 1]);
        }
    }
    
    // метод расширения ключа до 80 бит
    void expandKeys80(std::vector<int> &key) {
        int wk[20];

        for (int i = 0; i < std::size(key); i++) {
            wk[2 * i] = key[i] >> 4;
            wk[2 * i + 1] = key[i] & 0x0f;
        }

        for (int i = 0; i < 35; i++) {
            this->rk[i][0] = wk[1];
            this->rk[i][1] = wk[3];
            this->rk[i][2] = wk[4];
            this->rk[i][3] = wk[6];
            this->rk[i][4] = wk[13];
            this->rk[i][5] = wk[14];
            this->rk[i][6] = wk[15];
            this->rk[i][7] = wk[16];

            wk[1] ^= sbox[wk[0]];
            wk[4] ^= sbox[wk[16]];
            int con = roundconst[i];
            wk[7] ^= con >> 3;
            wk[19] ^= con & 7;

            int tmp0 = wk[0];
            int tmp1 = wk[1];
            int tmp2 = wk[2];
            int tmp3 = wk[3];

            for (int j = 0; j < 4; j++) {
                int fourj = j * 4;
                wk[fourj] = wk[fourj + 4];
                wk[fourj + 1] = wk[fourj + 5];
                wk[fourj + 2] = wk[fourj + 6];
                wk[fourj + 3] = wk[fourj + 7];
            }
            wk[16] = tmp1;
            wk[17] = tmp2;
            wk[18] = tmp3;
            wk[19] = tmp0;
        }

        this->rk[35][0] = wk[1];
        this->rk[35][1] = wk[3];
        this->rk[35][2] = wk[4];
        this->rk[35][3] = wk[6];
        this->rk[35][4] = wk[13];
        this->rk[35][5] = wk[14];
        this->rk[35][6] = wk[15];
        this->rk[35][7] = wk[16];
    }

    // метод расширения ключа до 128 бит        
    void expandKeys128(std::vector<int> &key) {
        int wk[32];

        for (int i = 0; i < std::size(key); i++) {
            wk[2 * i] = key[i] >> 4;
            wk[2 * i + 1] = key[i] & 0x0f;
        }

        for (int i = 0; i < 35; i++) {

            this->rk[i][0] = wk[2];
            this->rk[i][1] = wk[3];
            this->rk[i][2] = wk[12];
            this->rk[i][3] = wk[15];
            this->rk[i][4] = wk[17];
            this->rk[i][5] = wk[18];
            this->rk[i][6] = wk[28];
            this->rk[i][7] = wk[31];

            wk[1] ^= sbox[wk[0]];
            wk[4] ^= sbox[wk[16]];
            wk[23] ^= sbox[wk[30]];
            int con = roundconst[i];
            wk[7] ^= con >> 3;
            wk[19] ^= con & 7;

            int tmp0 = wk[0];
            int tmp1 = wk[1];
            int tmp2 = wk[2];
            int tmp3 = wk[3];

            for (int j = 0; j < 7; j++) {
                int fourj = j * 4;
                wk[fourj] = wk[fourj + 4];
                wk[fourj + 1] = wk[fourj + 5];
                wk[fourj + 2] = wk[fourj + 6];
                wk[fourj + 3] = wk[fourj + 7];
            }
            wk[28] = tmp1;
            wk[29] = tmp2;
            wk[30] = tmp3;
            wk[31] = tmp0;
        }
        this->rk[35][0] = wk[2];
        this->rk[35][1] = wk[3];
        this->rk[35][2] = wk[12];
        this->rk[35][3] = wk[15];
        this->rk[35][4] = wk[17];
        this->rk[35][5] = wk[18];
        this->rk[35][6] = wk[28];
        this->rk[35][7] = wk[31];

    }
        
    // функция шифрования
    void Encrypt(std::vector<int> &dst, std::vector<int> &src) {
        int x[16];
        for (int i = 0; i < std::size(src); i++) {
            x[2 * i] = src[i] >> 4;
            x[2 * i + 1] = src[i] & 0x0f;
        }

        for (int i = 0; i < 35; i++) {
            for (int j = 0; j < 8; j++) {
                x[2 * j + 1] ^= sbox[x[2 * j] ^ this->rk[i][j]];
            }

            int xnext[16];

            for (int h = 0; h < 16; h++)
                xnext[shuf[h]] = x[h];

            memcpy(x, xnext, sizeof(x));
        }

        // последний раунд
        int i = 35;
        for (int j = 0; j < 8; j++) {
            x[2 * j + 1] ^= sbox[x[2 * j] ^ this->rk[i][j]];
        }

        for (i = 0; i < 8; i++) {
            dst.push_back(x[2 * i] << 4 | x[2 * i + 1]);
        }
    }

    explicit twineCipher(std::vector<int> &key);
};

// конструктор
twineCipher::twineCipher(std::vector<int> &key) {
    int l = std::size(key);

    if (l != 10 && l != 16)
        exit(1);


    if (l == 10) twineCipher::expandKeys80(key);
    else twineCipher::expandKeys128(key);
}

// для дальнейшей кодовой базы (статический метод)
int twineCipher::BlockSize() {
    return 8;
}

// структура "тест кейсов" (test1, test2)
struct tests {
    std::vector<int> key;
    std::vector<int> plain;
    std::vector<int> cipher;
} test1, test2;

int main() {
    // инициализируем test1
    test1.key = std::vector<int>{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99};
    test1.plain = std::vector<int>{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
    test1.cipher = std::vector<int>{0x7c, 0x1f, 0x0f, 0x80, 0xb1, 0xdf, 0x9c, 0x28};
    
    // инициазируем test2
    test2.key = std::vector<int>{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
                                 0xEE, 0xFF};
    test2.plain = std::vector<int>{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
    test2.cipher = std::vector<int>{0x97, 0x9F, 0xF9, 0xB3, 0x79, 0xB5, 0xA9, 0xB8};

    // test1 Шифрование
    twineCipher c1(test1.key);

    std::vector<int> ct;
    c1.Encrypt(ct, test1.plain);

    for (auto i: ct)
        std::cout << std::hex << i << ' ';
    std::cout << std::endl;
    for (auto i: test1.cipher)
        std::cout << std::hex << i << ' ';
    std::cout << std::endl;

    if (std::equal(ct.begin(), ct.end(), test1.cipher.begin()))
        std::cout << "TEST 1: Encryption SUCCESSFUL" << std::endl;

    // test1 Расшифрование
    std::vector<int> pt;
    c1.Decrypt(pt, ct);

    for (auto i: pt)
        std::cout << std::hex << i << ' ';
    std::cout << std::endl;
    for (auto i: test1.plain)
        std::cout << std::hex << i << ' ';
    std::cout << std::endl;

    if (std::equal(pt.begin(), pt.end(), test1.plain.begin()))
        std::cout << "TEST 1: Decryption SUCCESSFUL" << std::endl;


    // test2 Шифрование
    twineCipher c2(test2.key);

    std::vector<int> ct2;
    c2.Encrypt(ct2, test2.plain);

    for (auto i: ct2)
        std::cout << std::hex << i << ' ';
    std::cout << std::endl;
    for (auto i: test2.cipher)
        std::cout << std::hex << i << ' ';
    std::cout << std::endl;

    if (std::equal(ct2.begin(), ct2.end(), test2.cipher.begin()))
        std::cout << "TEST 2: Encryption SUCCESSFUL" << std::endl;

    // test2 Расшифрование
    std::vector<int> pt2;
    c2.Decrypt(pt2, ct2);

    for (auto i: pt2)
        std::cout << std::hex << i << ' ';
    std::cout << std::endl;
    for (auto i: test2.plain)
        std::cout << std::hex << i << ' ';
    std::cout << std::endl;

    if (std::equal(pt2.begin(), pt2.end(), test2.plain.begin()))
        std::cout << "TEST 2: Decryption SUCCESSFUL" << std::endl;

    return 0;
}
