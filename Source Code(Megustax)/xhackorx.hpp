#pragma once
#define XSTR_SEED 676
#if 0
#define TBX_XSTR_SEED ((__TIME__[7] - '0') * 1ull    + (__TIME__[6] - '0') * 10ull  + \
                       (__TIME__[4] - '0') * 60ull   + (__TIME__[3] - '0') * 600ull + \
                       (__TIME__[1] - '0') * 3600ull + (__TIME__[0] - '0') * 36000ull)
#else
#define TBX_XSTR_SEED (3600ull)
#endif

namespace crypt {
    constexpr unsigned long long linear_congruent_generator(unsigned rounds)
    {
        return 1013904223ull + (1664525ull * ((rounds > 0) ? linear_congruent_generator(rounds - 1) : (XSTR_SEED))) % 0xFFFFFFFF;
    }
#define Random() linear_congruent_generator(10)
#define XSTR_RANDOM_NUMBER(Min, Max) ((Min) + (Random() % ((Max) - (Min) + 1)))

    constexpr const unsigned long long XORKEY = XSTR_RANDOM_NUMBER(0, 0xFF);
    template<typename Char >
    constexpr Char encrypt_character(const Char character, int index) {
        return static_cast<Char>(character ^ (static_cast<Char>(XORKEY) + index));
    }
    template <unsigned size, typename Char>
    class Xor_string {
    public:
        const unsigned _nb_chars = (size - 1);
        Char _string[size];
        inline constexpr Xor_string(const Char* string)
            : _string{}
        {
            for (unsigned i = 0u; i < size; ++i)
                _string[i] = encrypt_character<Char>(string[i], i);
        }
        const Char* decrypt() const
        {
            Char* string = const_cast<Char*>(_string);
            for (unsigned t = 0; t < _nb_chars; t++) {
                string[t] = static_cast<Char>(string[t] ^ (static_cast<Char>(XORKEY) + t));
            }
            string[_nb_chars] = '\0';
            return string;
        }
    };
}

#define XorS(name, my_string)    constexpr crypt::Xor_string<(sizeof(my_string)/sizeof(char)), char> name(my_string)
#define XorString(my_string) []{ constexpr crypt::Xor_string<(sizeof(my_string)/sizeof(char)), char> expr(my_string); return expr; }().decrypt()
#define E( string ) XorString( string )
#define XorWS(name, my_string)       constexpr crypt::Xor_string<(sizeof(my_string)/sizeof(wchar_t)), wchar_t> name(my_string)
#define XorWideString(my_string) []{ constexpr crypt::Xor_string<(sizeof(my_string)/sizeof(wchar_t)), wchar_t> expr(my_string); return expr; }().decrypt()
#define EW( string ) XorWideString( string )