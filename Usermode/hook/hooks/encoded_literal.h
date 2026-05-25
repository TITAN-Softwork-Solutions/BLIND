#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <Windows.h>
#include <cstddef>
#include <cstdint>

namespace IX_RUNTIME_INTERNAL
{
    template <std::size_t N> struct IxEncodedAnsiLiteral
    {
        std::uint8_t Bytes[N]{};
        std::uint8_t Key = 0;

        constexpr IxEncodedAnsiLiteral(const char (&literal)[N], std::uint8_t key) noexcept : Key(key)
        {
            for (std::size_t i = 0; i < N; ++i)
            {
                Bytes[i] = static_cast<std::uint8_t>(static_cast<std::uint8_t>(literal[i]) ^ Mask(i));
            }
        }

        constexpr std::uint8_t Mask(std::size_t index) const noexcept
        {
            return static_cast<std::uint8_t>(Key + static_cast<std::uint8_t>(index * 0x5Du) +
                                             static_cast<std::uint8_t>(index >> 1));
        }

        void Decode(char (&out)[N]) const noexcept
        {
            for (std::size_t i = 0; i < N; ++i)
            {
                out[i] = static_cast<char>(Bytes[i] ^ Mask(i));
            }
            out[N - 1] = '\0';
        }
    };

    template <std::size_t N> struct IxEncodedWideLiteral
    {
        std::uint16_t Words[N]{};
        std::uint16_t Key = 0;

        constexpr IxEncodedWideLiteral(const wchar_t (&literal)[N], std::uint16_t key) noexcept : Key(key)
        {
            for (std::size_t i = 0; i < N; ++i)
            {
                Words[i] = static_cast<std::uint16_t>(static_cast<std::uint16_t>(literal[i]) ^ Mask(i));
            }
        }

        constexpr std::uint16_t Mask(std::size_t index) const noexcept
        {
            return static_cast<std::uint16_t>(Key + static_cast<std::uint16_t>(index * 0x135Du) +
                                              static_cast<std::uint16_t>(index >> 1));
        }

        void Decode(wchar_t (&out)[N]) const noexcept
        {
            for (std::size_t i = 0; i < N; ++i)
            {
                out[i] = static_cast<wchar_t>(Words[i] ^ Mask(i));
            }
            out[N - 1] = L'\0';
        }
    };

    template <std::size_t N> struct IxScopedAnsiLiteral
    {
        char Value[N]{};

        explicit IxScopedAnsiLiteral(const IxEncodedAnsiLiteral<N> &literal) noexcept
        {
            literal.Decode(Value);
        }

        ~IxScopedAnsiLiteral()
        {
            SecureZeroMemory(Value, sizeof(Value));
        }

        const char *c_str() const noexcept
        {
            return Value;
        }

        operator const char *() const noexcept
        {
            return c_str();
        }
    };

    template <std::size_t N> struct IxScopedWideLiteral
    {
        wchar_t Value[N]{};

        explicit IxScopedWideLiteral(const IxEncodedWideLiteral<N> &literal) noexcept
        {
            literal.Decode(Value);
        }

        ~IxScopedWideLiteral()
        {
            SecureZeroMemory(Value, sizeof(Value));
        }

        const wchar_t *c_str() const noexcept
        {
            return Value;
        }

        operator const wchar_t *() const noexcept
        {
            return c_str();
        }
    };

    template <std::size_t N>
    IxEncodedAnsiLiteral(const char (&literal)[N], std::uint8_t key) -> IxEncodedAnsiLiteral<N>;

    template <std::size_t N>
    IxEncodedWideLiteral(const wchar_t (&literal)[N], std::uint16_t key) -> IxEncodedWideLiteral<N>;

    template <std::size_t N>
    IxScopedAnsiLiteral(const IxEncodedAnsiLiteral<N> &literal) -> IxScopedAnsiLiteral<N>;

    template <std::size_t N>
    IxScopedWideLiteral(const IxEncodedWideLiteral<N> &literal) -> IxScopedWideLiteral<N>;

    inline IxScopedWideLiteral<10> DecodeIxDllName() noexcept
    {
        static constexpr IxEncodedWideLiteral kName{L"BLIND.dll", 0x071u};
        return IxScopedWideLiteral{kName};
    }

    inline IxScopedWideLiteral<10> DecodeNtdllDllName() noexcept
    {
        static constexpr IxEncodedWideLiteral kName{L"ntdll.dll", 0x0B7u};
        return IxScopedWideLiteral{kName};
    }
} // namespace IX_RUNTIME_INTERNAL
