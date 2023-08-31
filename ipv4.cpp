#define _CRT_SECURE_NO_WARNINGS
#include "ipv4.hpp"
#include <algorithm>
#include <stdint.h>
#include <string>

namespace timlibs
{
    /// @brief Initialaize IPv4 address object
    /// @param ip_address IPv4 address as string, ex. "192.168.34.2"
    IPv4::IPv4(const std::string& ip_address)
    {
        this->Set(ip_address);
    }

    /// @brief Initialaize IPv4 address object (Copy constructor)
    /// @param ip_address IPv4 object
    IPv4::IPv4(const IPv4& ip_address)
    {
        this->address = ip_address.GetAsInt();
    }

    /// @brief Sets IPv4 address object
    /// @param ip_address IPv4 address as string, ex. "192.168.34.2"
    void IPv4::Set(const std::string& ip_address)
    {
        if (!(this->IsValid(ip_address))) throw ExceptionIPv4("Invalid IP address");

        uint32_t a, b, c, d;
        std::sscanf(ip_address.c_str(), "%d.%d.%d.%d", &a, &b, &c, &d);

        this->address = (a << 24 | b << 16 | c << 8 | d);

    }

    /// @brief Returns IPv4 address as string
    /// @return IPv4 address as string, ex. "192.168.34.2"
    std::string IPv4::GetAsString() const
    {
        std::string value{ "" };
        for (int i = 3; i >= 0; i--)
        {
            value += std::to_string(((this->address) >> 3 * i) & 0x000000ff);
            if (i != 0) value += '.';
        }

        return value;
    }

    /// @brief Checks "Is Valid the IPv4 address represents as string?"
    /// @param str IPv4 address represents as string
    /// @return Result of matching string to regex
    bool IPv4::IsValid(const std::string& str) const
    {
        static const std::regex r(R"(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])");
        return std::regex_match(str, r);
    }

    /// @brief Per bit multiply operator
    /// @param operand second operand
    /// @return IPv4 object as result of multipling
    IPv4 IPv4::operator&(const IPv4& operand) const
    {
        return (this->address) & (operand.address);
    }

    /// @brief Equal operator
    /// @param operand second operand
    /// @return Comparison result
    bool IPv4::operator==(const IPv4& operand) const
    {
        return (this->address == operand.address);
    }

    /// @brief Initialaize IPv4Mask network mask object
    /// @param ip_address network mask as integer
    IPv4Mask::IPv4Mask(const uint32_t& ip_address)
    {
        if (this->IsValid(IPv4(ip_address).GetAsString())) this->address = ip_address;
    }

    /// @brief Initialaize IPv4Mask network mask object
    /// @param ip_address network mask as IPv4 object
    IPv4Mask::IPv4Mask(const IPv4& ip_address)
    {
        if (this->IsValid(ip_address.GetAsString())) this->address = ip_address.GetAsInt();
    }

    /// @brief Initialaize IPv4Mask network mask object (Copy constructor)
    /// @param ip_address network mask as IPv4Mask object
    IPv4Mask::IPv4Mask(const IPv4Mask& ip_address)
    {
        this->address = ip_address.GetAsInt();
    }

    /// @brief Checks "Is Valid the IPv4Mask network mask represents as string?"
    /// @param str IPv4Mask address represents as string, ex. "255.255.254.0"
    /// @return Result of matching string to regex
    bool IPv4Mask::IsValid(const std::string& str) const
    {
        static const std::regex r(R"(?:(?:255\.){3}(2(?:5[542]|4[80]|24)|192|128|0)|(?:255\.){2}(?1)(?:\.0)|255\.(?1)(?:\.0){2}|(?1)(?:\.0){3})");
        return std::regex_match(str, r);
    }

    /// @brief Gets IPv4Mask object as integer value of CIRD
    /// @return CIDR as intenger
    uint8_t IPv4Mask::GetAsCIDR() const
    {
        uint32_t address = this->GetAsInt();
        uint8_t cidr{ 0 };
        for (int i = 0; i < 32; i++)
        {
            if (address & 0x80000000) //2147483648 = 0x80000000 = 0b10000000 00000000 00000000 00000000
            {
                cidr++;
                address <<= 1;
            }
            else break;
        }
        return cidr;
    }

    /// @brief Assignment operator
    /// @param operand second operand
    /// @return Copy of second operand
    IPv4& IPv4::operator=(const IPv4& operand)
    {
        this->address = operand.GetAsInt();
        return *this;
    }

    /// @brief Gets one of free ips
    /// @param ip IPv4 address as object
    /// @param mask IPv4Mask network mask as object
    /// @param list_of_not_free list of not free IPv4 addresses as objects
    /// @return IPv4 address as object
    const IPv4 IPv4::GetFreeIP(const IPv4& ip, const IPv4Mask& mask, const std::vector<IPv4>& list_of_not_free)
    {
        IPv4 address_of_network = ip & mask;
        uint32_t min_address = 0;
        uint32_t max_address = ((IPv4::Reverse(mask)) & IPv4(0xffffffff)).GetAsInt();
        IPv4 broacast_address(address_of_network.GetAsInt() + max_address);
        for (uint32_t i = min_address + 1; i < max_address; i++)
        {
            IPv4 current(address_of_network.GetAsInt() + i);
            if ((std::find(list_of_not_free.begin(), list_of_not_free.end(), current)) != list_of_not_free.end()) return current;
        }

        throw ExceptionIPv4("No free address found");
    }

    /// @brief Makes Wildcard of ip address
    /// @param ip IPv4 address as object
    /// @return Reversed IPv4 address as object
    const IPv4 IPv4::Reverse(const IPv4& ip)
    {
        return IPv4(~(ip.GetAsInt()));
    }

    /// @brief Makes Wildcard of ip address
    /// @return Reversed IPv4 address as object
    IPv4 IPv4::Reverse() const
    {
        return IPv4::Reverse(*this);
    }
}


