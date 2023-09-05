#include <stdint.h>
#include <string>
#include <regex>
#include <vector>

#define NULL_IP_DEC (uint32_t)NULL
#define NULL_IP_STR "0.0.0.0"
#define NULL_IP timlibs::IPv4(NULL_IP_DEC)

namespace timlibs
{
    class ExceptionIPv4
    {
    public:
        ExceptionIPv4() : problem{ "" } {};
        ExceptionIPv4(const std::string& what) : problem{ what } {};
        std::string what() const { return this->problem; };
    private:
        std::string problem;
    };

    class IPv4Mask;

    class IPv4
    {
    public:
        IPv4();
        IPv4(const std::string& ip_address);
        IPv4(const uint32_t& ip_address);
        IPv4(const IPv4& ip_address);
        void Set(const std::string& ip_address);
        void Set(const uint32_t& ip_address);
        std::string GetAsString() const;
        uint32_t GetAsInt() const;
        virtual bool IsValid(const std::string& str) const;
        IPv4 operator&(const IPv4& operand) const;
        bool operator==(const IPv4& operand) const;
        IPv4& operator=(const IPv4& operand);
        static const IPv4 GetFreeIP(const IPv4& ip, const IPv4Mask& mask, const std::vector<IPv4>& list_of_not_free);
        static const IPv4 Reverse(const IPv4& ip);
        IPv4 Reverse() const;
    protected:
        uint32_t address;
    };

    class IPv4Mask : public IPv4
    {
    public:
        IPv4Mask() : IPv4() {};
        IPv4Mask(const std::string& ip_address);
        IPv4Mask(const uint32_t& ip_address);
        IPv4Mask(const IPv4& ip_address);
        IPv4Mask(const IPv4Mask& ip_address);
        bool IsValid(const std::string& str) const;
        uint8_t GetAsCIDR() const;
    };
}
