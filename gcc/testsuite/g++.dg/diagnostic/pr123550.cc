// { dg-do compile { target c++11 } }
template <auto = +[] {
    struct LocalType {
        auto operator<=>(const LocalType &other) const = default;
    };
    constexpr LocalType a, b;
    static_assert(noexcept(a <=> b), "Noexcept check failed");
}
