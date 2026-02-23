// { dg-do compile { target c++11 } }
template<auto = []{
    struct S {
        static constexpr int n = -1;
    };
    S::n;
}>
void f() {
}
