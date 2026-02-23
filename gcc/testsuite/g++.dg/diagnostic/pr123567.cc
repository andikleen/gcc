// { dg-do compile { target c++11 } }
template <auto =
              [] {
                class LocalClass {
                  void test();
                };
                LocalClass lc;
                lc.test();
              }>
constexpr bool flag = true;
template <typename> void f() { if constexpr (flag<>) }
int main() { f<int>(); }
