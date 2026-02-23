// { dg-do compile { target c++11 } }
template <int = 0, class F = decltype([]<int = 1, auto G = [] {}>() {
                     struct MyClass {
                       int i = [this]() -> int {}
                     };
                     MyClass obj;
                   })>
void f(F op = {}) {
  op();
}
int main() { f(); }
