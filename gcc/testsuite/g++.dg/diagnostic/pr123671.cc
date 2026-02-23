// { dg-do compile { target c++11 } }
struct S { int i; };

struct bad {
  template <auto L = [] {
    struct { S s; } ct;
    auto result = ct.s;
  }>
  static g() {
    L();
  }
};

int main() {
  bad::g();
}
