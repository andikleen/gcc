// { dg-do compile { target c++11 } }
template <class F = decltype([] <auto G = [] {
    struct S {
        int& out;
    };
    int offset = __builtin_offsetof(S, out);
}> () {})>
void f(F op = {}) { op(); }

int main() { f(); }
