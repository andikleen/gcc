// { dg-do compile { target c++11 } }
template < auto B =
              [] {
                struct E {
                  E();
                };
                E();
              }>
struct A;
A x;
