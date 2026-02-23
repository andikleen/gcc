// { dg-do compile { target c++11 } }

template <auto =
              [] {
                struct {
                } s; // { dg-error "lambda not allowed" }
              }>
bool v;
v<>  // { dg-error "does not name" }
