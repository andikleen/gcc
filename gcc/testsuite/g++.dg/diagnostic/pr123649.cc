// { dg-do compile { target c++11 } }
struct B : { // When remove : cause internal compiler error: in
             // finish_expr_stmt, at cp/semantics.cc:1171
  int j;
};
template <auto L =
              [] {
                struct D : B {};
                D d;
                d.j;
              }>
static void g();
struct A {
  virtual ~A() { g(); }
};
