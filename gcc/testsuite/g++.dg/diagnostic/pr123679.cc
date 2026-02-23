// { dg-do compile { target c++11 } }
class ConversionClass {
  void someMethod() {}
};

template <int T> struct bad {
  template <auto L =
                [] {
                  ConversionClass obj;
                  auto pmf = &ConversionClass::someMethod;
                  auto lambda = [&](auto &&obj) {
                    return [pmf, &obj]() { (obj.*pmf)(); };
                  };
                }>
  static void g() {
    L();
  }
};

template <class T> void f(T) { bad<0>::g(); }
