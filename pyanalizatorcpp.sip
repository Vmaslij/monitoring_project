%Module(name=analizatorcpp, language="C++")
%DefaultEncoding "UTF-8"

class Analizator {
    %TypeHeaderCode
    #include <analizator.h>
    %End

    public:
        int main_cycle(unsigned char* interface);

        Analizator();
        ~Analizator();
};