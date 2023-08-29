#include <linux/types.h>
#include <linux/if_ether.h>
#include <fstream>

#define PROMISC_MODE_ON 1 // флаг включения неразборчивый режим
#define PROMISC_MODE_OFF 0 // флаг выключения неразборчивого режима

using namespace std;

class Analizator
{
private:
//    __u8 buff[ETH_FRAME_LEN + 4];
//    unsigned char* intfc;
    int getsock_recv(int index);
    static int getifconf(__u8 *intf, struct ifparam *ifp, int mode);
    static char* translate_to_ip(__u32 ip_or_mask);
    static void stop_output(int signum);

public:
    int main_cycle(unsigned char* interface);

    Analizator();
    ~Analizator();
};
